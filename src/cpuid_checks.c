/* ===========================================================================
   RILEVAMENTO VIA CPUID
   ===========================================================================

   CPUID e' l'istruzione con cui il software interroga la CPU (vendor, modello,
   feature). Gli hypervisor la intercettano con un "VM exit" e possono
   modificare le risposte: e' quindi il canale piu' usato sia per dichiarare
   una VM sia per nasconderla.

   Metodi implementati in questo file
   ----------------------------------
   1) CPUID.1:ECX[31]  bit "hypervisor present".
      Convenzione nata con Intel VT-x/AMD-V: se una VM gira sotto un
      hypervisor, la foglia 1 deve avere il bit 31 di ECX a 1.
      Attenzione: lo stesso bit e' a 1 su un PC fisico con Hyper-V, VBS /
      Credential Guard, Windows Sandbox o WSL2 attivi, perche' Windows gira
      sopra il microkernel Hyper-V. Da solo NON prova una VM.

   2) Foglia 0x40000000  firma del vendor hypervisor.
      Gli hypervisor deducono una foglia "riservata" a partire da 0x40000000
      e vi espongono 12 byte ASCII con il proprio nome (EBX, ECX, EDX), per
      esempio "VMwareVMware", "VBoxVBoxVBox", "KVMKVMKVM", "Microsoft Hv".
      E' la prova piu' diretta e viene marcata "definitiva" tranne per
      "Microsoft Hv" (vedi sopra: anche gli host la espongono).

   3) Brand string 0x80000002..0x80000004.
      Il nome commerciale del processore. Molti emulatori espongono
      "QEMU Virtual CPU", "VirtualBox Virtual CPU" o direttamente il nome
      dell'hypervisor. Peso basso: il valore e' modificabile.

   4) Backdoor VMware (porta I/O 0x5658).
      Protocollo non documentato: si esegue IN a 32 bit dalla porta 0x5658
      con EAX = 0x564D5868 ('VMXh'). L'hypervisor VMware risponde mettendo
      EBX = 0x564D5868; su hardware reale l'istruzione IN e' privilegiata
      (CPL 3) e genera un'eccezione #GP, recuperata con vd_probe().
      E' una prova "definitiva" quando EBX torna il magic value.

   Pesi e affidabilita'
   --------------------
   Le firme di tipo 2 (VMware, VBox, KVM, Xen, Parallels, bhyve, TCG) valgono
   40 punti e sono definitive: se l'hypervisor le espone non c'e' ambiguita'.
   "Microsoft Hv" vale 5 e non e' definitiva per i motivi al punto 1.
   Una firma sconosciuta vale 20: un hypervisor c'e', il vendor no.
   Un bit hypervisor senza firma leggibile vale 5 (VM indurita o hypervisor
   minimale che non implementa la foglia 0x40000000).
   =========================================================================== */

#include "checks.h"

#include <cpuid.h>
#include <string.h>

#define CAT "CPUID / hypervisor"

/* Testi mostrati a schermo: spiegano con quale tecnica e' stato fatto il
   controllo e come va interpretato il risultato. */
static const char *const M_BRAND =
    "Legge il nome del processore (CPUID 0x80000002-0x80000004): gli "
    "emulatori spesso espongono il nome dell'hypervisor o 'Virtual CPU'.";
static const char *const M_HV_BIT =
    "Legge CPUID.1:ECX[31], il bit con cui l'hypervisor dichiara la presenza "
    "di una VM; su un PC fisico con Hyper-V/VBS/WSL2 puo' essere a 1.";
static const char *const M_SIGNATURE =
    "Interroga la foglia 0x40000000 e legge i 12 byte di firma che gli "
    "hypervisor espongono come nome del vendor.";
static const char *const M_BACKDOOR =
    "Esegue IN dalla porta I/O 0x5658 con EAX='VMXh': solo l'hypervisor "
    "VMware risponde con EBX='VMXh', l'hardware reale genera #GP.";
static const char *const M_LEAVES =
    "Riporta le foglie CPUID massime e la larghezza degli indirizzi fisici "
    "(solo dato diagnostico).";

/* Ricompone i 12 byte della firma da EBX, ECX, EDX della foglia 0x40000000. */
static void signature_string(unsigned a, unsigned b, unsigned c, unsigned d,
                             char out[13])
{
    unsigned regs[3] = { b, c, d };
    int pos = 0;
    (void)a;
    for (int i = 0; i < 3; ++i) {
        for (int j = 0; j < 4; ++j) {
            unsigned char ch = (unsigned char)((regs[i] >> (j * 8)) & 0xFF);
            out[pos++] = (ch >= 32 && ch < 127) ? (char)ch : '.';
        }
    }
    out[pos] = '\0';
}

/* Tabella delle firme note. "definitive" = la firma identifica l'hypervisor
   in modo affidabile anche su un PC fisico (vedi commento in testa). */
static const struct {
    const char *signature;
    const char *vendor;
    int weight;
    int definitive;
} known_signatures[] = {
    { "VMwareVMware",   VD_VENDOR_VMWARE,    40, 1 },
    { "VBoxVBoxVBox",   VD_VENDOR_VBOX,      40, 1 },
    { "KVMKVMKVM",      VD_VENDOR_QEMU,      40, 1 },
    { "LinuxKVMHv",     VD_VENDOR_QEMU,      35, 1 },
    { "XenVMMXenVMM",   VD_VENDOR_XEN,       40, 1 },
    { "TCGTCGTCGTCG",   VD_VENDOR_QEMU,      40, 1 },
    { "prl hyperv",     VD_VENDOR_PARALLELS, 40, 1 },
    { "bhyve bhyve",    VD_VENDOR_BHYVE,     40, 1 },
    { "ACRNACRNACRN",   VD_VENDOR_GENERIC,   30, 1 },
    { "Microsoft Hv",   VD_VENDOR_HYPERV,     5, 0 },
};

/* Esegue la backdoor VMware. Va chiamata solo dentro vd_probe(), che
   intercetta il #GP prodotto su una macchina fisica. */
static volatile uint32_t bd_eax;
static volatile uint32_t bd_ebx;

static void probe_vmware_backdoor(void)
{
    uint32_t eax = 0x564D5868u;
    uint32_t ebx = 0;
    uint32_t ecx = 0x0A;
    uint32_t edx = 0x5658;

    __asm__ __volatile__("inl %%dx, %%eax"
                         : "+a"(eax), "=b"(ebx), "+c"(ecx), "+d"(edx));
    bd_eax = eax;
    bd_ebx = ebx;
}

/* Brand string: tre foglie consecutive da 16 byte ciascuna (48 byte). */
static void cpu_brand(char out[49])
{
    unsigned max_ext = __get_cpuid_max(0x80000000u, NULL);
    out[0] = '\0';
    if (max_ext < 0x80000004u) {
        return;
    }

    unsigned regs[4 * 3];
    for (unsigned leaf = 0; leaf < 3; ++leaf) {
        unsigned a, b, c, d;
        __cpuid_count(0x80000002u + leaf, 0, a, b, c, d);
        regs[leaf * 4 + 0] = a;
        regs[leaf * 4 + 1] = b;
        regs[leaf * 4 + 2] = c;
        regs[leaf * 4 + 3] = d;
    }

    int pos = 0;
    for (int i = 0; i < 12; ++i) {
        for (int j = 0; j < 4; ++j) {
            char ch = (char)((regs[i] >> (j * 8)) & 0xFF);
            out[pos++] = ch;
        }
    }
    out[pos] = '\0';

    char *start = out;
    while (*start == ' ') {
        ++start;
    }
    if (start != out) {
        memmove(out, start, strlen(start) + 1);
    }
    size_t len = strlen(out);
    while (len > 0 && (out[len - 1] == ' ' || out[len - 1] == '\0')) {
        out[--len] = '\0';
    }
}

void checks_cpuid(VdReport *r)
{
    unsigned a = 0, b = 0, c = 0, d = 0;
    unsigned max_basic = __get_cpuid_max(0, NULL);
    unsigned max_ext = __get_cpuid_max(0x80000000u, NULL);

    /* --- metodo 3: brand string --------------------------------------- */
    int leaf1_ok = (max_basic >= 1) && __get_cpuid(1, &a, &b, &c, &d);
    int hv_bit = leaf1_ok && ((c >> 31) & 1u);

    char brand[49];
    cpu_brand(brand);
    if (brand[0]) {
        const char *hv_brand = vd_vendor_from_text(brand);
        int virtual_brand = hv_brand != NULL ||
                            vd_ci_contains(brand, "virtual cpu") ||
                            vd_ci_contains(brand, "virtual processor");
        if (virtual_brand) {
            vd_add(r, CAT, "Brand della CPU virtuale", M_BRAND,
                   VDS_DETECTED, 10, "\"%s\"", brand);
            if (hv_brand) {
                vd_note_vendor(r, hv_brand, 60);
            }
        } else {
            vd_add(r, CAT, "Brand della CPU fisica", M_BRAND,
                   VDS_INFO, 0, "\"%s\"", brand);
        }
    }

    if (hv_bit) {
        r->hypervisor_present = 1;
    }

    /* --- metodo 2: firma dell'hypervisor ------------------------------ */
    unsigned ha = 0, hb = 0, hc = 0, hd = 0;
    __cpuid_count(0x40000000u, 0, ha, hb, hc, hd);
    char sig[13];
    signature_string(ha, hb, hc, hd, sig);
    int sig_readable = 1;
    for (int i = 0; sig[i]; ++i) {
        if (sig[i] == '.') {
            sig_readable = 0;
            break;
        }
    }
    /* La foglia 0x40000000 va letta sempre, anche con il bit a 0: un
       hypervisor puo' nascondere il bit e lasciare la firma. */
    const char *sig_vendor = NULL;
    int sig_known = 0;
    int sig_definitive = 0;
    int sig_microsoft = 0;

    if (sig_readable) {
        for (size_t i = 0; i < sizeof(known_signatures) / sizeof(known_signatures[0]); ++i) {
            if (strncmp(sig, known_signatures[i].signature, 12) == 0) {
                sig_vendor = known_signatures[i].vendor;
                sig_known = 1;
                sig_definitive = known_signatures[i].definitive;
                sig_microsoft =
                    strncmp(sig, "Microsoft Hv", 12) == 0;
                if (hv_bit) {
                    vd_add(r, CAT, "Firma CPUID dell'hypervisor", M_SIGNATURE,
                           VDS_DETECTED, known_signatures[i].weight,
                           "\"%s\" (%s)%s", sig, sig_vendor,
                           known_signatures[i].definitive ? "" :
                           " - presente anche su host con Hyper-V/VBS attivo");
                } else {
                    /* Firma di un hypervisor con bit dichiarativo a 0:
                       l'hypervisor sta nascondendo la VM. */
                    vd_add(r, CAT, "Firma hypervisor con bit mascherato",
                           M_SIGNATURE, VDS_DETECTED,
                           sig_microsoft ? 20 : 35,
                           "\"%s\" (%s) ma CPUID.1:ECX[31]=0: firma presente "
                           "con bit hypervisor mascherato", sig, sig_vendor);
                }
                if (sig_definitive && hv_bit) {
                    vd_mark_definitive(r);
                } else if (!sig_microsoft && !hv_bit) {
                    vd_mark_definitive(r);
                }
                vd_note_vendor(r, sig_vendor,
                               (sig_definitive && hv_bit) ? 90 :
                               (!sig_microsoft && !hv_bit) ? 95 :
                               (sig_microsoft && !hv_bit) ? 60 : 55);
                break;
            }
        }
    }

    if (!sig_known && hv_bit) {
        if (sig_readable && strncmp(sig, "            ", 12) != 0) {
            vd_add(r, CAT, "Firma CPUID non riconosciuta", M_SIGNATURE,
                   VDS_DETECTED, 20, "\"%s\" (hypervisor non in elenco)", sig);
            vd_note_vendor(r, VD_VENDOR_GENERIC, 40);
        } else {
            /* Il bit c'e' ma la firma no: hypervisor minimale o VM indurita. */
            vd_add(r, CAT, "Bit hypervisor senza firma leggibile", M_HV_BIT,
                   VDS_DETECTED, 5,
                   "CPUID.1:ECX[31]=1 ma foglia 0x40000000 vuota o non leggibile");
        }
    } else if (!sig_known) {
        vd_add(r, CAT, "Bit hypervisor CPUID", M_HV_BIT, VDS_CLEAN, 0,
               "CPUID.1:ECX[31]=0 e foglia 0x40000000 senza firma nota "
               "(nessun hypervisor dichiarato)");
    }

    if (hv_bit) {
        unsigned la = 0, lb = 0, lc = 0, ld = 0;
        __cpuid_count(0x40000000u, 0, la, lb, lc, ld);
        if (la >= 0x40000000u) {
            if (g_verbose) {
                vd_add(r, CAT, "Foglia hypervisor massima", M_LEAVES,
                       VDS_INFO, 0, "0x%08X, interfaccia 0x%08X",
                       la, 0x40000000u);
            }
        }
    }

    /* --- metodo 4: backdoor VMware ------------------------------------
       Non dipende dal bit hypervisor: si prova sempre. Su hardware reale
       l'istruzione IN genera #GP e vd_probe() restituisce 0. */
    int no_fault = vd_probe(probe_vmware_backdoor);
    if (no_fault && bd_ebx == 0x564D5868u) {
        vd_add(r, CAT, "Backdoor VMware (porta 0x5658)", M_BACKDOOR,
               VDS_DETECTED, 60,
               "risposta valida: EBX='VMXh', EAX=0x%08X - VMware confermato", bd_eax);
        vd_mark_definitive(r);
        vd_note_vendor(r, VD_VENDOR_VMWARE, 100);
    } else if (no_fault) {
        vd_add(r, CAT, "Backdoor VMware (porta 0x5658)", M_BACKDOOR,
               VDS_CLEAN, 0,
               "I/O completato ma senza firma VMware (EBX=0x%08X)", bd_ebx);
    } else {
        vd_add(r, CAT, "Backdoor VMware (porta 0x5658)", M_BACKDOOR,
               VDS_CLEAN, 0,
               "I/O privilegiato non disponibile (atteso su hardware reale o "
               "hypervisor diverso da VMware)");
    }

    /* Dati diagnostici aggiuntivi, solo con --verbose. */
    if (g_verbose) {
        unsigned pa = 0, pb = 0, pc = 0, pd = 0;
        if (__get_cpuid(0x80000008u, &pa, &pb, &pc, &pd)) {
            vd_add(r, CAT, "Larghezza indirizzi fisici", M_LEAVES,
                   VDS_INFO, 0, "%u bit (CPUID.80000008:EAX)", pa & 0xFF);
        }
        vd_add(r, CAT, "Foglie CPUID", M_LEAVES, VDS_INFO, 0,
               "base max 0x%08X, estesa max 0x%08X", max_basic, max_ext);
    }
}

/* ===========================================================================
   CONTROLLI DI COERENZA (COMBINAZIONI IMPOSSIBILI)
   ===========================================================================

   I controlli degli altri moduli cercano firme e parole chiave. Una VM
   costruita per non averne puo' superarli tutti. Questo modulo cerca invece
   combinazioni che un PC fisico non puo' produrre: non importa quale nome
   l'hypervisor dichiari, se i dati fra loro non tornano la macchina e' una VM.

   Ogni regola confronta DUE fonti indipendenti. Se una e' falsificata,
   l'altra la contraddice. Le incoerenze hanno un canale separato rispetto
   agli indizi positivi: non si sommano al punteggio, ma alzano la probabilita'
   e due o piu' incoerenze impongono un minimo del 90% (vedi probability.c).

   Regole implementate
   -------------------
   1) CPUID.1 EAX (family/model/stepping) contro il brand string.
      Un "Intel(R) Core(TM) i7..." e' sempre family 6 sui processori moderni;
      family 15 con quel brand e' impossibile. Il vendor CPUID deve inoltre
      concordare con il nome ("Intel" vs "AMD").

   2) Core/thread contro il brand e contro le altre fonti.
      Il nome commerciale implica un numero di core/thread (tabella sotto).
      Si confrontano: topologia CPUID (foglia 0x1F/0xB), conteggio di Windows,
      SMBIOS tipo 4. Una VM da 4C/4T che dichiara un i7-5820K (6C/12T) non
      torna. Anche SMBIOS e CPUID che si contraddicono fra loro sono una prova.

   3) PCI: device ID e subsystem ID, non solo il vendor.
      - SUBSYS_xxxxxxxx con vendor virtuale (1AF4 Red Hat/QEMU, 1B36, 15AD,
        80EE, 5853...): il subsystem sopravvive allo spoofing di VEN_/DEV_.
      - Un iGPU Intel G45 (DEV_29C2 e simili) su una piattaforma X99 con CPU
        Haswell-E/Broadwell-E e' impossibile: quelle CPU non hanno GPU
        integrata.
      - Chipset ICH9 (DEV_2918/2922/2930/293A) su una CPU -E senza PCH
        moderno (2Fxx/8Dxx/A1xx) e' una combinazione impossibile.

   4) Memoria SMBIOS (tipo 17) contro la memoria vista da Windows.
      Il totale dei moduli non puo' essere molto diverso dalla RAM installata;
      un singolo modulo non puo' superare la RAM totale del sistema.

   5) Inventario SMBIOS.
      Un firmware completo espone cache (tipo 7), slot (9), stringhe OEM (11)
      e system boot (32). Un inventario molto ridotto che ne perde diversi e'
      tipico delle VM, non di una scheda AMI desktop.

   6) Foglie CPUID non valide.
      Su Intel una foglia oltre il massimo restituisce i dati della foglia
      massima (clamp). Se restituisce dati diversi e non nulli, il comportamento
      non e' quello di un Intel fisico.

   Falsi positivi
   --------------
   Le regole sono volutamente strette e scattano solo quando entrambe le fonti
   sono disponibili e si contraddicono. L'host di prova (ASRock X99, i7-5820K,
   SMBIOS AMI con 32 strutture, PCI con PCH 2Fxx) non attiva nessuna regola:
   senza questo controllo le euristiche negative sarebbero pericolose.
   =========================================================================== */

#include "checks.h"

#include <cpuid.h>
#include <stdlib.h>
#include <string.h>

#define CAT "Coerenza"

static const char *const M_FMS =
    "Confronta family/model/stepping di CPUID.1 con il nome commerciale della "
    "CPU: un Intel Core e' family 6, e il vendor CPUID deve concordare col "
    "brand.";
static const char *const M_CORES =
    "Confronta i core/thread dichiarati dal brand con la topologia CPUID "
    "(0x1F/0xB), il conteggio di Windows e il tipo 4 SMBIOS: devono coincidere.";
static const char *const M_PCI =
    "Enumera Enum\\PCI e legge device ID e subsystem ID: cerca SUBSYS di "
    "vendor virtuali (1AF4...), iGPU Intel su piattaforme -E e chipset ICH9 "
    "su CPU moderne.";
static const char *const M_MEM =
    "Somma i moduli SMBIOS tipo 17 e li confronta con la RAM vista da Windows: "
    "un modulo piu' grande del totale o un totale incompatibile e' impossibile.";
static const char *const M_INV =
    "Conta le strutture SMBIOS e verifica la presenza dei tipi 7 (cache), 9 "
    "(slot), 11 (stringhe OEM) e 32 (system boot): un inventario ridotto e' "
    "tipico delle VM.";
static const char *const M_LEAF =
    "Interroga una foglia CPUID oltre il massimo: su Intel deve restituire i "
    "dati della foglia massima (clamp), non valori diversi.";

/* --------------------------------------------------------------- CPUID */

typedef struct {
    int ok;
    char vendor[13];
    char brand[49];
    unsigned eax;
    unsigned family, model, stepping;
    unsigned max_basic;
    unsigned win_logical;
    int topo_ok;
    unsigned smt;
    unsigned cores;
    unsigned threads;
} CpuInfo;

static void cpu_vendor(char out[13])
{
    unsigned a = 0, b = 0, c = 0, d = 0;
    __cpuid(0, a, b, c, d);
    unsigned regs[3] = { b, d, c };
    int pos = 0;
    for (int i = 0; i < 3; ++i) {
        for (int j = 0; j < 4; ++j) {
            char ch = (char)((regs[i] >> (j * 8)) & 0xFF);
            out[pos++] = (ch >= 32 && ch < 127) ? ch : '.';
        }
    }
    out[12] = '\0';
}

static void cpu_brand_string(char out[49])
{
    out[0] = '\0';
    unsigned max_ext = __get_cpuid_max(0x80000000u, NULL);
    if (max_ext < 0x80000004u) {
        return;
    }

    unsigned regs[12];
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
            out[pos++] = (char)((regs[i] >> (j * 8)) & 0xFF);
        }
    }
    out[48] = '\0';

    char *start = out;
    while (*start == ' ') {
        ++start;
    }
    if (start != out) {
        memmove(out, start, strlen(start) + 1);
    }
    size_t len = strlen(out);
    while (len > 0 && out[len - 1] == ' ') {
        out[--len] = '\0';
    }
}

static void cpu_topology(CpuInfo *ci)
{
    ci->max_basic = __get_cpuid_max(0, NULL);

    unsigned leaf = 0;
    if (ci->max_basic >= 0x1Fu) {
        leaf = 0x1Fu;
    } else if (ci->max_basic >= 0x0Bu) {
        leaf = 0x0Bu;
    }
    if (!leaf) {
        return;
    }

    unsigned smt = 0, core = 0;
    for (unsigned sub = 0; sub < 8; ++sub) {
        unsigned a, b, c, d;
        __cpuid_count(leaf, sub, a, b, c, d);
        unsigned type = (c >> 8) & 0xFF;
        if (!type) {
            break;
        }
        unsigned count = b & 0xFFFF;
        if (type == 1 && count > smt) {
            smt = count;
        } else if (type == 2) {
            core = count;
        }
    }

    if (smt && core && core >= smt && core % smt == 0) {
        ci->topo_ok = 1;
        ci->smt = smt;
        ci->cores = core / smt;
        ci->threads = core;
    }
}

static void cpu_read(CpuInfo *ci)
{
    memset(ci, 0, sizeof(*ci));

    unsigned a = 0, b = 0, c = 0, d = 0;
    if (__get_cpuid(1, &a, &b, &c, &d)) {
        ci->ok = 1;
        ci->eax = a;
        unsigned base_family = (a >> 8) & 0xF;
        unsigned ext_family = (a >> 20) & 0xFF;
        unsigned base_model = (a >> 4) & 0xF;
        unsigned ext_model = (a >> 16) & 0xF;

        ci->stepping = a & 0xF;
        ci->family = (base_family == 0xF) ? base_family + ext_family : base_family;
        ci->model = base_model;
        if (ci->family == 0x6 || ci->family == 0xF) {
            ci->model += ext_model << 4;
        }
    }

    cpu_vendor(ci->vendor);
    cpu_brand_string(ci->brand);
    cpu_topology(ci);

    ci->win_logical = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
}

/* Modelli il cui numero di core/thread e' noto dal nome commerciale. La
   tabella copre solo i modelli desktop piu' comuni: se il brand non compare
   qui non viene fatto alcun confronto (nessun falso positivo). */
typedef struct {
    const char *model;
    unsigned cores;
    unsigned threads;
} BrandSpec;

static const BrandSpec brand_specs[] = {
    { "i7-5820k",  6, 12 }, { "i7-5930k",  6, 12 }, { "i7-5960x",  8, 16 },
    { "i7-6700k",  4,  8 }, { "i7-7700k",  4,  8 },
    { "i7-8086k",  6, 12 }, { "i7-8700k",  6, 12 }, { "i5-8400",   6,  6 },
    { "i5-8600k",  6,  6 }, { "i5-9600k",  6,  6 },
    { "i7-9700k",  8,  8 }, { "i9-9900ks", 8, 16 }, { "i9-9900k",  8, 16 },
    { "i5-10400",  6, 12 }, { "i7-10700k", 8, 16 }, { "i9-10850k",10, 20 },
    { "i9-10900k",10, 20 }, { "i5-11600k", 6, 12 }, { "i7-11700k", 8, 16 },
    { "i9-11900k", 8, 16 }, { "i5-12600k",10, 16 }, { "i7-12700k",12, 20 },
    { "i9-12900k",16, 24 }, { "i5-13600k",14, 20 }, { "i7-13700k",16, 24 },
    { "i9-13900k",24, 32 }, { "i7-14700k",20, 28 }, { "i9-14900k",24, 32 },
    { "ryzen 5 3600", 6, 12 }, { "ryzen 5 5600x", 6, 12 },
    { "ryzen 7 3700x", 8, 16 }, { "ryzen 7 5800x", 8, 16 },
    { "ryzen 9 5900x",12, 24 }, { "ryzen 9 5950x",16, 32 },
    { "ryzen 5 7600x", 6, 12 }, { "ryzen 7 7700x", 8, 16 },
    { "ryzen 9 7900x",12, 24 }, { "ryzen 9 7950x",16, 32 },
};

static const BrandSpec *brand_spec(const char *brand)
{
    for (size_t i = 0; i < sizeof(brand_specs) / sizeof(brand_specs[0]); ++i) {
        if (vd_ci_contains(brand, brand_specs[i].model)) {
            return &brand_specs[i];
        }
    }
    return NULL;
}

static int cpu_is_intel(const CpuInfo *ci)
{
    return strcmp(ci->vendor, "GenuineIntel") == 0;
}

static int cpu_is_amd(const CpuInfo *ci)
{
    return strcmp(ci->vendor, "AuthenticAMD") == 0;
}

/* Regola 1: family/model/stepping contro il brand. */
static void check_family_model(VdReport *r, const CpuInfo *ci)
{
    if (!ci->ok || !ci->brand[0]) {
        vd_add(r, CAT, "Family/model/stepping vs brand", M_FMS, VDS_SKIP, 0,
               "CPUID.1 o brand string non disponibili");
        return;
    }

    int core_brand = vd_ci_contains(ci->brand, "core(tm)");
    int amd_brand = vd_ci_contains(ci->brand, "amd") ||
                    vd_ci_contains(ci->brand, "ryzen");
    int bad = 0;

    if (core_brand && !cpu_is_intel(ci)) {
        vd_add_contradiction(r, CAT, "Vendor CPUID e brand Intel", M_FMS, 35,
                             "brand \"%s\" ma vendor CPUID \"%s\": impossibile",
                             ci->brand, ci->vendor);
        bad = 1;
    } else if (core_brand && ci->family != 6) {
        vd_add_contradiction(r, CAT, "Family CPUID incompatibile col brand",
                             M_FMS, 30,
                             "brand \"%s\" (family 6 attesa) ma CPUID.1 "
                             "EAX=0x%08X riporta family %u, model %u, "
                             "stepping %u",
                             ci->brand, ci->eax, ci->family, ci->model,
                             ci->stepping);
        bad = 1;
    }

    if (!bad && amd_brand && !cpu_is_amd(ci)) {
        vd_add_contradiction(r, CAT, "Vendor CPUID e brand AMD", M_FMS, 35,
                             "brand \"%s\" ma vendor CPUID \"%s\": impossibile",
                             ci->brand, ci->vendor);
        bad = 1;
    } else if (!bad && amd_brand && ci->family != 0x17 && ci->family != 0x19 &&
               ci->family != 0x1A) {
        vd_add_contradiction(r, CAT, "Family CPUID incompatibile col brand",
                             M_FMS, 30,
                             "brand \"%s\" (family 17h/19h/1Ah attesa) ma "
                             "CPUID.1 EAX=0x%08X riporta family %u, model %u",
                             ci->brand, ci->eax, ci->family, ci->model);
        bad = 1;
    }

    if (!bad) {
        vd_add(r, CAT, "Family/model/stepping vs brand", M_FMS, VDS_CLEAN, 0,
               "family %u, model %u, stepping %u (CPUID.1 EAX=0x%08X) coerenti "
               "con \"%s\" (vendor %s)",
               ci->family, ci->model, ci->stepping, ci->eax,
               ci->brand, ci->vendor);
    }
}

/* Regola 6: comportamento delle foglie CPUID non valide (solo Intel). */
static void check_invalid_leaf(VdReport *r, const CpuInfo *ci)
{
    if (!ci->ok || !cpu_is_intel(ci) || ci->max_basic < 1 ||
        ci->max_basic >= 0xFFFFFFFEu) {
        vd_add(r, CAT, "Foglie CPUID non valide", M_LEAF, VDS_SKIP, 0,
               "controllo non applicabile (CPU non Intel o foglia massima ignota)");
        return;
    }

    unsigned a0 = 0, b0 = 0, c0 = 0, d0 = 0;
    unsigned a1 = 0, b1 = 0, c1 = 0, d1 = 0;
    __cpuid_count(ci->max_basic, 0, a0, b0, c0, d0);
    __cpuid_count(ci->max_basic + 1, 0, a1, b1, c1, d1);

    int same = a0 == a1 && b0 == b1 && c0 == c1 && d0 == d1;
    int zero = a1 == 0 && b1 == 0 && c1 == 0 && d1 == 0;

    if (!same && !zero) {
        vd_add(r, CAT, "Clamp CPUID non rispettato", M_LEAF, VDS_DETECTED, 4,
               "foglia 0x%X restituisce %08X %08X %08X %08X, la foglia massima "
               "0x%X restituisce %08X %08X %08X %08X: un Intel fisico clampa",
               ci->max_basic + 1, a1, b1, c1, d1,
               ci->max_basic, a0, b0, c0, d0);
    } else {
        vd_add(r, CAT, "Foglie CPUID non valide", M_LEAF, VDS_CLEAN, 0,
               "foglia massima 0x%X, foglia successiva %s (clamp Intel)",
               ci->max_basic, same ? "identica" : "nulla");
    }
}

/* ---------------------------------------------------------------- SMBIOS */

typedef struct {
    int ok;
    int structures;
    BYTE seen[128];
    char cpu_socket[64];
    char cpu_man[64];
    char cpu_ver[96];
    unsigned cpu_family;
    unsigned cpu_cores;
    unsigned cpu_threads;
    int dimm_count;
    unsigned long long dimm_total_mb;
    unsigned long long dimm_max_mb;
    int dimm_placeholder_serial;
    int type16, type17;
} SmbiosCoherence;

static void cs_str(const BYTE *fmt, const BYTE *end, BYTE index,
                   char *out, size_t outsz)
{
    out[0] = '\0';
    if (!index) {
        return;
    }
    const BYTE *p = fmt;
    for (BYTE n = 1; n < index && p < end; ++n) {
        if (*p == 0) {
            return;
        }
        while (p < end && *p) {
            ++p;
        }
        if (p >= end) {
            return;
        }
        ++p;
    }
    if (p >= end || *p == 0) {
        return;
    }
    size_t pos = 0;
    while (p < end && *p && pos + 1 < outsz) {
        unsigned char ch = *p++;
        out[pos++] = (ch >= 32 && ch != 127) ? (char)ch : '?';
    }
    out[pos] = '\0';
}

static const BYTE *cs_next(const BYTE *p, const BYTE *end)
{
    if (p + 4 > end) {
        return NULL;
    }
    BYTE len = p[1];
    if (len < 4) {
        return NULL;
    }
    const BYTE *q = p + len;
    if (q >= end) {
        return NULL;
    }
    while (q + 1 < end && !(q[0] == 0 && q[1] == 0)) {
        ++q;
    }
    if (q + 1 >= end) {
        return NULL;
    }
    return q + 2;
}

static int serial_is_placeholder(const char *serial)
{
    if (!serial[0]) {
        return 1;
    }
    int all_zero = 1;
    int all_same = 1;
    char first = serial[0];
    for (const char *p = serial; *p; ++p) {
        if (*p != '0' && *p != ' ') all_zero = 0;
        if (*p != first) all_same = 0;
    }
    return all_zero || all_same ||
           vd_ci_contains(serial, "not specified") ||
           vd_ci_contains(serial, "to be filled");
}

static void smbios_read(SmbiosCoherence *s)
{
    memset(s, 0, sizeof(*s));

    DWORD needed = GetSystemFirmwareTable(0x52534D42u /* RSMB */, 0, NULL, 0);
    if (needed < 8) {
        return;
    }
    BYTE *buf = (BYTE *)malloc(needed);
    if (!buf) {
        return;
    }
    DWORD got = GetSystemFirmwareTable(0x52534D42u, 0, buf, needed);
    if (got < 8) {
        free(buf);
        return;
    }

    DWORD table_len = *(const DWORD *)(buf + 4);
    const BYTE *p = buf + 8;
    const BYTE *end = buf + 8 + table_len;
    if (end > buf + got) {
        end = buf + got;
    }

    s->ok = 1;
    while (p && p + 4 <= end) {
        BYTE type = p[0];
        BYTE len = p[1];
        const BYTE *fmt = p + len;

        ++s->structures;
        if (type < 128) {
            s->seen[type] = 1;
        }
        if (type == 127) {
            break;
        }

        if (type == 4 && len >= 0x24) {
            cs_str(fmt, end, p[4], s->cpu_socket, sizeof(s->cpu_socket));
            cs_str(fmt, end, p[7], s->cpu_man, sizeof(s->cpu_man));
            if (len >= 0x11) {
                cs_str(fmt, end, p[0x10], s->cpu_ver, sizeof(s->cpu_ver));
            }
            s->cpu_family = p[6];
            s->cpu_cores = p[0x23];
            unsigned threads = 0;
            if (s->cpu_cores) {
                /* Alcuni BIOS usano il layout SMBIOS 2.3 (thread count a 1
                   byte a 0x25, characteristics a 0x26) pur dichiarando una
                   lunghezza 2.5. Si accetta il valore plausibile. */
                if (len >= 0x27) {
                    unsigned word = (unsigned)p[0x25] |
                                    ((unsigned)p[0x26] << 8);
                    if (word >= s->cpu_cores && word <= s->cpu_cores * 8) {
                        threads = word;
                    }
                }
                if (!threads) {
                    unsigned byte = p[0x25];
                    if (byte >= s->cpu_cores && byte <= s->cpu_cores * 8) {
                        threads = byte;
                    }
                }
            }
            s->cpu_threads = threads;
        } else if (type == 16) {
            s->type16 = 1;
        } else if (type == 17 && len >= 0x1B) {
            s->type17 = 1;
            unsigned long long mb =
                (unsigned long long)p[0x0C] | ((unsigned long long)p[0x0D] << 8);
            if (mb == 0x7FFF && len >= 0x20) {
                mb = *(const DWORD *)(p + 0x1C) & 0x7FFFFFFFu;
            }
            if (mb) {
                ++s->dimm_count;
                s->dimm_total_mb += mb;
                if (mb > s->dimm_max_mb) {
                    s->dimm_max_mb = mb;
                }
                char serial[64];
                cs_str(fmt, end, p[0x18], serial, sizeof(serial));
                if (serial_is_placeholder(serial)) {
                    ++s->dimm_placeholder_serial;
                }
            }
        }

        p = cs_next(p, end);
    }

    free(buf);
}

/* Regola 2: core/thread contro brand, SMBIOS e Windows. */
static void check_cores(VdReport *r, const CpuInfo *ci, const SmbiosCoherence *s)
{
    const BrandSpec *spec = brand_spec(ci->brand);
    int bad = 0;

    if (spec && ci->topo_ok &&
        (ci->cores != spec->cores || ci->threads != spec->threads)) {
        vd_add_contradiction(r, CAT, "Core/thread incompatibili col brand",
                             M_CORES, 30,
                             "\"%s\" prevede %uC/%uT, ma CPUID riporta %uC/%uT "
                             "(Windows vede %u thread, SMBIOS %uC/%uT)",
                             ci->brand, spec->cores, spec->threads,
                             ci->cores, ci->threads, ci->win_logical,
                             s->cpu_cores, s->cpu_threads);
        bad = 1;
    } else if (spec && !ci->topo_ok && s->cpu_cores &&
               (s->cpu_cores != spec->cores ||
                (s->cpu_threads && s->cpu_threads != spec->threads))) {
        vd_add_contradiction(r, CAT, "Core/thread incompatibili col brand",
                             M_CORES, 25,
                             "\"%s\" prevede %uC/%uT, ma SMBIOS tipo 4 riporta "
                             "%uC/%uT",
                             ci->brand, spec->cores, spec->threads,
                             s->cpu_cores, s->cpu_threads);
        bad = 1;
    }

    if (!bad && ci->topo_ok && s->cpu_cores && s->cpu_cores != ci->cores) {
        vd_add_contradiction(r, CAT, "SMBIOS e CPUID discordi sui core",
                             M_CORES, 20,
                             "CPUID riporta %u core, SMBIOS tipo 4 ne dichiara "
                             "%u (Windows vede %u thread)",
                             ci->cores, s->cpu_cores, ci->win_logical);
        bad = 1;
    }

    if (!bad) {
        if (spec && ci->topo_ok) {
            vd_add(r, CAT, "Core/thread coerenti", M_CORES, VDS_CLEAN, 0,
                   "\"%s\" = %uC/%uT; CPUID %uC/%uT; Windows %u thread; "
                   "SMBIOS %uC/%uT",
                   ci->brand, spec->cores, spec->threads,
                   ci->cores, ci->threads, ci->win_logical,
                   s->cpu_cores, s->cpu_threads);
        } else if (ci->topo_ok) {
            vd_add(r, CAT, "Topologia CPU", M_CORES, VDS_INFO, 0,
                   "CPUID %uC/%uT; Windows %u thread; SMBIOS %uC/%uT "
                   "(brand non in tabella, nessun confronto)",
                   ci->cores, ci->threads, ci->win_logical,
                   s->cpu_cores, s->cpu_threads);
        } else {
            vd_add(r, CAT, "Topologia CPU", M_CORES, VDS_SKIP, 0,
                   "foglia topologica non disponibile; Windows vede %u thread",
                   ci->win_logical);
        }
    }
}

/* Regola 4: memoria SMBIOS contro memoria di Windows. */
static void check_memory(VdReport *r, const SmbiosCoherence *s)
{
    if (!s->ok || !s->dimm_count) {
        vd_add(r, CAT, "Memoria SMBIOS vs Windows", M_MEM, VDS_SKIP, 0,
               "moduli di memoria (SMBIOS tipo 17) non leggibili");
        return;
    }

    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (!GlobalMemoryStatusEx(&ms) || !ms.ullTotalPhys) {
        vd_add(r, CAT, "Memoria SMBIOS vs Windows", M_MEM, VDS_SKIP, 0,
               "GlobalMemoryStatusEx non disponibile");
        return;
    }

    unsigned long long os_mb = ms.ullTotalPhys / (1024ull * 1024ull);
    int bad = 0;

    if (s->dimm_max_mb > os_mb + 512) {
        vd_add_contradiction(r, CAT, "Modulo di memoria piu' grande del sistema",
                             M_MEM, 25,
                             "un modulo SMBIOS dichiara %llu MB ma Windows vede "
                             "solo %llu MB di RAM",
                             s->dimm_max_mb, os_mb);
        bad = 1;
    } else if (s->dimm_total_mb > os_mb + os_mb / 2 + 1024) {
        vd_add_contradiction(r, CAT, "Memoria SMBIOS superiore al sistema",
                             M_MEM, 20,
                             "i moduli SMBIOS sommano %llu MB ma Windows vede "
                             "%llu MB: differenza impossibile",
                             s->dimm_total_mb, os_mb);
        bad = 1;
    } else if (os_mb > s->dimm_total_mb * 2 + 2048) {
        vd_add_contradiction(r, CAT, "Memoria SMBIOS molto inferiore al sistema",
                             M_MEM, 20,
                             "i moduli SMBIOS sommano solo %llu MB mentre "
                             "Windows vede %llu MB: moduli mancanti o inventati",
                             s->dimm_total_mb, os_mb);
        bad = 1;
    }

    if (!bad) {
        vd_add(r, CAT, "Memoria SMBIOS vs Windows", M_MEM, VDS_CLEAN, 0,
               "%d moduli per %llu MB, Windows vede %llu MB (coerenti)",
               s->dimm_count, s->dimm_total_mb, os_mb);

        if (s->dimm_count >= 2 &&
            s->dimm_placeholder_serial * 2 >= s->dimm_count) {
            vd_add(r, CAT, "Seriali dei moduli memoria", M_MEM,
                   VDS_DETECTED, 6,
                   "%d/%d moduli hanno un seriale vuoto o segnaposto "
                   "(00000000/Not Specified): tipico delle VM",
                   s->dimm_placeholder_serial, s->dimm_count);
        }
    }
}

/* Regola 5: inventario delle strutture SMBIOS. */
static void check_inventory(VdReport *r, const SmbiosCoherence *s)
{
    if (!s->ok) {
        vd_add(r, CAT, "Inventario SMBIOS", M_INV, VDS_SKIP, 0,
               "tabella SMBIOS non leggibile");
        return;
    }

    int missing = 0;
    missing += !s->seen[7];
    missing += !s->seen[9];
    missing += !s->seen[11];
    missing += !s->seen[32];

    if (s->structures < 16 && missing >= 3) {
        vd_add_contradiction(r, CAT, "Inventario SMBIOS ridotto", M_INV, 20,
                             "solo %d strutture SMBIOS e mancano %d dei tipi "
                             "7/9/11/32: un firmware desktop completo ne espone "
                             "molte di piu'",
                             s->structures, missing);
    } else if ((!s->type16 || !s->type17) && s->seen[1]) {
        vd_add_contradiction(r, CAT, "SMBIOS senza array di memoria", M_INV, 12,
                             "mancano le strutture tipo 16/17 (memoria) mentre "
                             "il sistema ne dichiara: firmware virtuale minimale");
    } else {
        vd_add(r, CAT, "Inventario SMBIOS", M_INV, VDS_CLEAN, 0,
               "%d strutture, tipi 7/9/11/32 %s",
               s->structures, missing == 0 ? "presenti" : "incompleti");
    }
}

/* ------------------------------------------------------------------ PCI */

typedef struct {
    int keys;
    int subsys_virtual;
    char subsys_example[384];
    int ich9;
    char ich9_example[192];
    int pch_modern;
    int igpu_legacy;
    char igpu_example[192];
} PciInfo;

static int is_virtual_subvendor(unsigned v)
{
    return v == 0x15AD || v == 0x80EE || v == 0x1AF4 || v == 0x1B36 ||
           v == 0x5853 || v == 0x1AB8 || v == 0x1234 || v == 0x1D0F ||
           v == 0x1AE0;
}

static int is_legacy_intel_gpu(unsigned dev)
{
    static const unsigned ids[] = {
        0x29C2, 0x2A42, 0x2E32, 0x0042, 0x0046, 0x0102, 0x0112,
        0x0122, 0x0162, 0x0412, 0x0A16, 0x0D26, 0x1616, 0x1622,
        0x1902, 0x1912, 0x1922, 0x5912, 0x3E92, 0x9BC5, 0x4692,
        0xA780,
    };
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); ++i) {
        if (dev == ids[i]) {
            return 1;
        }
    }
    return 0;
}

static int is_ich9(unsigned dev)
{
    return dev == 0x2918 || dev == 0x2922 || dev == 0x2930 || dev == 0x293A;
}

static void pci_scan(PciInfo *pi)
{
    memset(pi, 0, sizeof(*pi));

    HKEY key = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Enum\\PCI", 0,
                      KEY_READ, &key) != ERROR_SUCCESS) {
        return;
    }

    for (DWORD i = 0; i < 4096; ++i) {
        wchar_t name[512];
        DWORD name_len = (DWORD)(sizeof(name) / sizeof(name[0]));
        if (RegEnumKeyExW(key, i, name, &name_len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
            break;
        }
        ++pi->keys;

        char id[512];
        vd_utf16_to_utf8(name, id, sizeof(id));
        vd_lower_ascii(id);

        const char *ven = strstr(id, "ven_");
        const char *dev = strstr(id, "dev_");
        const char *sub = strstr(id, "subsys_");
        if (!ven || !dev) {
            continue;
        }

        unsigned dev_id = (unsigned)(strtoul(dev + 4, NULL, 16) & 0xFFFF);

        if (sub && strlen(sub + 7) >= 8) {
            unsigned sys = (unsigned)strtoul(sub + 7, NULL, 16);
            unsigned subvendor = sys & 0xFFFF;
            if (is_virtual_subvendor(subvendor)) {
                ++pi->subsys_virtual;
                if (!pi->subsys_example[0]) {
                    snprintf(pi->subsys_example, sizeof(pi->subsys_example),
                             "%.140s", id);
                }
            }
        }

        if (is_ich9(dev_id)) {
            pi->ich9 = 1;
            if (!pi->ich9_example[0]) {
                snprintf(pi->ich9_example, sizeof(pi->ich9_example),
                         "%.180s", id);
            }
        }
        if ((dev_id >= 0x2F00 && dev_id <= 0x2FFF) ||
            (dev_id >= 0x8D00 && dev_id <= 0x8DFF) ||
            (dev_id >= 0xA100 && dev_id <= 0xA1FF)) {
            pi->pch_modern = 1;
        }
        if (is_legacy_intel_gpu(dev_id) && vd_ci_contains(id, "ven_8086")) {
            pi->igpu_legacy = 1;
            if (!pi->igpu_example[0]) {
                snprintf(pi->igpu_example, sizeof(pi->igpu_example),
                         "%.180s", id);
            }
        }
    }
    RegCloseKey(key);
}

static int cpu_is_e_series(const char *brand)
{
    return vd_ci_contains(brand, "i7-58") || vd_ci_contains(brand, "i7-59") ||
           vd_ci_contains(brand, "i7-68") || vd_ci_contains(brand, "i7-69") ||
           (vd_ci_contains(brand, "xeon") &&
            (vd_ci_contains(brand, "e5-26") || vd_ci_contains(brand, "e5-16")));
}

/* Regola 3: PCI device/subsystem e combinazioni piattaforma/CPU. */
static void check_pci(VdReport *r, const CpuInfo *ci)
{
    PciInfo pi;
    pci_scan(&pi);

    if (!pi.keys) {
        vd_add(r, CAT, "Coerenza PCI (device/subsystem)", M_PCI, VDS_SKIP, 0,
               "Enum\\PCI non accessibile");
        return;
    }

    int bad = 0;
    int e_series = cpu_is_e_series(ci->brand);

    if (pi.subsys_virtual) {
        vd_add_contradiction(r, CAT, "Subsystem PCI di vendor virtuale", M_PCI,
                             35,
                             "%d device PCI con subsystem di un vendor virtuale, "
                             "es. %s: il subsystem sopravvive allo spoofing di "
                             "VEN_/DEV_",
                             pi.subsys_virtual,
                             pi.subsys_example[0] ? pi.subsys_example : "?");
        bad = 1;
    }

    if (e_series && pi.igpu_legacy) {
        vd_add_contradiction(r, CAT, "GPU Intel su CPU senza iGPU", M_PCI, 30,
                             "la CPU \"%s\" non ha grafica integrata, ma Enum\\PCI "
                             "contiene un iGPU Intel (%s): combinazione impossibile",
                             ci->brand, pi.igpu_example[0] ? pi.igpu_example : "?");
        bad = 1;
    }

    if (e_series && pi.ich9 && !pi.pch_modern) {
        vd_add_contradiction(r, CAT, "Chipset ICH9 su piattaforma -E", M_PCI, 25,
                             "CPU \"%s\" con chipset ICH9 (%s) e nessun PCH "
                             "2Fxx/8Dxx/A1xx: un PC X99/C610 non puo' averlo",
                             ci->brand, pi.ich9_example[0] ? pi.ich9_example : "?");
        bad = 1;
    }

    if (!bad) {
        vd_add(r, CAT, "Coerenza PCI (device/subsystem)", M_PCI, VDS_CLEAN, 0,
               "%d device PCI esaminati; nessun subsystem virtuale%s%s",
               pi.keys,
               e_series && pi.pch_modern ? "; PCH moderno presente" : "",
               e_series && !pi.igpu_legacy ? "; nessun iGPU su CPU -E" : "");
    }
}

/* --------------------------------------------------------- SMBIOS ident */

/* Vendor CPUID contro produttore CPU SMBIOS (tipo 4). */
static void check_smbios_cpu_identity(VdReport *r, const CpuInfo *ci,
                                      const SmbiosCoherence *s)
{
    if (!s->ok || !s->cpu_man[0]) {
        return;
    }

    int man_intel = vd_ci_contains(s->cpu_man, "intel");
    int man_amd = vd_ci_contains(s->cpu_man, "amd");

    if ((man_intel && cpu_is_amd(ci)) || (man_amd && cpu_is_intel(ci))) {
        vd_add_contradiction(r, CAT, "Produttore CPU SMBIOS e CPUID discordi",
                             M_FMS, 25,
                             "SMBIOS tipo 4 dichiara \"%s\", CPUID riporta \"%s\"",
                             s->cpu_man, ci->vendor);
    }

    if (vd_ci_contains(s->cpu_ver, "virtual")) {
        vd_add(r, CAT, "Versione CPU SMBIOS virtuale", M_FMS, VDS_DETECTED, 8,
               "\"%s\"", s->cpu_ver);
    }
}

void checks_coherence(VdReport *r)
{
    CpuInfo ci;
    cpu_read(&ci);

    SmbiosCoherence smb;
    smbios_read(&smb);

    check_family_model(r, &ci);
    check_cores(r, &ci, &smb);
    check_pci(r, &ci);
    check_memory(r, &smb);
    check_inventory(r, &smb);
    check_invalid_leaf(r, &ci);
    check_smbios_cpu_identity(r, &ci, &smb);
}

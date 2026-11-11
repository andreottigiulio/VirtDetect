/* ===========================================================================
   RILEVAMENTO DAL FIRMWARE (SMBIOS / ACPI)
   ===========================================================================

   Ogni PC espone una tabella SMBIOS (chiamata anche DMI) che descrive
   produttore, modello, scheda madre, BIOS, chassis, memorie e UUID. Il
   firmware ACPI aggiunge le tabelle usate dal sistema operativo. Gli
   hypervisor devono emulare tutto questo: quasi sempre lo fanno con valori
   incompleti o con nomi riconoscibili.

   Metodi implementati in questo file
   ----------------------------------
   5) Identita' SMBIOS (tipo 0, 1, 2, 3).
      Legge produttore/modello/versione/seriale di sistema, scheda madre e
      chassis con GetSystemFirmwareTable('RSMB') e cerca i marchi dei
      vendor virtuali ("VMware", "VirtualBox", "QEMU", "innotek"...).
      Peso 35: e' un indizio molto forte ma un firmware reale puo' essere
      "spoofato" da una VM indurita.

   6) Stringhe BIOS (tipo 0).
      Confronta vendor, versione e data del BIOS con i firmware usati dagli
      emulatori: SeaBIOS e OVMF/EDK II (QEMU), stringhe AMI/Insyde delle VM
      VMware/VirtualBox. Peso 15.

   7) UUID di sistema (tipo 1).
      Un PC fisico ha un UUID casuale assegnato dal produttore. Le VM
      spesso usano tutti 0x00/0xFF oppure un UUID con prefisso 0x564D
      (le lettere "VM" in ASCII). Peso 8, indizio debole.

   8) Moduli di memoria (tipo 17).
      Le VM dichiarano memorie con produttore/modello virtuali o vuoti.
      Peso 6.

   9) Tabelle ACPI (FADT) e registro.
      La tabella FADT contiene OEM ID e creator; i firmware virtuali usano
      "QEMU", "BOCHS_", "VBOX__", "XenVMMXenVMM". Le stesse stringhe
      compaiono nelle chiavi HKLM\HARDWARE\ACPI. Peso 20/15.
      Se 'FIRM' non e' leggibile (BIOS legacy) si usa il fallback:
      inventario con EnumSystemFirmwareTables, registro HARDWARE\ACPI e dati
      secondari (MSDM, thermal zone, PNP0C14). La scansione EBDA/F-segment
      richiede un driver kernel: il limite viene dichiarato, non ignorato.

   Falsi positivi
   --------------
   Un PC fisico non contiene nessuna di queste stringhe; il rischio e' il
   contrario (VM che falsificano i valori). Le stringhe BIOS nel registro
   (HKLM\HARDWARE\DESCRIPTION\System\BIOS) sono solo una copia di quelle
   SMBIOS, percio' valgono meno (20 punti) e servono a confermare.
   =========================================================================== */

#include "checks.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#define CAT "Firmware (SMBIOS/ACPI)"
#define VD_RSMB 0x52534D42u   /* 'RSMB': tabella SMBIOS grezza */
#define VD_FIRM 0x4649524Du   /* 'FIRM': tabelle ACPI del firmware */
#define VD_ACPI 0x41435049u   /* 'ACPI': provider delle singole tabelle */

/* Testi mostrati a schermo. */
static const char *const M_SMBIOS =
    "Legge la tabella SMBIOS dal firmware (GetSystemFirmwareTable 'RSMB') e "
    "cerca i marchi dei vendor virtuali in produttore, prodotto e scheda madre.";
static const char *const M_BIOS =
    "Confronta vendor, versione e data del BIOS con i firmware tipici delle "
    "VM (SeaBIOS, OVMF/EDK II, stringhe AMI virtuali).";
static const char *const M_UUID =
    "Analizza l'UUID di sistema (SMBIOS tipo 1): tutti 0x00/0xFF o il "
    "prefisso 0x564D ('VM') indicano un UUID generato dall'hypervisor.";
static const char *const M_MEMORY =
    "Legge i moduli di memoria (SMBIOS tipo 17) e cerca produttori o modelli "
    "usati dalle VM.";
static const char *const M_CHASSIS =
    "Legge il tipo di chassis (SMBIOS tipo 3): 'Other'/'Unknown' sono comuni "
    "nelle VM ma anche su hardware generico.";
static const char *const M_SMBIOS_RAW =
    "Mostra i campi SMBIOS grezzi letti dal firmware (solo dato diagnostico).";
static const char *const M_FADT =
    "Legge la tabella ACPI FADT dal firmware ('FIRM') e controlla OEM ID, "
    "OEM Table ID e creator (QEMU, BOCHS_, VBOX__...). Se il firmware non "
    "espone le tabelle, il controllo passa al registro (fallback) e dichiara "
    "il limite invece di considerare la macchina pulita.";
static const char *const M_ACPI_LIST =
    "Elenca le tabelle ACPI visibili con EnumSystemFirmwareTables: un "
    "inventario molto ridotto e' tipico dei firmware virtuali. La lettura "
    "diretta di EBDA/F-segment richiede accesso fisico alla memoria (driver "
    "kernel) e non e' possibile da utente standard.";
static const char *const M_ACPI_EXTRA =
    "Fallback quando 'FIRM' non e' leggibile: cerca la tabella MSDM (chiave "
    "OEM Windows) e i device ACPI thermal zone e PNP0C14 (WMI). Sono dati "
    "diagnostici: l'assenza e' normale su desktop e PC assemblati e non "
    "viene conteggiata.";
static const char *const M_ACPI_REG =
    "Elenca le chiavi HKLM\\HARDWARE\\ACPI (DSDT/FADT/RSDT/XSDT) cercando un "
    "OEM ID di virtualizzazione.";
static const char *const M_BIOS_REG =
    "Legge HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS e confronta i valori con "
    "i marchi virtuali.";
static const char *const M_BIOS_RAW =
    "Valore del registro BIOS letto singolarmente (dato grezzo utile a capire "
    "cosa vede Windows).";
static const char *const M_SYSINFO =
    "Legge SYSTEM\\CurrentControlSet\\Control\\SystemInformation, la copia "
    "usata da Windows per il modello del sistema.";

typedef struct {
    char bios_vendor[128];
    char bios_version[128];
    char bios_date[128];

    char sys_man[128];
    char sys_prod[128];
    char sys_ver[128];
    char sys_serial[128];
    char sys_sku[128];
    char sys_family[128];
    char uuid[48];
    BYTE uuid_raw[16];
    int  uuid_ok;

    char board_man[128];
    char board_prod[128];
    char board_ver[128];
    char board_serial[128];

    char chassis_man[128];
    char chassis_ver[128];
    char chassis_serial[128];
    BYTE chassis_type;

    char memory[512];
    int  memory_found;
} SmbiosInfo;

static void app(char *dst, size_t cap, const char *fmt, ...)
{
    size_t used = strlen(dst);
    if (used + 1 >= cap) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(dst + used, cap - used, fmt, ap);
    va_end(ap);
}

static void trim_spaces(char *s)
{
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t' ||
                       s[len - 1] == '\r' || s[len - 1] == '\n')) {
        s[--len] = '\0';
    }
    size_t start = 0;
    while (s[start] == ' ' || s[start] == '\t') {
        ++start;
    }
    if (start) {
        memmove(s, s + start, strlen(s + start) + 1);
    }
}

/* Le stringhe SMBIOS non sono inline: ogni struttura ha un indice e le
   stringhe stanno subito dopo, ciascuna terminata da un singolo NUL, con un
   NUL aggiuntivo a chiudere l'elenco. La funzione scorre fino alla stringa
   numero "index" (1-based). */
static void smbios_string(const BYTE *fmt, const BYTE *end, BYTE index,
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
        while (p < end && *p != 0) {
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
    trim_spaces(out);
}

/* Struttura successiva: salta la parte formattata e l'elenco di stringhe
   terminato da doppio NUL. */
static const BYTE *smbios_next(const BYTE *p, const BYTE *end)
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

/* UUID SMBIOS: i primi tre campi sono little-endian, gli altri big-endian. */
static void format_uuid(const BYTE *u, char *out, size_t outsz)
{
    snprintf(out, outsz,
             "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
             u[3], u[2], u[1], u[0], u[5], u[4], u[7], u[6],
             u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
}

static int uuid_is_placeholder(const BYTE *u)
{
    int all_zero = 1;
    int all_ff = 1;
    for (int i = 0; i < 16; ++i) {
        if (u[i] != 0x00) all_zero = 0;
        if (u[i] != 0xFF) all_ff = 0;
    }
    return all_zero || all_ff;
}

static int read_smbios(BYTE **data, DWORD *length)
{
    DWORD needed = GetSystemFirmwareTable(VD_RSMB, 0, NULL, 0);
    if (needed < 8) {
        return 0;
    }
    BYTE *buf = (BYTE *)malloc(needed);
    if (!buf) {
        return 0;
    }
    DWORD got = GetSystemFirmwareTable(VD_RSMB, 0, buf, needed);
    if (got < 8) {
        free(buf);
        return 0;
    }
    *data = buf;
    *length = got;
    return 1;
}

/* Parser SMBIOS: il buffer restituito da Windows ha un header di 8 byte
   (firma + lunghezza), poi le strutture concatenate. Ci interessano i tipi
   0 (BIOS), 1 (sistema), 2 (scheda madre), 3 (chassis) e 17 (memoria). */
static void parse_smbios(const BYTE *data, DWORD length, SmbiosInfo *si)
{
    if (length < 8) {
        return;
    }
    DWORD table_len = *(const DWORD *)(data + 4);
    const BYTE *p = data + 8;
    const BYTE *end = data + 8 + table_len;
    if (end > data + length) {
        end = data + length;
    }

    while (p && p + 4 <= end) {
        BYTE type = p[0];
        BYTE len = p[1];
        const BYTE *fmt = p + len;

        if (type == 127) {
            break;
        }

        if (type == 0 && len >= 0x12) {
            smbios_string(fmt, end, p[4], si->bios_vendor, sizeof(si->bios_vendor));
            smbios_string(fmt, end, p[5], si->bios_version, sizeof(si->bios_version));
            smbios_string(fmt, end, p[8], si->bios_date, sizeof(si->bios_date));
        } else if (type == 1 && len >= 0x08) {
            smbios_string(fmt, end, p[4], si->sys_man, sizeof(si->sys_man));
            smbios_string(fmt, end, p[5], si->sys_prod, sizeof(si->sys_prod));
            smbios_string(fmt, end, p[6], si->sys_ver, sizeof(si->sys_ver));
            smbios_string(fmt, end, p[7], si->sys_serial, sizeof(si->sys_serial));
            if (len >= 0x18) {
                memcpy(si->uuid_raw, p + 8, 16);
                si->uuid_ok = 1;
                format_uuid(si->uuid_raw, si->uuid, sizeof(si->uuid));
            }
            if (len >= 0x1A) {
                smbios_string(fmt, end, p[0x19], si->sys_sku, sizeof(si->sys_sku));
            }
            if (len >= 0x1B) {
                smbios_string(fmt, end, p[0x1A], si->sys_family, sizeof(si->sys_family));
            }
        } else if (type == 2 && len >= 0x08) {
            smbios_string(fmt, end, p[4], si->board_man, sizeof(si->board_man));
            smbios_string(fmt, end, p[5], si->board_prod, sizeof(si->board_prod));
            smbios_string(fmt, end, p[6], si->board_ver, sizeof(si->board_ver));
            smbios_string(fmt, end, p[7], si->board_serial, sizeof(si->board_serial));
        } else if (type == 3 && len >= 0x09) {
            smbios_string(fmt, end, p[4], si->chassis_man, sizeof(si->chassis_man));
            smbios_string(fmt, end, p[5], si->chassis_ver, sizeof(si->chassis_ver));
            smbios_string(fmt, end, p[6], si->chassis_serial, sizeof(si->chassis_serial));
            if (len >= 0x0E) {
                si->chassis_type = p[0x0D];
            }
        } else if (type == 17 && len >= 0x1B) {
            unsigned size = (unsigned)p[0x0C] | ((unsigned)p[0x0D] << 8);
            if (size != 0) {
                char locator[64], man[96], part[96], serial[96];
                smbios_string(fmt, end, p[0x10], locator, sizeof(locator));
                smbios_string(fmt, end, p[0x17], man, sizeof(man));
                smbios_string(fmt, end, p[0x18], serial, sizeof(serial));
                smbios_string(fmt, end, p[0x1A], part, sizeof(part));
                if (man[0] || part[0] || serial[0]) {
                    si->memory_found = 1;
                    app(si->memory, sizeof(si->memory), "%s%s%s%s%s%s%s; ",
                        locator[0] ? locator : "?", "=",
                        man[0] ? man : "", part[0] ? " " : "", part,
                        serial[0] ? " S/N " : "", serial);
                }
            }
        }

        p = smbios_next(p, end);
    }
}

static const char *chassis_name(BYTE type)
{
    switch (type) {
    case 1: return "Other";
    case 2: return "Unknown";
    case 3: return "Desktop";
    case 4: return "Low Profile Desktop";
    case 5: return "Pizza Box";
    case 6: return "Mini Tower";
    case 7: return "Tower";
    case 8: return "Portable";
    case 9: return "Laptop";
    case 10: return "Notebook";
    case 11: return "Hand Held";
    case 12: return "Docking Station";
    case 13: return "All in One";
    case 14: return "Sub Notebook";
    case 15: return "Space-saving";
    case 16: return "Lunch Box";
    case 17: return "Main Server Chassis";
    case 18: return "Expansion Chassis";
    case 19: return "Sub Chassis";
    case 20: return "Bus Expansion Chassis";
    case 21: return "Peripheral Chassis";
    case 22: return "RAID Chassis";
    case 23: return "Rack Mount Chassis";
    case 24: return "Sealed-case PC";
    case 25: return "Multi-system";
    case 26: return "Compact PCI";
    case 27: return "Advanced TCA";
    case 28: return "Blade";
    case 29: return "Blade Enclosure";
    case 30: return "Tablet";
    case 31: return "Convertible";
    case 32: return "Detachable";
    case 33: return "IoT Gateway";
    case 34: return "Embedded PC";
    case 35: return "Mini PC";
    case 36: return "Stick PC";
    default: return "sconosciuto";
    }
}

/* Metodi 5-8: identita' SMBIOS, stringhe BIOS, UUID, memorie, chassis. */
static void check_smbios(VdReport *r)
{
    BYTE *data = NULL;
    DWORD length = 0;
    if (!read_smbios(&data, &length)) {
        vd_add(r, CAT, "Tabella SMBIOS", M_SMBIOS, VDS_SKIP, 0,
               "GetSystemFirmwareTable('RSMB') non disponibile");
        return;
    }

    SmbiosInfo si;
    memset(&si, 0, sizeof(si));
    parse_smbios(data, length, &si);
    free(data);

    char identity[1024] = "";
    if (si.sys_man[0])    app(identity, sizeof(identity), "%s | ", si.sys_man);
    if (si.sys_prod[0])   app(identity, sizeof(identity), "%s | ", si.sys_prod);
    if (si.sys_ver[0])    app(identity, sizeof(identity), "%s | ", si.sys_ver);
    if (si.sys_serial[0]) app(identity, sizeof(identity), "%s | ", si.sys_serial);
    if (si.sys_sku[0])    app(identity, sizeof(identity), "%s | ", si.sys_sku);
    if (si.sys_family[0]) app(identity, sizeof(identity), "%s | ", si.sys_family);
    if (si.board_man[0])  app(identity, sizeof(identity), "%s | ", si.board_man);
    if (si.board_prod[0]) app(identity, sizeof(identity), "%s | ", si.board_prod);
    if (si.board_ver[0])  app(identity, sizeof(identity), "%s | ", si.board_ver);
    if (si.chassis_man[0]) app(identity, sizeof(identity), "%s | ", si.chassis_man);
    if (si.chassis_ver[0]) app(identity, sizeof(identity), "%s | ", si.chassis_ver);

    const char *vendor = vd_vendor_from_text(identity);
    if (vendor) {
        vd_add(r, CAT, "Identita' SMBIOS virtuale", M_SMBIOS, VDS_DETECTED, 35,
               "manuf/prodotto/board contengono un marchio di virtualizzazione "
               "(sistema: %s %s; board: %s %s)",
               si.sys_man, si.sys_prod, si.board_man, si.board_prod);
        vd_note_vendor(r, vendor, 75);
    } else {
        vd_add(r, CAT, "Identita' SMBIOS fisica", M_SMBIOS, VDS_CLEAN, 0,
               "sistema: %s %s | board: %s %s",
               si.sys_man[0] ? si.sys_man : "?",
               si.sys_prod[0] ? si.sys_prod : "?",
               si.board_man[0] ? si.board_man : "?",
               si.board_prod[0] ? si.board_prod : "?");
    }

    char bios[512] = "";
    if (si.bios_vendor[0])  app(bios, sizeof(bios), "%s | ", si.bios_vendor);
    if (si.bios_version[0]) app(bios, sizeof(bios), "%s | ", si.bios_version);
    if (si.bios_date[0])    app(bios, sizeof(bios), "%s", si.bios_date);

    const char *bios_vendor = vd_vendor_from_text(bios);
    if (!bios_vendor &&
        (vd_ci_contains(bios, "seabios") || vd_ci_contains(bios, "ovmf") ||
         vd_ci_contains(bios, "edk ii"))) {
        bios_vendor = VD_VENDOR_QEMU;
    }
    if (bios_vendor) {
        vd_add(r, CAT, "Stringhe BIOS virtuali", M_BIOS, VDS_DETECTED, 15,
               "%s", bios[0] ? bios : "stringhe firmware tipiche di VM");
        vd_note_vendor(r, bios_vendor, 65);
    } else {
        vd_add(r, CAT, "Stringhe BIOS", M_BIOS, VDS_CLEAN, 0, "%s",
               bios[0] ? bios : "nessuna stringa");
    }

    if (si.uuid_ok) {
        int placeholder = uuid_is_placeholder(si.uuid_raw);
        int vmware_style = (si.uuid_raw[0] == 0x56 && si.uuid_raw[1] == 0x4D);
        if (placeholder || vmware_style) {
            vd_add(r, CAT, "UUID di sistema sintetico", M_UUID, VDS_DETECTED, 8,
                   "%s (%s)", si.uuid,
                   vmware_style ? "formato VMware" : "tutti 0x00/0xFF");
            if (vmware_style) {
                vd_note_vendor(r, VD_VENDOR_VMWARE, 62);
            }
        } else {
            vd_add(r, CAT, "UUID di sistema", M_UUID, VDS_CLEAN, 0,
                   "%s (plausibile)", si.uuid);
        }
    }

    if (si.memory_found) {
        const char *mem_vendor = vd_vendor_from_text(si.memory);
        if (mem_vendor) {
            vd_add(r, CAT, "Moduli di memoria virtuali", M_MEMORY, VDS_DETECTED, 6,
                   "%s", si.memory);
            vd_note_vendor(r, mem_vendor, 55);
        } else if (g_verbose) {
            vd_add(r, CAT, "Moduli di memoria", M_MEMORY, VDS_INFO, 0,
                   "%s", si.memory);
        }
    }

    if (si.chassis_type == 1 || si.chassis_type == 2) {
        vd_add(r, CAT, "Tipo chassis SMBIOS", M_CHASSIS, VDS_INFO, 0,
               "%s (%u) - generico, comune anche su VM", chassis_name(si.chassis_type),
               si.chassis_type);
    } else if (si.chassis_type) {
        vd_add(r, CAT, "Tipo chassis SMBIOS", M_CHASSIS, VDS_INFO, 0,
               "%s (%u)", chassis_name(si.chassis_type), si.chassis_type);
    }

    if (g_verbose) {
        vd_add(r, CAT, "Dettaglio SMBIOS", M_SMBIOS_RAW, VDS_INFO, 0,
               "BIOS: %s %s %s | Sistema: %s %s | Seriale: %s | SKU: %s | "
               "Board: %s %s | Chassis: %s",
               si.bios_vendor, si.bios_version, si.bios_date,
               si.sys_man, si.sys_prod, si.sys_serial, si.sys_sku,
               si.board_man, si.board_prod, si.chassis_man);
    }
}

/* Inventario ACPI: EnumSystemFirmwareTables funziona anche quando 'FIRM' e'
   bloccata (BIOS legacy) e permette almeno di contare le tabelle esposte. */
static void check_acpi_inventory(VdReport *r)
{
    DWORD bytes = EnumSystemFirmwareTables(VD_ACPI, NULL, 0);
    if (bytes < 4) {
        vd_add(r, CAT, "Inventario tabelle ACPI", M_ACPI_LIST, VDS_SKIP, 0,
               "EnumSystemFirmwareTables('ACPI') non disponibile");
        return;
    }

    BYTE *buf = (BYTE *)malloc(bytes);
    if (!buf) {
        vd_add(r, CAT, "Inventario tabelle ACPI", M_ACPI_LIST, VDS_SKIP, 0,
               "memoria insufficiente");
        return;
    }
    DWORD got = EnumSystemFirmwareTables(VD_ACPI, (PCHAR)buf, bytes);
    if (got < 4) {
        free(buf);
        vd_add(r, CAT, "Inventario tabelle ACPI", M_ACPI_LIST, VDS_SKIP, 0,
               "elenco delle tabelle ACPI non leggibile");
        return;
    }

    unsigned count = got / 4;
    char list[192] = "";
    unsigned shown = 0;
    for (unsigned i = 0; i < count && shown < 8; ++i) {
        char sig[5];
        sig[0] = (char)buf[i * 4 + 0];
        sig[1] = (char)buf[i * 4 + 1];
        sig[2] = (char)buf[i * 4 + 2];
        sig[3] = (char)buf[i * 4 + 3];
        sig[4] = '\0';
        int printable = 1;
        for (int k = 0; k < 4; ++k) {
            if (sig[k] < 32 || sig[k] > 126) printable = 0;
        }
        if (!printable) {
            continue;
        }
        app(list, sizeof(list), "%s ", sig);
        ++shown;
    }
    free(buf);

    if (count < 8) {
        vd_add(r, CAT, "Inventario ACPI ridotto", M_ACPI_LIST, VDS_DETECTED, 5,
               "solo %u tabelle ACPI visibili (%s): inventario tipico di un "
               "firmware virtuale", count, list);
    } else {
        vd_add(r, CAT, "Inventario tabelle ACPI", M_ACPI_LIST, VDS_INFO, 0,
               "%u tabelle visibili: %s", count, list);
    }
}

/* Metodo 9b: dati ACPI secondari, usati come fallback quando 'FIRM' non e'
   leggibile. Solo diagnostica: nessun peso, perche' MSDM manca sui PC
   assemblati, le thermal zone mancano sui desktop e PNP0C14 manca su alcuni
   firmware minimali anche fisici. */
static int acpi_table_signature(const BYTE *buf, DWORD count, const char *sig)
{
    for (DWORD i = 0; i < count; ++i) {
        if (memcmp(buf + i * 4, sig, 4) == 0) {
            return 1;
        }
    }
    return 0;
}

static void check_acpi_secondary(VdReport *r)
{
    int tables_ok = 0;
    int msdm = 0;

    DWORD bytes = EnumSystemFirmwareTables(VD_ACPI, NULL, 0);
    if (bytes >= 4) {
        BYTE *buf = (BYTE *)malloc(bytes);
        if (buf) {
            DWORD got = EnumSystemFirmwareTables(VD_ACPI, (PCHAR)buf, bytes);
            if (got >= 4) {
                tables_ok = 1;
                msdm = acpi_table_signature(buf, got / 4, "MSDM");
            }
            free(buf);
        }
    }

    int reg_ok = 0, thermal = 0, wmi = 0;
    HKEY key = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Enum\\ACPI", 0,
                      KEY_READ, &key) == ERROR_SUCCESS) {
        reg_ok = 1;
        for (DWORD i = 0; i < 512; ++i) {
            wchar_t name[256];
            DWORD name_len = (DWORD)(sizeof(name) / sizeof(name[0]));
            if (RegEnumKeyExW(key, i, name, &name_len, NULL, NULL, NULL,
                              NULL) != ERROR_SUCCESS) {
                break;
            }
            char utf8[256];
            vd_utf16_to_utf8(name, utf8, sizeof(utf8));
            if (vd_ci_contains(utf8, "pnp0c0a") ||
                vd_ci_contains(utf8, "pnp0c0b")) {
                thermal = 1;
            }
            if (vd_ci_contains(utf8, "pnp0c14")) {
                wmi = 1;
            }
        }
        RegCloseKey(key);
    }

    if (!tables_ok && !reg_ok) {
        vd_add(r, CAT, "Dati ACPI secondari", M_ACPI_EXTRA, VDS_SKIP, 0,
               "ne' le tabelle ACPI ne' Enum\\ACPI sono accessibili");
        return;
    }

    vd_add(r, CAT, "Dati ACPI secondari", M_ACPI_EXTRA, VDS_INFO, 0,
           "MSDM %s; thermal zone %s; PNP0C14 %s (assenza non conteggiata: "
           "normale su desktop e PC assemblati)",
           tables_ok ? (msdm ? "presente" : "assente") : "non verificabile",
           reg_ok ? (thermal ? "presenti" : "assenti") : "non verificabili",
           reg_ok ? (wmi ? "presente" : "assente") : "non verificabile");
}

/* Metodo 9a: tabella ACPI FADT letta dal firmware.
   Layout: OEMID a offset 10 (6 byte), OEM Table ID a 16 (8 byte),
   creator ID a 28 (4 byte). */
static void check_acpi_fadt(VdReport *r)
{
    DWORD needed = GetSystemFirmwareTable(VD_FIRM, 0, NULL, 0);
    if (needed < 36) {
        vd_add(r, CAT, "Tabelle ACPI (FADT)", M_FADT, VDS_INFO, 0,
               "GetSystemFirmwareTable('FIRM') non disponibile: FADT non letto "
               "dal firmware. Fallback: chiavi HKLM\\HARDWARE\\ACPI. La "
               "scansione EBDA/F-segment richiede un driver kernel e non e' "
               "possibile da utente standard, quindi questo dato resta "
               "parziale (non e' una prova di PC fisico)");
        return;
    }

    BYTE *buf = (BYTE *)malloc(needed);
    if (!buf) {
        vd_add(r, CAT, "Tabelle ACPI (FADT)", M_FADT, VDS_SKIP, 0,
               "memoria insufficiente");
        return;
    }
    DWORD got = GetSystemFirmwareTable(VD_FIRM, 0, buf, needed);
    if (got < 36) {
        free(buf);
        vd_add(r, CAT, "Tabelle ACPI (FADT)", M_FADT, VDS_INFO, 0,
               "tabella FADT non leggibile dal firmware; uso il fallback nel "
               "registro HKLM\\HARDWARE\\ACPI");
        return;
    }

    char oem_id[7], table_id[9], creator[5];
    memcpy(oem_id, buf + 10, 6);
    oem_id[6] = '\0';
    memcpy(table_id, buf + 16, 8);
    table_id[8] = '\0';
    memcpy(creator, buf + 28, 4);
    creator[4] = '\0';
    free(buf);

    trim_spaces(oem_id);
    trim_spaces(table_id);
    trim_spaces(creator);

    char text[128];
    snprintf(text, sizeof(text), "%s | %s | %s", oem_id, table_id, creator);

    const char *vendor = vd_vendor_from_text(text);
    if (vendor) {
        vd_add(r, CAT, "OEM ID delle tabelle ACPI", M_FADT, VDS_DETECTED, 20,
               "FADT: OEMID=\"%s\", OEM Table ID=\"%s\", creator=\"%s\"",
               oem_id, table_id, creator);
        vd_note_vendor(r, vendor, 70);
    } else {
        vd_add(r, CAT, "OEM ID delle tabelle ACPI", M_FADT, VDS_CLEAN, 0,
               "FADT: OEMID=\"%s\", table=\"%s\", creator=\"%s\"",
               oem_id, table_id, creator);
    }
}

/* Metodo 9b: gli stessi OEM ID, ma letti dal registro dove Windows li copia
   (HKLM\HARDWARE\ACPI\...). Utile se GetSystemFirmwareTable e' bloccata. */
static void check_acpi_registry(VdReport *r)
{
    static const wchar_t *roots[] = {
        L"HARDWARE\\ACPI\\DSDT",
        L"HARDWARE\\ACPI\\FADT",
        L"HARDWARE\\ACPI\\FACP",
        L"HARDWARE\\ACPI\\RSDT",
        L"HARDWARE\\ACPI\\XSDT",
    };

    char matches[512] = "";
    int found = 0;

    for (size_t k = 0; k < sizeof(roots) / sizeof(roots[0]); ++k) {
        HKEY key = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, roots[k], 0, KEY_READ, &key) != ERROR_SUCCESS) {
            continue;
        }
        wchar_t name[256];
        for (DWORD i = 0; i < 64; ++i) {
            DWORD name_len = (DWORD)(sizeof(name) / sizeof(name[0]));
            if (RegEnumKeyExW(key, i, name, &name_len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
                break;
            }
            char utf8[256];
            vd_utf16_to_utf8(name, utf8, sizeof(utf8));
            if (vd_vendor_from_text(utf8) ||
                vd_ci_contains(utf8, "vbox") || vd_ci_contains(utf8, "qemu") ||
                vd_ci_contains(utf8, "bochs") || vd_ci_contains(utf8, "bhyve")) {
                app(matches, sizeof(matches), "%s ", utf8);
                found = 1;
            }
        }
        RegCloseKey(key);
    }

    if (found) {
        const char *vendor = vd_vendor_from_text(matches);
        vd_add(r, CAT, "OEM ID ACPI nel registro", M_ACPI_REG, VDS_DETECTED, 15,
               "chiavi HKLM\\HARDWARE\\ACPI: %s", matches);
        if (vendor) {
            vd_note_vendor(r, vendor, 68);
        }
    } else {
        vd_add(r, CAT, "OEM ID ACPI nel registro", M_ACPI_REG, VDS_CLEAN, 0,
               "nessun OEM ID di virtualizzazione in HKLM\\HARDWARE\\ACPI");
    }
}

/* Con -v elenca anche i singoli valori letti, per capire cosa vede Windows. */
static void check_registry_bios(VdReport *r)
{
    static const struct {
        const wchar_t *value;
    } values[] = {
        { L"SystemManufacturer" }, { L"SystemProductName" }, { L"SystemVersion" },
        { L"BaseBoardManufacturer" }, { L"BaseBoardProduct" },
        { L"BIOSVendor" }, { L"BIOSVersion" }, { L"SystemBiosVersion" },
        { L"BIOSReleaseDate" }, { L"VideoBiosVersion" },
    };

    const wchar_t *path = L"HARDWARE\\DESCRIPTION\\System\\BIOS";
    char text[1024] = "";
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        char value[256];
        if (vd_reg_read_sz(HKEY_LOCAL_MACHINE, path, values[i].value, value, sizeof(value))) {
            app(text, sizeof(text), "%s | ", value);
            if (g_verbose) {
                char name[64];
                vd_utf16_to_utf8(values[i].value, name, sizeof(name));
                vd_add(r, CAT, name, M_BIOS_RAW, VDS_INFO, 0, "%s", value);
            }
        }
    }

    const char *vendor = vd_vendor_from_text(text);
    if (!vendor && (vd_ci_contains(text, "seabios") || vd_ci_contains(text, "ovmf"))) {
        vendor = VD_VENDOR_QEMU;
    }

    if (vendor) {
        vd_add(r, CAT, "Stringhe BIOS nel registro", M_BIOS_REG, VDS_DETECTED, 20,
               "%s", text);
        vd_note_vendor(r, vendor, 72);
    } else {
        vd_add(r, CAT, "Stringhe BIOS nel registro", M_BIOS_REG, VDS_CLEAN, 0, "%s",
               text[0] ? text : "chiave assente o vuota");
    }
}

/* Metodo 5b: copia di produttore/modello che Windows usa per il modello del
   sistema (mostrata anche in Impostazioni > Sistema > Informazioni). */
static void check_system_information(VdReport *r)
{
    const wchar_t *path = L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation";
    char man[256], prod[256];
    int ok_man = vd_reg_read_sz(HKEY_LOCAL_MACHINE, path, L"SystemManufacturer",
                                man, sizeof(man));
    int ok_prod = vd_reg_read_sz(HKEY_LOCAL_MACHINE, path, L"SystemProductName",
                                 prod, sizeof(prod));
    if (!ok_man && !ok_prod) {
        vd_add(r, CAT, "SystemInformation di Windows", M_SYSINFO, VDS_SKIP, 0,
               "chiave SYSTEM\\CurrentControlSet\\Control\\SystemInformation assente");
        return;
    }

    char text[640];
    snprintf(text, sizeof(text), "%.250s | %.250s", ok_man ? man : "", ok_prod ? prod : "");
    const char *vendor = vd_vendor_from_text(text);
    if (vendor) {
        vd_add(r, CAT, "SystemInformation di Windows", M_SYSINFO, VDS_DETECTED, 10,
               "%s %s", ok_man ? man : "?", ok_prod ? prod : "?");
        vd_note_vendor(r, vendor, 66);
    } else {
        vd_add(r, CAT, "SystemInformation di Windows", M_SYSINFO, VDS_CLEAN, 0,
               "%s %s", ok_man ? man : "?", ok_prod ? prod : "?");
    }
}

void checks_firmware(VdReport *r)
{
    check_smbios(r);
    check_acpi_inventory(r);
    check_acpi_secondary(r);
    check_acpi_fadt(r);
    check_acpi_registry(r);
    check_registry_bios(r);
    check_system_information(r);
}

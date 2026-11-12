/* ===========================================================================
   CONTROLLI CHE RICHIEDONO I PRIVILEGI DI AMMINISTRATORE
   ===========================================================================

   Perche' un blocco separato
   --------------------------
   I controlli di questo file usano IOCTL che Windows concede solo a un
   processo elevato (token con TokenElevation diverso da zero). Il resto del
   programma non chiede privilegi: se VirtDetect parte da un utente normale
   questo blocco produce una sola riga [--] e non tocca il disco.

   Metodi implementati in questo file
   ----------------------------------
   M) Elevazione del processo.
      OpenProcessToken + GetTokenInformation(TokenElevation): senza
      privilegi il blocco ATA non viene nemmeno tentato.

   N) ATA IDENTIFY DEVICE.
      Apre \\\\.\\PhysicalDriveN in lettura/scrittura e invia il comando
      ATA IDENTIFY DEVICE (0xEC) con IOCTL_ATA_PASS_THROUGH. La risposta di
      512 byte contiene il modello (word 27-46), il seriale (10-19), il
      firmware (23-26), la velocita' di rotazione (word 217) e i flag NCQ
      (word 76 bit 8) e TRIM (word 169 bit 0).

      Perche' serve: IOCTL_STORAGE_QUERY_PROPERTY legge la descrizione che
      il driver espone a Windows, mentre IDENTIFY arriva dal dispositivo
      emulato. Un hypervisor che falsifica la prima puo' lasciare la
      seconda con i propri valori.

   O) Coerenza tra i due livelli.
      Se solo uno tra descrizione Windows e IDENTIFY dichiara un disco
      virtuale, uno dei due livelli e' stato falsificato: combinazione
      impossibile su un PC fisico (canale delle incoerenze, peso 30).

   P) Modello SSD/NVMe contro dati reali.
      - Il nome del disco dichiara SSD ma IDENTIFY riporta una rotazione
        >= 1000 RPM (word 217): il modello e' falso, peso 20.
      - Il nome contiene "NVMe" ma il bus e' ATA/SATA/SCSI/RAID: NVMe usa
        PCI Express e non puo' comparire su questi bus, peso 20. I dischi
        USB sono esclusi per non segnalare box esterni che riportano nomi
        di unita' NVMe.

   Limiti dichiarati
   -----------------
   - IDENTIFY esiste solo per dischi ATA/SATA. NVMe, RAID hardware, USB e
     dischi virtuali VHD non vengono interrogati (riga [--] con il bus).
   - Un hypervisor che falsifica anche IDENTIFY (modello e seriale
     credibili, rotazione coerente) non viene smascherato da questo blocco:
     il confronto e' tra due livelli, non con il dispositivo fisico.
   - Non serve un driver kernel: IDENTIFY passa dallo stack ATA di Windows.
     Letture dirette di MSR, spazio di configurazione PCI o memoria EBDA
     richiederebbero un driver, non solo l'elevazione.
   =========================================================================== */

#include "checks.h"

#include <winioctl.h>
#include <ntddscsi.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define CAT "Controlli privilegiati"

/* Valori di STORAGE_BUS_TYPE usati nei confronti (l'enum del SDK puo'
   cambiare nome tra versioni, i valori no). */
#define VD_BUS_ATA          3
#define VD_BUS_USB          7
#define VD_BUS_RAID         8
#define VD_BUS_SATA         11
#define VD_BUS_VIRTUAL      14
#define VD_BUS_FILEBACKED   15
#define VD_BUS_NVME         17

#ifndef IOCTL_ATA_PASS_THROUGH
#define IOCTL_ATA_PASS_THROUGH \
    CTL_CODE(IOCTL_SCSI_BASE, 0x040b, METHOD_BUFFERED, \
             FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#endif

#ifndef ATA_FLAGS_DRDY_REQUIRED
#define ATA_FLAGS_DRDY_REQUIRED 0x01
#endif
#ifndef ATA_FLAGS_DATA_IN
#define ATA_FLAGS_DATA_IN 0x02
#endif

static const char *const M_ELEV =
    "Legge il token del processo con GetTokenInformation(TokenElevation): "
    "senza privilegi elevati Windows nega l'apertura in scrittura di "
    "\\\\.\\PhysicalDriveN necessaria ai comandi ATA.";

static const char *const M_ATA =
    "Invia ATA IDENTIFY DEVICE (0xEC) con IOCTL_ATA_PASS_THROUGH e legge "
    "modello (word 27-46), seriale (10-19), firmware (23-26), rotazione "
    "(217), NCQ (76 bit 8) e TRIM (169 bit 0).";

static const char *const M_LAYER =
    "Confronta il modello letto a livello ATA con quello che Windows mostra "
    "nello storage descriptor: se solo uno dei due dichiara un disco "
    "virtuale, uno dei due livelli e' stato falsificato.";

static const char *const M_ROT =
    "Word 217 di IDENTIFY: 1 = disco a stato solido, da 0x0401 in su = "
    "velocita' in RPM. Un nome che dichiara SSD ma una rotazione reale "
    "e' una combinazione impossibile.";

static const char *const M_NVME =
    "Un modello che contiene 'NVMe' su un bus ATA/SATA/SCSI/RAID e' "
    "impossibile: NVMe usa un bus PCI Express dedicato. I dischi USB sono "
    "esclusi per non segnalare box esterni.";

static void appendf(char *dst, size_t cap, const char *fmt, ...)
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

static void trim_right(char *s)
{
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t')) {
        s[--len] = '\0';
    }
}

/* --------------------------------------------------------- token */

/* Metodo M. */
static int process_is_elevated(void)
{
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return 0;
    }
    TOKEN_ELEVATION elevation;
    DWORD returned = 0;
    int elevated = 0;
    if (GetTokenInformation(token, TokenElevation, &elevation,
                            sizeof(elevation), &returned)) {
        elevated = elevation.TokenIsElevated != 0;
    }
    CloseHandle(token);
    return elevated;
}

/* -------------------------------------------------- disco e ATA */

typedef struct {
    HANDLE handle;
    int exists;
    int writable;
    DWORD error;
} VdDiskOpen;

static VdDiskOpen open_physical_drive(int index)
{
    VdDiskOpen out;
    memset(&out, 0, sizeof(out));
    out.handle = INVALID_HANDLE_VALUE;

    wchar_t path[64];
    swprintf(path, sizeof(path) / sizeof(path[0]),
             L"\\\\.\\PhysicalDrive%d", index);

    HANDLE h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        out.handle = h;
        out.exists = 1;
        out.writable = 1;
        return out;
    }

    DWORD err = GetLastError();
    if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND ||
        err == ERROR_INVALID_PARAMETER) {
        out.error = err;
        return out;
    }

    out.exists = 1;
    h = CreateFileW(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        out.handle = h;
        out.error = err;
        return out;
    }
    out.error = GetLastError();
    return out;
}

static const char *bus_name(STORAGE_BUS_TYPE type)
{
    switch ((int)type) {
    case 0:  return "sconosciuto";
    case 1:  return "SCSI";
    case 2:  return "ATAPI";
    case VD_BUS_ATA:        return "ATA";
    case 4:  return "IEEE 1394";
    case 5:  return "SSA";
    case 6:  return "Fibre Channel";
    case VD_BUS_USB:        return "USB";
    case VD_BUS_RAID:       return "RAID";
    case 9:  return "iSCSI";
    case 10: return "SAS";
    case VD_BUS_SATA:       return "SATA";
    case 12: return "SD";
    case 13: return "MMC";
    case VD_BUS_VIRTUAL:    return "Virtual";
    case VD_BUS_FILEBACKED: return "FileBackedVirtual";
    case 16: return "Spaces";
    case VD_BUS_NVME:       return "NVMe";
    case 18: return "SCM";
    case 19: return "UFS";
    default: return "sconosciuto";
    }
}

static const char *storage_string(const BYTE *base, DWORD offset)
{
    return offset ? (const char *)(base + offset) : "";
}

/* Word little-endian del settore IDENTIFY. */
static unsigned identify_word(const unsigned char *id, int word)
{
    return (unsigned)id[word * 2] | ((unsigned)id[word * 2 + 1] << 8);
}

/* Le stringhe IDENTIFY hanno i due byte di ogni word invertiti e sono
   riempite con spazi. Si scartano i byte non stampabili. */
static void copy_identify_string(const unsigned char *id, int first_word,
                                 int last_word, char *out, size_t cap)
{
    char raw[80];
    size_t n = 0;
    for (int w = first_word; w <= last_word && n + 2 < sizeof(raw); ++w) {
        unsigned char hi = id[w * 2 + 1];
        unsigned char lo = id[w * 2];
        raw[n++] = (hi >= 0x20 && hi < 0x7f) ? (char)hi : ' ';
        raw[n++] = (lo >= 0x20 && lo < 0x7f) ? (char)lo : ' ';
    }
    while (n > 0 && raw[n - 1] == ' ') {
        --n;
    }
    size_t start = 0;
    while (start < n && raw[start] == ' ') {
        ++start;
    }
    size_t len = n - start;
    if (len >= cap) {
        len = cap - 1;
    }
    memcpy(out, raw + start, len);
    out[len] = '\0';
}

/* Parser separato dalla chiamata IOCTL: cosi' e' verificabile con un
   settore sintetico senza un disco vero. */
void vd_ata_parse_identify(const unsigned char *sector, VdAtaIdentify *out)
{
    memset(out, 0, sizeof(*out));

    unsigned config = identify_word(sector, 0);
    if (config & 0x8000u) {
        return;  /* ATAPI: risponde a PACKET IDENTIFY, non a IDENTIFY DEVICE */
    }

    copy_identify_string(sector, 10, 19, out->serial, sizeof(out->serial));
    copy_identify_string(sector, 23, 26, out->firmware, sizeof(out->firmware));
    copy_identify_string(sector, 27, 46, out->model, sizeof(out->model));
    if (strlen(out->model) < 2) {
        return;  /* risposta vuota o non decodificabile */
    }

    unsigned rotation = identify_word(sector, 217);
    if (rotation == 1) {
        out->rotation = 1;
    } else if (rotation >= 0x0401 && rotation <= 0xfffe) {
        out->rotation = (int)rotation;
    }

    out->ncq = (identify_word(sector, 76) & 0x0100u) != 0;
    out->trim = (identify_word(sector, 169) & 0x0001u) != 0;
    out->valid = 1;
}

static int ata_identify_handle(HANDLE disk, unsigned char *sector)
{
    /* Due tentativi: alcuni driver accettano solo la variante senza
       ATA_FLAGS_DRDY_REQUIRED. */
    for (int attempt = 0; attempt < 2; ++attempt) {
        struct {
            ATA_PASS_THROUGH_EX apt;
            unsigned char data[512];
        } buf;

        memset(&buf, 0, sizeof(buf));
        buf.apt.Length = (USHORT)sizeof(ATA_PASS_THROUGH_EX);
        buf.apt.AtaFlags = (USHORT)(ATA_FLAGS_DATA_IN |
            (attempt == 0 ? ATA_FLAGS_DRDY_REQUIRED : 0));
        buf.apt.DataTransferLength = 512;
        buf.apt.TimeOutValue = 5;
        buf.apt.DataBufferOffset = (ULONG_PTR)sizeof(ATA_PASS_THROUGH_EX);
        buf.apt.CurrentTaskFile[6] = 0xEC;  /* IDENTIFY DEVICE */

        DWORD returned = 0;
        if (DeviceIoControl(disk, IOCTL_ATA_PASS_THROUGH,
                            &buf, sizeof(buf), &buf, sizeof(buf),
                            &returned, NULL)) {
            memcpy(sector, buf.data, 512);
            return 1;
        }
    }
    return 0;
}

/* -------------------------------------------------------- scansione */

typedef struct {
    int disks;
    int ata_ok;
    char ata_detail[VD_EVIDENCE_MAX];
    char virtual_hits[VD_EVIDENCE_MAX];
    int virtual_count;
    char mismatch_hits[VD_EVIDENCE_MAX];
    int mismatch_count;
    char rotation_hits[VD_EVIDENCE_MAX];
    int rotation_count;
    char nvme_hits[VD_EVIDENCE_MAX];
    int nvme_count;
    char problems[VD_EVIDENCE_MAX];
    int problems_count;
} VdPrivScan;

static const char *rotation_text(int rotation, char *buf, size_t cap)
{
    if (rotation == 1) {
        return "SSD (non rotante)";
    }
    if (rotation >= 1000) {
        snprintf(buf, cap, "%d RPM", rotation);
        return buf;
    }
    return "non riportata";
}

static int text_claims_ssd(const char *text)
{
    return vd_ci_contains(text, "ssd") ||
           vd_ci_contains(text, "solid state");
}

static const char *disk_vendor_from_text(const char *text)
{
    const char *vendor = vd_vendor_from_text(text);
    if (!vendor) {
        if (vd_ci_contains(text, "virtual hd") ||
            vd_ci_contains(text, "virtual disk") ||
            vd_ci_contains(text, "msft virtual")) {
            vendor = VD_VENDOR_HYPERV;
        }
    }
    return vendor;
}

/* Ritorna -1 se il numero di disco non esiste, 0 se e' stato esaminato
   (anche solo per registrare un problema). */
static int scan_privileged_disk(VdReport *r, int index, VdPrivScan *s)
{
    VdDiskOpen disk = open_physical_drive(index);
    if (!disk.exists) {
        return -1;
    }
    ++s->disks;

    if (disk.handle == INVALID_HANDLE_VALUE) {
        appendf(s->problems, sizeof(s->problems),
                "PhysicalDrive%d non apribile (errore %lu); ",
                index, (unsigned long)disk.error);
        ++s->problems_count;
        return 0;
    }

    STORAGE_PROPERTY_QUERY query;
    memset(&query, 0, sizeof(query));
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;

    BYTE buffer[1024];
    DWORD returned = 0;
    if (!DeviceIoControl(disk.handle, IOCTL_STORAGE_QUERY_PROPERTY,
                         &query, sizeof(query), buffer, sizeof(buffer),
                         &returned, NULL)) {
        appendf(s->problems, sizeof(s->problems),
                "PhysicalDrive%d: descrizione non disponibile (errore %lu); ",
                index, (unsigned long)GetLastError());
        ++s->problems_count;
        CloseHandle(disk.handle);
        return 0;
    }

    STORAGE_DEVICE_DESCRIPTOR *desc = (STORAGE_DEVICE_DESCRIPTOR *)buffer;
    char vendor[64];
    char product[128];
    char serial[96];
    snprintf(vendor, sizeof(vendor), "%s",
             storage_string(buffer, desc->VendorIdOffset));
    snprintf(product, sizeof(product), "%s",
             storage_string(buffer, desc->ProductIdOffset));
    snprintf(serial, sizeof(serial), "%s",
             storage_string(buffer, desc->SerialNumberOffset));
    trim_right(vendor);
    trim_right(product);
    trim_right(serial);

    int bus = (int)desc->BusType;

    /* Testo che Windows mostra per il disco: si esclude il seriale dalla
       ricerca del vendor per non confondere un seriale che contiene per
       caso "xen" o "kvm" con il nome di un hypervisor. */
    char win_text[256];
    snprintf(win_text, sizeof(win_text), "%s %s", vendor, product);
    const char *win_vendor = disk_vendor_from_text(win_text);

    /* Modello che dichiara NVMe su un bus che non e' PCI Express. Solo
       bus interni: un box USB con dentro un'unita' NVMe e' legittimo. */
    if (vd_ci_contains(product, "nvme") &&
        (bus == VD_BUS_ATA || bus == VD_BUS_SATA ||
         bus == 1 || bus == VD_BUS_RAID)) {
        appendf(s->nvme_hits, sizeof(s->nvme_hits),
                "PhysicalDrive%d: \"%s\" su bus %s; ", index, product,
                bus_name(desc->BusType));
        ++s->nvme_count;
    }

    if (bus == VD_BUS_ATA || bus == VD_BUS_SATA) {
        if (!disk.writable) {
            appendf(s->problems, sizeof(s->problems),
                    "PhysicalDrive%d: handle in sola lettura, IDENTIFY non "
                    "inviabile (errore %lu); ",
                    index, (unsigned long)disk.error);
            ++s->problems_count;
        } else {
            unsigned char sector[512];
            if (ata_identify_handle(disk.handle, sector)) {
                VdAtaIdentify id;
                vd_ata_parse_identify(sector, &id);
                if (!id.valid) {
                    appendf(s->problems, sizeof(s->problems),
                            "PhysicalDrive%d: risposta IDENTIFY non valida; ",
                            index);
                    ++s->problems_count;
                } else {
                    char rot_buf[32];
                    const char *rot = rotation_text(id.rotation, rot_buf,
                                                   sizeof(rot_buf));
                    ++s->ata_ok;

                    appendf(s->ata_detail, sizeof(s->ata_detail),
                            "PhysicalDrive%d: \"%s\" S/N \"%s\" fw \"%s\", "
                            "rotazione %s, NCQ %s, TRIM %s; ",
                            index, id.model, id.serial, id.firmware, rot,
                            id.ncq ? "si" : "no", id.trim ? "si" : "no");

                    const char *ata_vendor = disk_vendor_from_text(id.model);
                    if (ata_vendor) {
                        appendf(s->virtual_hits, sizeof(s->virtual_hits),
                                "PhysicalDrive%d: IDENTIFY riporta \"%s\"; ",
                                index, id.model);
                        ++s->virtual_count;
                        vd_note_vendor(r, ata_vendor, 66);
                    }

                    if ((ata_vendor != NULL) != (win_vendor != NULL)) {
                        appendf(s->mismatch_hits, sizeof(s->mismatch_hits),
                                "PhysicalDrive%d: Windows \"%s\" / ATA \"%s\"; ",
                                index, win_text[0] ? win_text : "?",
                                id.model);
                        ++s->mismatch_count;
                    }

                    if (text_claims_ssd(product) && id.rotation >= 1000) {
                        appendf(s->rotation_hits, sizeof(s->rotation_hits),
                                "PhysicalDrive%d: \"%s\" ma IDENTIFY riporta "
                                "%d RPM; ", index, product, id.rotation);
                        ++s->rotation_count;
                    }
                }
            } else {
                appendf(s->problems, sizeof(s->problems),
                        "PhysicalDrive%d: IDENTIFY rifiutato dal driver "
                        "(errore %lu); ",
                        index, (unsigned long)GetLastError());
                ++s->problems_count;
            }
        }
    } else {
        appendf(s->problems, sizeof(s->problems),
                "PhysicalDrive%d: bus %s, IDENTIFY ATA non applicabile; ",
                index, bus_name(desc->BusType));
        ++s->problems_count;
    }

    CloseHandle(disk.handle);
    return 0;
}

/* I risultati sono aggregati per tipo: un PC con piu' dischi virtuali non
   moltiplica il peso dello stesso indizio. */
static void report_privileged_scan(VdReport *r, const VdPrivScan *s)
{
    if (s->virtual_count) {
        vd_add(r, CAT, "Disco virtuale al livello ATA", M_ATA,
               VDS_DETECTED, 25, "%s", s->virtual_hits);
    }
    if (s->mismatch_count) {
        vd_add_contradiction(r, CAT, "Livelli disco incoerenti", M_LAYER,
                             30, "%s", s->mismatch_hits);
    }
    if (s->rotation_count) {
        vd_add_contradiction(r, CAT, "SSD dichiarato ma disco rotante", M_ROT,
                             20, "%s", s->rotation_hits);
    }
    if (s->nvme_count) {
        vd_add_contradiction(r, CAT, "NVMe su bus non NVMe", M_NVME,
                             20, "%s", s->nvme_hits);
    }

    if (s->ata_ok) {
        vd_add(r, CAT, "Dati IDENTIFY dei dischi", M_ATA, VDS_INFO, 0,
               "%s", s->ata_detail);
        if (!s->virtual_count && !s->mismatch_count &&
            !s->rotation_count && !s->nvme_count) {
            vd_add(r, CAT, "Coerenza dei dischi ATA", M_ATA, VDS_CLEAN, 0,
                   "%d disco/i interrogati: modello, seriale e rotazione "
                   "coerenti con la descrizione Windows", s->ata_ok);
        }
    }

    if (s->problems_count) {
        vd_add(r, CAT, "Dischi non interrogabili con IDENTIFY", M_ATA,
               VDS_SKIP, 0, "%s", s->problems);
    }
}

void checks_privileged(VdReport *r)
{
    if (!process_is_elevated()) {
        vd_add(r, CAT, "Controlli ATA (amministratore)", M_ELEV,
               VDS_SKIP, 0,
               "processo non elevato: Windows non consente l'apertura in "
               "scrittura di \\\\.\\PhysicalDriveN. Avviare VirtDetect come "
               "amministratore per eseguire ATA IDENTIFY");
        return;
    }

    VdPrivScan scan;
    memset(&scan, 0, sizeof(scan));

    int misses = 0;
    for (int index = 0; index < 32 && misses < 6; ++index) {
        int rc = scan_privileged_disk(r, index, &scan);
        if (rc < 0) {
            ++misses;
        } else {
            misses = 0;
        }
    }

    if (!scan.disks) {
        vd_add(r, CAT, "Dischi con privilegi", M_ATA, VDS_SKIP, 0,
               "nessun \\\\.\\PhysicalDriveN accessibile");
        return;
    }

    report_privileged_scan(r, &scan);
}

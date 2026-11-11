/* ===========================================================================
   RILEVAMENTO DAI DISPOSITIVI E DALLA RETE
   ===========================================================================

   L'hypervisor emula periferiche con nomi e identificatori propri. Questi
   controlli guardano l'hardware "visto" dal sistema operativo, quindi
   funzionano anche se il firmware e' stato falsificato.

   Metodi implementati in questo file
   ----------------------------------
   I) Modello dei dischi fisici.
      Apre \\\\.\\PhysicalDriveN e interroga la periferica con
      IOCTL_STORAGE_QUERY_PROPERTY, leggendo vendor, prodotto e seriale
      dichiarati dal controller. Le VM usano stringhe come
      "VMware Virtual disk", "VBOX HARDDISK", "QEMU HARDDISK",
      "Msft Virtual Disk" (Hyper-V). Peso 25.

   J) Schede di rete.
      Enumera gli adattatori con GetAdaptersAddresses e controlla due cose:
      - la descrizione ("VMware Virtual Ethernet Adapter", "VirtualBox
        Host-Only", "Red Hat VirtIO Ethernet Adapter"...);
      - i primi 3 byte del MAC (OUI): 00:05:69, 00:0C:29, 00:1C:14,
        00:50:56 VMware; 08:00:27 e 0A:00:27 VirtualBox; 52:54:00 QEMU;
        00:15:5D e 00:03:FF Hyper-V; 00:16:3E Xen; 00:1C:42 Parallels;
        00:0D:3A Azure.
      Gli adattatori host-only, vmnet, vEthernet e loopback sono esclusi:
      un PC con VMware/VirtualBox installati li possiede per definizione.
      Peso 10.

   K) Scheda video.
      Legge la classe display del registro ({4d36e968-...}) e confronta il
      DriverDesc con gli adattatori virtuali noti (VMware SVGA, VirtualBox
      Graphics, QXL, Cirrus Logic, Microsoft Basic Display). Peso 20, ma
      "Basic Display" da solo e' solo informativo: compare anche su un PC
      senza driver video installati.

   L) Batteria.
      Solo informativo: l'assenza di batteria e' normale sia su un desktop
      sia su una VM.
   =========================================================================== */

#include "checks.h"

#include <winsock2.h>
#include <iphlpapi.h>
#include <winioctl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#define CAT "Dispositivi e rete"

static const char *const M_SERIAL =
    "Controlla il formato del seriale letto via IOCTL_STORAGE_QUERY_PROPERTY: "
    "un seriale ATA/NVMe e' alfanumerico, mentre un percorso bus (es. "
    "1-0000:00:1d.7-1) e' un identificatore di QEMU/libvirt, non un seriale "
    "del disco fisico.";

/* Testi mostrati a schermo. */
static const char *const M_DISKS =
    "Apre ogni \\\\.\\PhysicalDriveN e legge vendor, modello e seriale con "
    "IOCTL_STORAGE_QUERY_PROPERTY: le VM usano nomi come 'VMware Virtual disk'.";
static const char *const M_NIC =
    "Elenca le NIC con GetAdaptersAddresses e confronta descrizione e prefisso "
    "MAC (OUI) con quelli di VMware, VirtualBox, QEMU, Hyper-V, Xen...";
static const char *const M_GPU =
    "Legge la classe display del registro e confronta il nome del driver video "
    "con gli adattatori virtuali (VMware SVGA, VirtualBox, QXL, Cirrus...).";
static const char *const M_POWER =
    "Legge lo stato della batteria con GetSystemPowerStatus (solo "
    "informativo).";

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

/* ----------------------------------------------------------- dischi */

static const char *storage_string(const BYTE *base, DWORD offset)
{
    return offset ? (const char *)(base + offset) : "";
}

/* Metodo I. Si fermano 6 aperture consecutive fallite, per non perdere
   tempo su numeri di disco inesistenti su macchine con molti volumi. */
static void check_physical_disks(VdReport *r)
{
    char evidence[1200] = "";
    char models[1200] = "";
    int opened = 0;
    int misses = 0;
    int serials = 0;
    int buspath_serials = 0;
    char buspath_example[256] = "";

    for (int index = 0; index < 32 && misses < 6; ++index) {
        wchar_t path[64];
        swprintf(path, sizeof(path) / sizeof(path[0]),
                 L"\\\\.\\PhysicalDrive%d", index);

        HANDLE disk = CreateFileW(path, 0,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                  OPEN_EXISTING, 0, NULL);
        if (disk == INVALID_HANDLE_VALUE) {
            ++misses;
            continue;
        }
        ++opened;
        misses = 0;

        STORAGE_PROPERTY_QUERY query;
        memset(&query, 0, sizeof(query));
        query.PropertyId = StorageDeviceProperty;
        query.QueryType = PropertyStandardQuery;

        BYTE buffer[1024];
        DWORD returned = 0;
        if (DeviceIoControl(disk, IOCTL_STORAGE_QUERY_PROPERTY,
                            &query, sizeof(query), buffer, sizeof(buffer),
                            &returned, NULL)) {
            STORAGE_DEVICE_DESCRIPTOR *desc = (STORAGE_DEVICE_DESCRIPTOR *)buffer;
            const char *vendor = storage_string(buffer, desc->VendorIdOffset);
            const char *product = storage_string(buffer, desc->ProductIdOffset);
            const char *serial = storage_string(buffer, desc->SerialNumberOffset);

            char line[384];
            snprintf(line, sizeof(line), "%s %s%s%s", vendor, product,
                     serial[0] ? " S/N " : "", serial);

            if (serial[0]) {
                ++serials;
                if (strchr(serial, ':')) {
                    ++buspath_serials;
                    if (!buspath_example[0]) {
                        snprintf(buspath_example, sizeof(buspath_example),
                                 "PhysicalDrive%d: \"%.180s\"", index, serial);
                    }
                }
            }

            const char *vm = vd_vendor_from_text(line);
            if (!vm && (vd_ci_contains(line, "virtual hd") ||
                        vd_ci_contains(line, "virtual disk") ||
                        vd_ci_contains(line, "msft virtual"))) {
                vm = VD_VENDOR_HYPERV;
            }

            if (vm) {
                appendf(evidence, sizeof(evidence), "PhysicalDrive%d: %s; ",
                        index, line);
                vd_note_vendor(r, vm, 61);
            } else if (g_verbose) {
                appendf(models, sizeof(models), "PhysicalDrive%d: %s; ",
                        index, line);
            }
        }
        CloseHandle(disk);
    }

    if (!opened) {
        vd_add(r, CAT, "Modello dei dischi fisici", M_DISKS, VDS_SKIP, 0,
               "accesso a \\\\.\\PhysicalDriveN negato");
        return;
    }

    if (evidence[0]) {
        vd_add(r, CAT, "Disco virtuale rilevato via IOCTL", M_DISKS,
               VDS_DETECTED, 25, "%s", evidence);
    } else {
        vd_add(r, CAT, "Modello dei dischi fisici", M_DISKS, VDS_CLEAN, 0,
               models[0] ? models : "nessun modello virtuale");
    }

    if (buspath_serials) {
        vd_add_contradiction(r, CAT, "Seriale disco a percorso bus", M_SERIAL,
                             20,
                             "%d disco/i con un seriale che e' un percorso bus: "
                             "%s. Un disco fisico espone un seriale del "
                             "produttore, non un indirizzo del bus",
                             buspath_serials, buspath_example);
    } else {
        vd_add(r, CAT, "Formato dei seriali disco", M_SERIAL, VDS_CLEAN, 0,
               "%d dischi con seriale, nessuno in formato percorso bus",
               serials);
    }
}

/* -------------------------------------------------------------- rete */

/* OUI (Organizationally Unique Identifier): i primi 24 bit del MAC
   identificano il costruttore. Questi sono quelli registrati dagli
   hypervisor. */
static const struct {
    const char *prefix;
    const char *vendor;
} oui_table[] = {
    { "00:05:69", VD_VENDOR_VMWARE },
    { "00:0C:29", VD_VENDOR_VMWARE },
    { "00:1C:14", VD_VENDOR_VMWARE },
    { "00:50:56", VD_VENDOR_VMWARE },
    { "08:00:27", VD_VENDOR_VBOX },
    { "0A:00:27", VD_VENDOR_VBOX },
    { "52:54:00", VD_VENDOR_QEMU },
    { "00:15:5D", VD_VENDOR_HYPERV },
    { "00:16:3E", VD_VENDOR_XEN },
    { "00:1C:42", VD_VENDOR_PARALLELS },
    { "00:03:FF", VD_VENDOR_HYPERV },
    { "00:0D:3A", VD_VENDOR_CLOUD },
};

static const char *oui_vendor(const BYTE *mac, ULONG len)
{
    if (len < 3) {
        return NULL;
    }
    char prefix[9];
    snprintf(prefix, sizeof(prefix), "%02X:%02X:%02X", mac[0], mac[1], mac[2]);
    for (size_t i = 0; i < sizeof(oui_table) / sizeof(oui_table[0]); ++i) {
        if (vd_ci_contains(prefix, oui_table[i].prefix)) {
            return oui_table[i].vendor;
        }
    }
    return NULL;
}

/* Adattatori che esistono solo perche' l'hypervisor e' installato
   sull'HOST: non sono prova che siamo dentro una VM. */
static int is_host_adapter(const char *text)
{
    return vd_ci_contains(text, "host-only") ||
           vd_ci_contains(text, "vmnet") ||
           vd_ci_contains(text, "virtual ethernet adapter") ||
           vd_ci_contains(text, "hyper-v virtual") ||
           vd_ci_contains(text, "loopback") ||
           vd_ci_contains(text, "pseudo-interface");
}

/* Metodo J. */
static void check_network_adapters(VdReport *r)
{
    ULONG size = 16384;
    IP_ADAPTER_ADDRESSES *addrs = NULL;
    ULONG rc = ERROR_BUFFER_OVERFLOW;

    for (int attempt = 0; attempt < 3 && rc == ERROR_BUFFER_OVERFLOW; ++attempt) {
        IP_ADAPTER_ADDRESSES *tmp =
            (IP_ADAPTER_ADDRESSES *)malloc(size);
        if (!tmp) {
            break;
        }
        addrs = tmp;
        rc = GetAdaptersAddresses(AF_UNSPEC,
                                  GAA_FLAG_SKIP_ANYCAST |
                                  GAA_FLAG_SKIP_MULTICAST |
                                  GAA_FLAG_SKIP_DNS_SERVER,
                                  NULL, addrs, &size);
        if (rc == ERROR_BUFFER_OVERFLOW) {
            free(addrs);
            addrs = NULL;
        }
    }

    if (rc != NO_ERROR || !addrs) {
        free(addrs);
        vd_add(r, CAT, "Schede di rete", M_NIC, VDS_SKIP, 0,
               "GetAdaptersAddresses non disponibile (errore %lu)", (unsigned long)rc);
        return;
    }

    char hits[1200] = "";
    const char *vendor = NULL;

    for (IP_ADAPTER_ADDRESSES *a = addrs; a; a = a->Next) {
        char desc[512];
        char friendly[256];
        vd_utf16_to_utf8(a->Description, desc, sizeof(desc));
        vd_utf16_to_utf8(a->FriendlyName, friendly, sizeof(friendly));

        char combined[1024];
        snprintf(combined, sizeof(combined), "%s | %s", desc, friendly);

        if (is_host_adapter(combined)) {
            continue;
        }

        char mac[32] = "";
        if (a->PhysicalAddressLength >= 6) {
            snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                     a->PhysicalAddress[0], a->PhysicalAddress[1],
                     a->PhysicalAddress[2], a->PhysicalAddress[3],
                     a->PhysicalAddress[4], a->PhysicalAddress[5]);
        }

        const char *desc_vendor = vd_vendor_from_text(combined);
        const char *mac_vendor = oui_vendor(a->PhysicalAddress,
                                            a->PhysicalAddressLength);
        if (desc_vendor || mac_vendor) {
            appendf(hits, sizeof(hits), "\"%s\" MAC %s%s%s; ",
                    desc[0] ? desc : friendly, mac[0] ? mac : "?",
                    desc_vendor ? " (nome virtuale)" : "",
                    mac_vendor ? " (OUI virtuale)" : "");
            if (!vendor) {
                vendor = desc_vendor ? desc_vendor : mac_vendor;
            }
        }
    }

    free(addrs);

    if (hits[0]) {
        vd_add(r, CAT, "Scheda di rete virtuale", M_NIC, VDS_DETECTED, 10,
               "%s", hits);
        if (vendor) {
            vd_note_vendor(r, vendor, 58);
        }
    } else {
        vd_add(r, CAT, "Schede di rete", M_NIC, VDS_CLEAN, 0,
               "descrizioni e MAC delle NIC non sono di virtualizzazione");
    }
}

/* --------------------------------------------------------------- GPU */

/* GUID della classe "Display" di Windows. */
static void check_display_adapters(VdReport *r)
{
    const wchar_t *class_path =
        L"SYSTEM\\CurrentControlSet\\Control\\Class\\"
        L"{4d36e968-e325-11ce-bfc1-08002be10318}";

    HKEY key = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, class_path, 0, KEY_READ, &key) != ERROR_SUCCESS) {
        vd_add(r, CAT, "Scheda video", M_GPU, VDS_SKIP, 0,
               "classe display non accessibile");
        return;
    }

    char hits[768] = "";
    char basic[256] = "";
    const char *vendor = NULL;

    for (DWORD i = 0; i < 64; ++i) {
        wchar_t name[128];
        DWORD name_len = (DWORD)(sizeof(name) / sizeof(name[0]));
        if (RegEnumKeyExW(key, i, name, &name_len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
            break;
        }
        wchar_t path[512];
        swprintf(path, sizeof(path) / sizeof(path[0]), L"%s\\%s", class_path, name);

        char desc[256];
        if (!vd_reg_read_sz(HKEY_LOCAL_MACHINE, path, L"DriverDesc", desc, sizeof(desc))) {
            continue;
        }

        const char *v = vd_vendor_from_text(desc);
        if (!v && vd_ci_contains(desc, "qxl")) {
            v = VD_VENDOR_QEMU;
        }
        if (!v && vd_ci_contains(desc, "cirrus logic")) {
            v = VD_VENDOR_GENERIC;
        }

        if (v && !vd_ci_contains(desc, "basic display")) {
            appendf(hits, sizeof(hits), "\"%s\"; ", desc);
            if (!vendor) {
                vendor = v;
            }
        } else if (vd_ci_contains(desc, "basic display")) {
            snprintf(basic, sizeof(basic), "%s", desc);
        }
    }
    RegCloseKey(key);

    if (hits[0]) {
        vd_add(r, CAT, "Scheda video virtuale", M_GPU, VDS_DETECTED, 20, "%s", hits);
        if (vendor) {
            vd_note_vendor(r, vendor, 59);
        }
    } else if (basic[0]) {
        vd_add(r, CAT, "Scheda video", M_GPU, VDS_INFO, 0,
               "%s (comune su VM senza accelerazione, ma anche su PC senza "
               "driver)", basic);
    } else {
        vd_add(r, CAT, "Scheda video", M_GPU, VDS_CLEAN, 0,
               "nessun adattatore grafico virtuale noto");
    }
}

/* --------------------------------------------------------- alimentazione */

/* Metodo L: puramente informativo. */
static void check_power(VdReport *r)
{
    SYSTEM_POWER_STATUS status;
    if (!GetSystemPowerStatus(&status)) {
        vd_add(r, CAT, "Alimentazione", M_POWER, VDS_SKIP, 0,
               "GetSystemPowerStatus non disponibile");
        return;
    }
    if (status.BatteryFlag == 128 || status.BatteryFlag == 255) {
        vd_add(r, CAT, "Batteria", M_POWER, VDS_INFO, 0,
               "nessuna batteria (desktop o VM) - indicatore poco significativo");
    } else {
        vd_add(r, CAT, "Batteria", M_POWER, VDS_INFO, 0,
               "batteria presente, macchina probabilmente portatile");
    }
}

void checks_devices(VdReport *r)
{
    check_physical_disks(r);
    check_network_adapters(r);
    check_display_adapters(r);
    check_power(r);
}

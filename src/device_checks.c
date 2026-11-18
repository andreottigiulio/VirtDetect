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
#include <setupapi.h>
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
static const char *const M_USB =
    "Enumera con SetupAPI i dispositivi USB e HID presenti (DIGCF_PRESENT) e "
    "tutte le voci installate, e cerca VID/PID dei device virtuali (0627 "
    "QEMU, 80EE VirtualBox, 0E0F VMware, 1AB8 Parallels, 5853 Xen) e "
    "descrizioni come 'QEMU USB Tablet'. Le voci non presenti sono mostrate "
    "a parte, senza peso.";

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

/* ----------------------------------------------------------- USB / HID */

/* VID assegnati alle periferiche emulate. Un dispositivo fisico non puo'
   avere questi identificatori: 0627 e' QEMU, 80EE VirtualBox, 0E0F VMware,
   1AB8 Parallels, 5853 XenSource. Le descrizioni coprono il caso in cui il
   driver generico HID non renda visibile il VID nel nome. */
static const struct {
    const char *pattern;
    const char *vendor;
} virtual_usb_patterns[] = {
    { "VID_0627",        VD_VENDOR_QEMU },
    { "VID_80EE",        VD_VENDOR_VBOX },
    { "VID_0E0F",        VD_VENDOR_VMWARE },
    { "VID_1AB8",        VD_VENDOR_PARALLELS },
    { "VID_5853",        VD_VENDOR_XEN },
    { "qemu",            VD_VENDOR_QEMU },
    { "virtualbox",      VD_VENDOR_VBOX },
    { "innotek",         VD_VENDOR_VBOX },
    { "vmware virtual",  VD_VENDOR_VMWARE },
    { "parallels",       VD_VENDOR_PARALLELS },
    { "xensource",       VD_VENDOR_XEN },
    { "xen usb",         VD_VENDOR_XEN },
    { "virtio",          VD_VENDOR_QEMU },
};

static const char *virtual_usb_vendor(const char *text)
{
    for (size_t i = 0; i < sizeof(virtual_usb_patterns) /
                            sizeof(virtual_usb_patterns[0]); ++i) {
        if (vd_ci_contains(text, virtual_usb_patterns[i].pattern)) {
            return virtual_usb_patterns[i].vendor;
        }
    }
    return NULL;
}

static int usb_property(HDEVINFO set, SP_DEVINFO_DATA *did, DWORD prop,
                        char *out, size_t cap)
{
    out[0] = '\0';
    wchar_t w[1024];
    DWORD type = 0;
    DWORD size = 0;
    if (!SetupDiGetDeviceRegistryPropertyW(set, did, prop, &type,
                                           (PBYTE)w, sizeof(w), &size)) {
        return 0;
    }
    w[(sizeof(w) / sizeof(w[0])) - 1] = L'\0';
    return vd_utf16_to_utf8(w, out, cap);
}

static int usb_instance(HDEVINFO set, SP_DEVINFO_DATA *did,
                        char *out, size_t cap)
{
    out[0] = '\0';
    wchar_t w[512];
    DWORD needed = 0;
    if (!SetupDiGetDeviceInstanceIdW(set, did, w,
                                     (DWORD)(sizeof(w) / sizeof(w[0])),
                                     &needed)) {
        return 0;
    }
    return vd_utf16_to_utf8(w, out, cap);
}

#define VD_USB_MAX_IDS 48

typedef struct {
    char present[VD_EVIDENCE_MAX];
    char ghosts[VD_EVIDENCE_MAX];
    int present_count;
    int ghost_count;
    int enumerated;
    const char *vendor;
    char seen_ids[VD_USB_MAX_IDS][192];
    int seen_id_count;
} VdUsbHits;

static int usb_id_seen(const char *id, const VdUsbHits *h)
{
    for (int i = 0; i < h->seen_id_count; ++i) {
        if (strcmp(h->seen_ids[i], id) == 0) {
            return 1;
        }
    }
    return 0;
}

static void usb_id_add(const char *id, VdUsbHits *h)
{
    if (h->seen_id_count < VD_USB_MAX_IDS) {
        snprintf(h->seen_ids[h->seen_id_count],
                 sizeof(h->seen_ids[0]), "%s", id);
        ++h->seen_id_count;
    }
}

/* VBoxUSB crea sul PC host una voce VID_80EE&PID_CAFE per ogni dispositivo
   USB collegato: e' il driver host di VirtualBox, non una periferica
   virtuale. Le VM vere usano altri PID dello stesso vendor. */
static int is_host_usb_driver(const char *hwid, const char *desc)
{
    return vd_ci_contains(hwid, "PID_CAFE") ||
           vd_ci_contains(desc, "virtualbox usb driver");
}

/* present = 1: solo dispositivi collegati; present = 0: tutte le voci
   installate, comprese quelle non presenti (dispositivo scollegato o
   traccia di una VM precedente). */
static void scan_usb_enumerator(const wchar_t *enumerator, int present,
                                VdUsbHits *h)
{
    DWORD flags = DIGCF_ALLCLASSES | (present ? DIGCF_PRESENT : 0);
    HDEVINFO set = SetupDiGetClassDevsW(NULL, enumerator, NULL, flags);
    if (set == INVALID_HANDLE_VALUE) {
        return;
    }
    h->enumerated = 1;

    SP_DEVINFO_DATA did;
    did.cbSize = sizeof(did);
    for (DWORD i = 0; SetupDiEnumDeviceInfo(set, i, &did); ++i) {
        char instance[224];
        if (!usb_instance(set, &did, instance, sizeof(instance))) {
            continue;
        }
        if (usb_id_seen(instance, h)) {
            continue;
        }

        char hwid[512];
        char desc[256];
        char friendly[256];
        char mfg[128];
        usb_property(set, &did, SPDRP_HARDWAREID, hwid, sizeof(hwid));
        usb_property(set, &did, SPDRP_DEVICEDESC, desc, sizeof(desc));
        usb_property(set, &did, SPDRP_FRIENDLYNAME, friendly, sizeof(friendly));
        usb_property(set, &did, SPDRP_MFG, mfg, sizeof(mfg));

        char text[1200];
        snprintf(text, sizeof(text), "%s | %s | %s | %s",
                 hwid, desc, friendly, mfg);

        if (is_host_usb_driver(hwid, desc)) {
            continue;
        }

        const char *vendor = virtual_usb_vendor(text);
        if (!vendor) {
            continue;
        }

        const char *label = desc[0] ? desc : (friendly[0] ? friendly : hwid);
        if (present) {
            if (h->present_count < 6) {
                appendf(h->present, sizeof(h->present), "\"%s\" [%s]; ",
                        label, hwid[0] ? hwid : instance);
            }
            ++h->present_count;
            if (!h->vendor) {
                h->vendor = vendor;
            }
        } else {
            if (h->ghost_count < 4) {
                appendf(h->ghosts, sizeof(h->ghosts),
                        "\"%s\" [%s]; ", label, hwid[0] ? hwid : instance);
            }
            ++h->ghost_count;
        }
        usb_id_add(instance, h);
    }
    SetupDiDestroyDeviceInfoList(set);
}

/* Metodo M. Il tablet QEMU e' il caso tipico: un dispositivo USB HID
   VID_0627&PID_0001 che Windows gestisce con il driver HID generico e che
   non compare nelle chiavi di registro gia' controllate. */
static void check_virtual_usb_hid(VdReport *r)
{
    VdUsbHits h;
    memset(&h, 0, sizeof(h));

    scan_usb_enumerator(L"USB", 1, &h);
    scan_usb_enumerator(L"HID", 1, &h);
    scan_usb_enumerator(L"USB", 0, &h);
    scan_usb_enumerator(L"HID", 0, &h);

    if (!h.enumerated) {
        vd_add(r, CAT, "Dispositivi USB/HID", M_USB, VDS_SKIP, 0,
               "SetupAPI non disponibile: impossibile enumerare USB e HID");
        return;
    }

    if (h.present_count > 6) {
        appendf(h.present, sizeof(h.present), "e altri %d; ",
                h.present_count - 6);
    }
    if (h.ghost_count > 4) {
        appendf(h.ghosts, sizeof(h.ghosts), "e altre %d voci; ",
                h.ghost_count - 4);
    }

    if (h.present_count) {
        vd_add(r, CAT, "Dispositivo USB/HID virtuale", M_USB,
               VDS_DETECTED, 25, "%s", h.present);
        if (h.vendor) {
            vd_note_vendor(r, h.vendor, 63);
        }
    }
    if (h.ghost_count) {
        vd_add(r, CAT, "Traccia USB/HID virtuale non presente", M_USB,
               VDS_INFO, 0, "%s", h.ghosts);
    }
    if (!h.present_count && !h.ghost_count) {
        vd_add(r, CAT, "Dispositivi USB/HID", M_USB, VDS_CLEAN, 0,
               "nessun VID/PID o descrizione di virtualizzazione nei "
               "dispositivi USB/HID presenti o installati");
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
    check_virtual_usb_hid(r);
    check_power(r);
}

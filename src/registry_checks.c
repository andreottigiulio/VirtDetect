/* ===========================================================================
   RILEVAMENTO DAL REGISTRO E DAI SERVIZI DI WINDOWS
   ===========================================================================

   Dentro una VM il sistema operativo vede solo l'hardware virtuale, quindi
   il registro contiene le tracce di quello che l'hypervisor emula e dei
   guest tools installati. Questi metodi sono preziosi perche' operano a
   livello di software: non dipendono dal fatto che la CPU "menta" o meno.

   Metodi implementati in questo file
   ----------------------------------
   A) Servizi HKLM\SYSTEM\CurrentControlSet\Services.
      I guest tools installano servizi con nomi caratteristici (VBoxGuest,
      VBoxMouse, VBoxSF, vmmouse, vmhgfs, Qemu-ga, vioser...). Il confronto
      e' fatto SOLO con nomi esclusivi del guest: un PC fisico con VMware
      Workstation, VirtualBox o Hyper-V installati ha servizi come vmci,
      vmnet, pvscsi, VBoxNetAdp, vmbus, vmic: non sono prove di VM.

   B) File .sys in System32\drivers.
      Stessa idea, ma sul disco: cercano i driver esclusivi dei guest
      (vboxguest.sys, vmmouse.sys, virtio*.sys...). Peso basso (8).

   C) Chiavi di installazione dei guest tools.
      VMware Tools (HKLM\SOFTWARE\VMware, Inc.\VMware Tools), VirtualBox
      Guest Additions e, per Hyper-V, la chiave Guest\Parameters che esiste
      SOLO dentro una VM Hyper-V ed e' quindi una prova definitiva.

   D) Services\Disk\Enum.
      Windows registra qui gli identificatori dei dischi visti all'avvio:
      "VMware Virtual disk", "VBOX HARDDISK", "QEMU HARDDISK",
      "Msft Virtual Disk" (Hyper-V). Peso 25: molto difficile da falsificare
      senza smontare la VM.

   E) Vendor PCI in Enum\PCI.
      I vendor ID sono assegnati dal PCI-SIG: 15AD VMware, 80EE VirtualBox,
      1AF4/1B36 Red Hat/QEMU, 5853 Xen, 1AB8 Parallels, 1234 Bochs, 1D0F
      Amazon, 1AE0 Google. Se compare uno di questi la VM e' certa.

   F) Device ACPI in Enum\ACPI.
      Le VM espongono device come VMBUS, QEMU0002, VBOX0001, AMZN0001.
      Peso 25.

   G) Identificatori in Enum\SCSI ed Enum\IDE.
      Alcuni hypervisor compaiono solo qui, con nomi tipo "VBOX HARDDISK".

   H) Programmi installati (Uninstall).
      VMware Tools, Guest Additions, QEMU Guest Agent, Parallels Tools,
      Xen Tools. Peso 8: l'utente puo' averli disinstallati.

   Nota sui falsi positivi
   -----------------------
   Il PC di prova ha VMware Workstation, VirtualBox e Hyper-V installati:
   senza il filtro "solo guest" questi controlli davano 60 punti e un
   verdetto "VM MOLTO PROBABILE" sbagliato. La whitelist qui sotto e' la
   correzione di quel caso.
   =========================================================================== */

#include "checks.h"

#include <string.h>

#define CAT "Registro e servizi"

/* Testi mostrati a schermo. */
static const char *const M_SERVICES =
    "Elenca HKLM\\SYSTEM\\CurrentControlSet\\Services e cerca solo i servizi "
    "esclusivi dei guest tools (VBoxGuest, vmmouse, Qemu-ga...), non i driver "
    "degli hypervisor installati sull'host.";
static const char *const M_HYPERV_STACK =
    "Cerca i servizi dello stack Hyper-V (VMBus, VMIC, storvsc, netvsc): "
    "presenti anche su un host fisico con Hyper-V attivo, quindi solo "
    "informativi.";
static const char *const M_DRIVERS =
    "Elenca System32\\drivers e cerca i file .sys esclusivi dei guest tools "
    "(vboxguest, vmmouse, virtio...).";
static const char *const M_GUEST_KEYS =
    "Verifica le chiavi di installazione: VMware Tools, VirtualBox Guest "
    "Additions, parametri guest Hyper-V.";
static const char *const M_DISK_ENUM =
    "Legge Services\\Disk\\Enum: gli identificatori dei dischi virtuali "
    "contengono 'VMware Virtual disk', 'VBOX HARDDISK', 'QEMU HARDDISK', "
    "'Msft Virtual Disk'...";
static const char *const M_PCI =
    "Enumera Enum\\PCI e cerca i vendor ID assegnati alle schede virtuali "
    "(15AD VMware, 80EE VBox, 1AF4 QEMU, 5853 Xen...).";
static const char *const M_ACPI_DEV =
    "Enumera Enum\\ACPI cercando device tipici delle VM (VMBUS, QEMU0002, "
    "VBOX0001, AMZN0001...).";
static const char *const M_STORAGE =
    "Enumera Enum\\SCSI ed Enum\\IDE cercando nomi di dischi virtuali.";
static const char *const M_UNINSTALL =
    "Cerca nei programmi installati (Uninstall) i guest tools: VMware Tools, "
    "Guest Additions, QEMU Guest Agent...";

typedef void (*VdSubkeyFn)(const wchar_t *name, void *user);
typedef void (*VdValueFn)(const wchar_t *name, const char *data, void *user);

static void add_token(char *dst, size_t cap, const char *token)
{
    size_t used = strlen(dst);
    if (used < cap - 2) {
        snprintf(dst + used, cap - used, "%.120s ", token);
    }
}

static void add_group(char *dst, size_t cap, const char *label, const char *list)
{
    if (!list[0]) {
        return;
    }
    size_t used = strlen(dst);
    if (used < cap - 2) {
        snprintf(dst + used, cap - used, "%s: %s; ", label, list);
    }
}

static void enum_subkeys(HKEY root, const wchar_t *path, VdSubkeyFn fn, void *user)
{
    HKEY key = NULL;
    if (RegOpenKeyExW(root, path, 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return;
    }
    for (DWORD i = 0; i < 4096; ++i) {
        wchar_t name[256];
        DWORD name_len = (DWORD)(sizeof(name) / sizeof(name[0]));
        LONG rc = RegEnumKeyExW(key, i, name, &name_len, NULL, NULL, NULL, NULL);
        if (rc != ERROR_SUCCESS) {
            break;
        }
        fn(name, user);
    }
    RegCloseKey(key);
}

static void enum_values_sz(HKEY root, const wchar_t *path, VdValueFn fn, void *user)
{
    HKEY key = NULL;
    if (RegOpenKeyExW(root, path, 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return;
    }
    for (DWORD i = 0; i < 512; ++i) {
        wchar_t name[256];
        DWORD name_len = (DWORD)(sizeof(name) / sizeof(name[0]));
        wchar_t data[1024];
        DWORD data_len = (DWORD)sizeof(data);
        DWORD type = 0;
        LONG rc = RegEnumValueW(key, i, name, &name_len, NULL, &type,
                                (LPBYTE)data, &data_len);
        if (rc != ERROR_SUCCESS) {
            break;
        }
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            data[(sizeof(data) / sizeof(data[0])) - 1] = L'\0';
            char utf8[2048];
            vd_utf16_to_utf8(data, utf8, sizeof(utf8));
            fn(name, utf8, user);
        }
    }
    RegCloseKey(key);
}

/* ------------------------------------------------------------- servizi */

typedef struct {
    char vmware[512];
    char vbox[512];
    char qemu[512];
    char xen[256];
    char parallels[256];
    char hyperv[512];
} ServiceHits;

static int contains_any(const char *s, const char *const *list)
{
    for (int i = 0; list[i]; ++i) {
        if (strstr(s, list[i])) {
            return 1;
        }
    }
    return 0;
}

/* Solo servizi esclusivi dei guest tools: i driver host di VMware Workstation,
   VirtualBox e Hyper-V installano servizi omonimi sul PC fisico (vmci, vmnet,
   vmx86, pvscsi, VBoxNetAdp, VBoxUSB, VBoxSup, vmbus, vmic...). */
static const char *const vmware_guest_services[] = {
    "vmmouse", "vmhgfs", "vmrawdsk", "vmtools", "vm3d", "vmusbmouse", NULL
};
static const char *const vbox_guest_services[] = {
    "vboxguest", "vboxmouse", "vboxsf", "vboxservice", "vboxvideo",
    "vboxwddm", "vboxtray", NULL
};
static const char *const qemu_guest_services[] = {
    "qemu-ga", "virtio", "viostor", "vioscsi", "netkvm", "balloon", "vioser", NULL
};

static void service_cb(const wchar_t *name, void *user)
{
    ServiceHits *h = (ServiceHits *)user;
    char lower[256];
    vd_utf16_to_utf8(name, lower, sizeof(lower));
    vd_lower_ascii(lower);

    if (contains_any(lower, vbox_guest_services)) {
        add_token(h->vbox, sizeof(h->vbox), lower);
    } else if (contains_any(lower, vmware_guest_services)) {
        add_token(h->vmware, sizeof(h->vmware), lower);
    } else if (contains_any(lower, qemu_guest_services)) {
        add_token(h->qemu, sizeof(h->qemu), lower);
    } else if (strstr(lower, "xen")) {
        add_token(h->xen, sizeof(h->xen), lower);
    } else if (strncmp(lower, "prl_", 4) == 0) {
        add_token(h->parallels, sizeof(h->parallels), lower);
    } else if (strstr(lower, "vmbus") || strstr(lower, "vmic") ||
               strstr(lower, "storvsc") || strstr(lower, "netvsc") ||
               strstr(lower, "hyperkbd")) {
        /* Stack Hyper-V: presente anche su host fisici con Hyper-V attivo,
           quindi e' solo informativo (peso 0). */
        add_token(h->hyperv, sizeof(h->hyperv), lower);
    }
}

/* Metodo A. */
static void check_services(VdReport *r)
{
    ServiceHits h;
    memset(&h, 0, sizeof(h));
    enum_subkeys(HKEY_LOCAL_MACHINE,
                 L"SYSTEM\\CurrentControlSet\\Services", service_cb, &h);

    if (h.vmware[0]) {
        vd_add(r, CAT, "Servizi VMware nel sistema", M_SERVICES, VDS_DETECTED, 18,
               "%s", h.vmware);
        vd_note_vendor(r, VD_VENDOR_VMWARE, 56);
    }
    if (h.vbox[0]) {
        vd_add(r, CAT, "Servizi VirtualBox nel sistema", M_SERVICES, VDS_DETECTED, 20,
               "%s", h.vbox);
        vd_note_vendor(r, VD_VENDOR_VBOX, 57);
    }
    if (h.qemu[0]) {
        vd_add(r, CAT, "Servizi QEMU/virtio nel sistema", M_SERVICES, VDS_DETECTED, 18,
               "%s", h.qemu);
        vd_note_vendor(r, VD_VENDOR_QEMU, 56);
    }
    if (h.xen[0]) {
        vd_add(r, CAT, "Servizi Xen nel sistema", M_SERVICES, VDS_DETECTED, 18,
               "%s", h.xen);
        vd_note_vendor(r, VD_VENDOR_XEN, 56);
    }
    if (h.parallels[0]) {
        vd_add(r, CAT, "Servizi Parallels nel sistema", M_SERVICES, VDS_DETECTED, 18,
               "%s", h.parallels);
        vd_note_vendor(r, VD_VENDOR_PARALLELS, 56);
    }
    if (h.hyperv[0]) {
        vd_add(r, CAT, "Stack Hyper-V (VMBus/VMIC)", M_HYPERV_STACK, VDS_INFO, 0,
               "%s (presente anche su un host fisico con Hyper-V attivo: "
               "non e' una prova di VM)", h.hyperv);
    }
    if (!h.vmware[0] && !h.vbox[0] && !h.qemu[0] && !h.xen[0] && !h.parallels[0]) {
        vd_add(r, CAT, "Servizi dei guest tools", M_SERVICES, VDS_CLEAN, 0,
               "nessun servizio guest VMware/VirtualBox/QEMU/Xen/Parallels");
    }
}

/* --------------------------------------------------------- file driver */

typedef struct {
    char vmware[512];
    char vbox[512];
    char qemu[512];
    char xen[256];
    char parallels[256];
    char hyperv[512];
} FileHits;

/* Metodo B. I nomi cercati sono solo quelli dei pacchetti guest. */
static void check_driver_files(VdReport *r)
{
    wchar_t pattern[MAX_PATH];
    UINT len = GetWindowsDirectoryW(pattern, MAX_PATH);
    if (!len || len + 24 >= MAX_PATH) {
        vd_add(r, CAT, "File driver guest", M_DRIVERS, VDS_SKIP, 0,
               "cartella di Windows non determinata");
        return;
    }
    wcscat(pattern, L"\\System32\\drivers\\*.sys");

    WIN32_FIND_DATAW fd;
    HANDLE find = FindFirstFileW(pattern, &fd);
    if (find == INVALID_HANDLE_VALUE) {
        vd_add(r, CAT, "File driver guest", M_DRIVERS, VDS_SKIP, 0,
               "impossibile elencare System32\\drivers");
        return;
    }

    FileHits h;
    memset(&h, 0, sizeof(h));
    do {
        char name[260];
        vd_utf16_to_utf8(fd.cFileName, name, sizeof(name));
        vd_lower_ascii(name);

        if (strstr(name, "vboxguest") || strstr(name, "vboxmouse") ||
            strstr(name, "vboxsf") || strstr(name, "vboxvideo") ||
            strstr(name, "vboxwddm")) {
            add_token(h.vbox, sizeof(h.vbox), name);
        } else if (strstr(name, "vmmouse") || strstr(name, "vmhgfs") ||
                   strstr(name, "vmrawdsk") || strstr(name, "vm3dmp") ||
                   strstr(name, "vm3dgl") || strstr(name, "vmusbmouse")) {
            add_token(h.vmware, sizeof(h.vmware), name);
        } else if (strstr(name, "qemu") || strstr(name, "virtio") ||
                   strstr(name, "viostor") || strstr(name, "vioscsi") ||
                   strstr(name, "netkvm") || strstr(name, "balloon") ||
                   strstr(name, "vioser")) {
            add_token(h.qemu, sizeof(h.qemu), name);
        } else if (strstr(name, "xen")) {
            add_token(h.xen, sizeof(h.xen), name);
        } else if (strncmp(name, "prl_", 4) == 0) {
            add_token(h.parallels, sizeof(h.parallels), name);
        }
    } while (FindNextFileW(find, &fd));
    FindClose(find);

    char all[1400] = "";
    add_group(all, sizeof(all), "VMware", h.vmware);
    add_group(all, sizeof(all), "VirtualBox", h.vbox);
    add_group(all, sizeof(all), "QEMU", h.qemu);
    add_group(all, sizeof(all), "Xen", h.xen);
    add_group(all, sizeof(all), "Parallels", h.parallels);
    add_group(all, sizeof(all), "Hyper-V", h.hyperv);

    if (all[0]) {
        vd_add(r, CAT, "Driver guest su disco", M_DRIVERS, VDS_DETECTED, 8, "%s", all);
        if (h.vmware[0]) vd_note_vendor(r, VD_VENDOR_VMWARE, 50);
        else if (h.vbox[0]) vd_note_vendor(r, VD_VENDOR_VBOX, 50);
        else if (h.qemu[0]) vd_note_vendor(r, VD_VENDOR_QEMU, 50);
        else if (h.xen[0]) vd_note_vendor(r, VD_VENDOR_XEN, 50);
        else if (h.parallels[0]) vd_note_vendor(r, VD_VENDOR_PARALLELS, 50);
    } else {
        vd_add(r, CAT, "Driver guest su disco", M_DRIVERS, VDS_CLEAN, 0,
               "nessun driver guest riconoscibile in System32\\drivers");
    }
}

/* ------------------------------------------------------- chiavi dirette */

/* Metodo C. La chiave Guest\Parameters esiste solo se Windows gira come
   guest Hyper-V: e' marcata definitiva. */
static void check_guest_keys(VdReport *r)
{
    static const wchar_t *vmware_paths[] = {
        L"SOFTWARE\\VMware, Inc.\\VMware Tools",
        L"SOFTWARE\\WOW6432Node\\VMware, Inc.\\VMware Tools",
    };
    for (size_t i = 0; i < sizeof(vmware_paths) / sizeof(vmware_paths[0]); ++i) {
        if (vd_reg_key_exists(HKEY_LOCAL_MACHINE, vmware_paths[i])) {
            char ver[64] = "";
            vd_reg_read_sz(HKEY_LOCAL_MACHINE, vmware_paths[i], L"Version",
                           ver, sizeof(ver));
            vd_add(r, CAT, "VMware Tools installato", M_GUEST_KEYS, VDS_DETECTED, 12,
                   "chiave presente%s%s", ver[0] ? ", versione " : "", ver);
            vd_note_vendor(r, VD_VENDOR_VMWARE, 58);
            break;
        }
    }

    static const wchar_t *vbox_paths[] = {
        L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        L"SOFTWARE\\WOW6432Node\\Oracle\\VirtualBox Guest Additions",
    };
    for (size_t i = 0; i < sizeof(vbox_paths) / sizeof(vbox_paths[0]); ++i) {
        if (vd_reg_key_exists(HKEY_LOCAL_MACHINE, vbox_paths[i])) {
            char ver[64] = "";
            vd_reg_read_sz(HKEY_LOCAL_MACHINE, vbox_paths[i], L"Version",
                           ver, sizeof(ver));
            vd_add(r, CAT, "VirtualBox Guest Additions", M_GUEST_KEYS, VDS_DETECTED, 12,
                   "chiave presente%s%s", ver[0] ? ", versione " : "", ver);
            vd_note_vendor(r, VD_VENDOR_VBOX, 58);
            break;
        }
    }

    const wchar_t *hv_guest = L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters";
    if (vd_reg_key_exists(HKEY_LOCAL_MACHINE, hv_guest)) {
        char host[256] = "";
        vd_reg_read_sz(HKEY_LOCAL_MACHINE, hv_guest, L"PhysicalHostName",
                       host, sizeof(host));
        vd_add(r, CAT, "Parametri guest Hyper-V", M_GUEST_KEYS, VDS_DETECTED, 30,
               "chiave Guest\\Parameters presente%s%s",
               host[0] ? ", host fisico: " : "", host);
        vd_note_vendor(r, VD_VENDOR_HYPERV, 60);
        vd_mark_definitive(r);
    }
}

/* --------------------------------------------------------------- dischi */

typedef struct {
    char text[1024];
} DiskHits;

static void disk_value_cb(const wchar_t *name, const char *data, void *user)
{
    (void)name;
    DiskHits *h = (DiskHits *)user;
    const char *vendor = vd_vendor_from_text(data);
    if (!vendor && !vd_ci_contains(data, "virtual hd") &&
        !vd_ci_contains(data, "virtual disk")) {
        return;
    }
    size_t used = strlen(h->text);
    if (used < sizeof(h->text) - 128) {
        snprintf(h->text + used, sizeof(h->text) - used, "%.300s; ", data);
    }
}

/* Metodo D. */
static void check_disk_enum(VdReport *r)
{
    DiskHits h;
    memset(&h, 0, sizeof(h));
    enum_values_sz(HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum",
                   disk_value_cb, &h);

    if (h.text[0]) {
        /* Hyper-V si presenta come "Msft Virtual Disk" / "Virtual HD":
           vd_vendor_from_text non lo riconosce, quindi aggiungiamo il
           fallback esplicito. */
        const char *vendor = vd_vendor_from_text(h.text);
        if (!vendor && (vd_ci_contains(h.text, "msft virtual") ||
                        vd_ci_contains(h.text, "virtual hd"))) {
            vendor = VD_VENDOR_HYPERV;
        }
        vd_add(r, CAT, "Identificatori dei dischi (Disk\\Enum)", M_DISK_ENUM,
               VDS_DETECTED, 25, "%s", h.text);
        if (vendor) {
            vd_note_vendor(r, vendor, 62);
        }
    } else {
        vd_add(r, CAT, "Identificatori dei dischi (Disk\\Enum)", M_DISK_ENUM,
               VDS_CLEAN, 0, "identificatori disco fisici");
    }
}

/* ----------------------------------------------------------- PCI / ACPI */

typedef struct {
    int vmware, vbox, qemu, xen, parallels, bochs, cloud;
} PciHits;

/* Vendor ID PCI-SIG usati dagli hypervisor. */
static void pci_cb(const wchar_t *name, void *user)
{
    PciHits *h = (PciHits *)user;
    char key[256];
    vd_utf16_to_utf8(name, key, sizeof(key));
    vd_lower_ascii(key);

    if (strstr(key, "ven_15ad")) h->vmware++;
    else if (strstr(key, "ven_80ee")) h->vbox++;
    else if (strstr(key, "ven_1af4") || strstr(key, "ven_1b36")) h->qemu++;
    else if (strstr(key, "ven_5853")) h->xen++;
    else if (strstr(key, "ven_1ab8")) h->parallels++;
    else if (strstr(key, "ven_1234")) h->bochs++;
    else if (strstr(key, "ven_1d0f") || strstr(key, "ven_1ae0")) h->cloud++;
}

/* Metodo E. */
static void check_pci(VdReport *r)
{
    PciHits h;
    memset(&h, 0, sizeof(h));
    enum_subkeys(HKEY_LOCAL_MACHINE,
                 L"SYSTEM\\CurrentControlSet\\Enum\\PCI", pci_cb, &h);

    char text[768] = "";
    if (h.vmware)    add_group(text, sizeof(text), "VMware VEN_15AD", "presente");
    if (h.vbox)      add_group(text, sizeof(text), "VirtualBox VEN_80EE", "presente");
    if (h.qemu)      add_group(text, sizeof(text), "QEMU/virtio VEN_1AF4/1B36", "presente");
    if (h.xen)       add_group(text, sizeof(text), "Xen VEN_5853", "presente");
    if (h.parallels) add_group(text, sizeof(text), "Parallels VEN_1AB8", "presente");
    if (h.bochs)     add_group(text, sizeof(text), "Bochs VEN_1234", "presente");
    if (h.cloud)     add_group(text, sizeof(text), "cloud VEN_1D0F/1AE0", "presente");

    if (text[0]) {
        vd_add(r, CAT, "Vendor PCI in Enum\\PCI", M_PCI, VDS_DETECTED, 30, "%s", text);
        if (h.vmware) vd_note_vendor(r, VD_VENDOR_VMWARE, 64);
        else if (h.vbox) vd_note_vendor(r, VD_VENDOR_VBOX, 64);
        else if (h.qemu) vd_note_vendor(r, VD_VENDOR_QEMU, 64);
        else if (h.xen) vd_note_vendor(r, VD_VENDOR_XEN, 64);
        else if (h.parallels) vd_note_vendor(r, VD_VENDOR_PARALLELS, 64);
    } else {
        vd_add(r, CAT, "Vendor PCI in Enum\\PCI", M_PCI, VDS_CLEAN, 0,
               "nessun vendor ID di virtualizzazione");
    }
}

/* Metodo F. Nomi come VMBUS, QEMU0002, VBOX0001 sono assegnati dal firmware
   virtuale e non esistono su hardware reale. */
static void check_acpi_devices(VdReport *r)
{
    char text[512] = "";
    HKEY key = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Enum\\ACPI", 0,
                      KEY_READ, &key) != ERROR_SUCCESS) {
        vd_add(r, CAT, "Device ACPI in Enum\\ACPI", M_ACPI_DEV, VDS_SKIP, 0,
               "chiave Enum\\ACPI non accessibile");
        return;
    }

    for (DWORD i = 0; i < 512; ++i) {
        wchar_t name[256];
        DWORD name_len = (DWORD)(sizeof(name) / sizeof(name[0]));
        if (RegEnumKeyExW(key, i, name, &name_len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
            break;
        }
        char utf8[256];
        vd_utf16_to_utf8(name, utf8, sizeof(utf8));
        if (vd_vendor_from_text(utf8) ||
            vd_ci_contains(utf8, "vmbus") || vd_ci_contains(utf8, "amzn")) {
            add_token(text, sizeof(text), utf8);
        }
    }
    RegCloseKey(key);

    if (text[0]) {
        const char *vendor = vd_vendor_from_text(text);
        vd_add(r, CAT, "Device ACPI in Enum\\ACPI", M_ACPI_DEV, VDS_DETECTED, 25,
               "%s", text);
        if (vendor) {
            vd_note_vendor(r, vendor, 63);
        }
    } else {
        vd_add(r, CAT, "Device ACPI in Enum\\ACPI", M_ACPI_DEV, VDS_CLEAN, 0,
               "nessun device ACPI di virtualizzazione");
    }
}

/* ------------------------------------------------------- installazioni */

/* Metodo H. Solo nomi espliciti di guest tools: "VirtualBox" da solo non
   basta, perche' l'utente puo' avere VirtualBox installato sull'host. */
static void uninstall_cb(const wchar_t *name, void *user)
{
    static const char *const guest_tools[] = {
        "vmware tools",
        "virtualbox guest additions",
        "guest additions",
        "qemu guest agent",
        "parallels tools",
        "xen tools",
        "xenserver tools",
        NULL
    };

    char *text = (char *)user;
    wchar_t path[512];
    swprintf(path, sizeof(path) / sizeof(path[0]),
             L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\%s", name);
    char display[256];
    if (!vd_reg_read_sz(HKEY_LOCAL_MACHINE, path, L"DisplayName",
                        display, sizeof(display))) {
        return;
    }
    if (!vd_ci_find_any(display, guest_tools)) {
        return;
    }
    size_t used = strlen(text);
    if (used < 1000 - 64) {
        snprintf(text + used, 1024 - used, "%s; ", display);
    }
}

static void check_uninstall(VdReport *r)
{
    char text[1024] = "";
    enum_subkeys(HKEY_LOCAL_MACHINE,
                 L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                 uninstall_cb, text);
    enum_subkeys(HKEY_LOCAL_MACHINE,
                 L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                 uninstall_cb, text);

    if (text[0]) {
        vd_add(r, CAT, "Guest tools nei programmi installati", M_UNINSTALL,
               VDS_DETECTED, 8, "%s", text);
        const char *vendor = vd_vendor_from_text(text);
        if (vendor) {
            vd_note_vendor(r, vendor, 52);
        }
    } else {
        vd_add(r, CAT, "Guest tools nei programmi installati", M_UNINSTALL,
               VDS_CLEAN, 0, "nessun guest tool nell'elenco installazioni");
    }
}

/* ----------------------------------------------------- dischi IDE/SCSI */

/* Metodo G. */
static void check_storage_enum(VdReport *r)
{
    char text[512] = "";
    static const wchar_t *roots[] = {
        L"SYSTEM\\CurrentControlSet\\Enum\\SCSI",
        L"SYSTEM\\CurrentControlSet\\Enum\\IDE",
    };
    for (size_t k = 0; k < sizeof(roots) / sizeof(roots[0]); ++k) {
        HKEY key = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, roots[k], 0, KEY_READ, &key) != ERROR_SUCCESS) {
            continue;
        }
        for (DWORD i = 0; i < 256; ++i) {
            wchar_t name[256];
            DWORD name_len = (DWORD)(sizeof(name) / sizeof(name[0]));
            if (RegEnumKeyExW(key, i, name, &name_len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
                break;
            }
            char utf8[256];
            vd_utf16_to_utf8(name, utf8, sizeof(utf8));
            if (vd_vendor_from_text(utf8) ||
                vd_ci_contains(utf8, "virtual hd") ||
                vd_ci_contains(utf8, "virtual disk")) {
                add_token(text, sizeof(text), utf8);
            }
        }
        RegCloseKey(key);
    }

    if (text[0]) {
        vd_add(r, CAT, "Dischi in Enum\\SCSI/IDE", M_STORAGE,
               VDS_DETECTED, 12, "%s", text);
        const char *vendor = vd_vendor_from_text(text);
        if (vendor) {
            vd_note_vendor(r, vendor, 60);
        }
    } else if (g_verbose) {
        vd_add(r, CAT, "Dischi in Enum\\SCSI/IDE", M_STORAGE,
               VDS_CLEAN, 0, "nessun identificatore virtuale");
    }
}

void checks_registry(VdReport *r)
{
    check_services(r);
    check_driver_files(r);
    check_guest_keys(r);
    check_disk_enum(r);
    check_pci(r);
    check_acpi_devices(r);
    check_storage_enum(r);
    check_uninstall(r);
}

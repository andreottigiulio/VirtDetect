/* ===========================================================================
   RILEVAMENTO DAI PROCESSI E DAI MODULI CARICATI
   ===========================================================================

   I guest tools sono programmi che l'utente (o l'amministratore della VM)
   installa DENTRO la macchina virtuale: driver video, integrazione con il
   clipboard, cartelle condivise, agenti di gestione. Se uno di questi
   processi o DLL e' presente, la macchina e' quasi certamente una VM.

   Metodi implementati in questo file
   ----------------------------------
   P) Processi in esecuzione.
      Scansiona l'elenco dei processi con CreateToolhelp32Snapshot e cerca:
      vmtoolsd, vmwaretray, vmwareuser, vgauthservice (VMware Tools);
      VBoxService, VBoxTray, VBoxClient (Guest Additions);
      qemu-ga (QEMU Guest Agent);
      prl_tools, prl_cc (Parallels Tools); xenservice (Xen).
      Peso 12: richiede che i guest tools siano installati e avviati.

   Q) DLL caricate nel processo corrente.
      GetModuleHandleW verifica se il processo ha gia' in memoria le DLL
      dei guest tools (vm3dgl, vm3dum, vmhook, vboxhook, vboxogl,
      vboxmrxnp, vmhgfs, vmci). Peso 8.
      Attenzione: vmci.dll e' anche il driver host di VMware Workstation,
      ma in questo caso la DLL deve essere caricata nel NOSTRO processo,
      cosa che avviene solo tramite i guest tools.

   Limiti
   ------
   Sono controlli "di comodo": una VM senza guest tools non mostra nulla.
   Per questo pesano poco e servono solo come conferma insieme agli altri.
   =========================================================================== */

#include "checks.h"

#include <string.h>
#include <tlhelp32.h>

#define CAT "Processi e moduli"

static const char *const M_PROC =
    "Scansiona l'elenco dei processi (Toolhelp32) cercando i processi dei "
    "guest tools (vmtoolsd, VBoxService, qemu-ga...).";
static const char *const M_MODULES =
    "Controlla se il processo ha caricato DLL dei guest tools (vm3dgl, "
    "vboxhook, vmhgfs...).";

static void add_name(char *dst, size_t cap, const char *name)
{
    size_t used = strlen(dst);
    if (used < cap - 2) {
        snprintf(dst + used, cap - used, "%.120s ", name);
    }
}

typedef struct {
    char vmware[384];
    char vbox[384];
    char qemu[256];
    char parallels[256];
    char xen[256];
} ProcessHits;

/* Metodo P. */
static void check_processes(VdReport *r)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        vd_add(r, CAT, "Processi guest", M_PROC, VDS_SKIP, 0,
               "snapshot dei processi non disponibile");
        return;
    }

    ProcessHits h;
    memset(&h, 0, sizeof(h));

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            char name[260];
            vd_utf16_to_utf8(entry.szExeFile, name, sizeof(name));
            vd_lower_ascii(name);

            if (strstr(name, "vmtoolsd") || strstr(name, "vmwaretray") ||
                strstr(name, "vmwareuser") || strstr(name, "vgauthservice")) {
                add_name(h.vmware, sizeof(h.vmware), name);
            } else if (strstr(name, "vboxservice") || strstr(name, "vboxtray") ||
                       strstr(name, "vboxclient")) {
                add_name(h.vbox, sizeof(h.vbox), name);
            } else if (strstr(name, "qemu-ga")) {
                add_name(h.qemu, sizeof(h.qemu), name);
            } else if (strstr(name, "prl_tools") || strstr(name, "prl_cc")) {
                add_name(h.parallels, sizeof(h.parallels), name);
            } else if (strstr(name, "xenservice")) {
                add_name(h.xen, sizeof(h.xen), name);
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);

    char text[1024] = "";
    const char *vendor = NULL;
    if (h.vmware[0])    { add_name(text, sizeof(text), h.vmware); vendor = VD_VENDOR_VMWARE; }
    if (h.vbox[0])      { add_name(text, sizeof(text), h.vbox); if (!vendor) vendor = VD_VENDOR_VBOX; }
    if (h.qemu[0])      { add_name(text, sizeof(text), h.qemu); if (!vendor) vendor = VD_VENDOR_QEMU; }
    if (h.parallels[0]) { add_name(text, sizeof(text), h.parallels); if (!vendor) vendor = VD_VENDOR_PARALLELS; }
    if (h.xen[0])       { add_name(text, sizeof(text), h.xen); if (!vendor) vendor = VD_VENDOR_XEN; }

    if (text[0]) {
        vd_add(r, CAT, "Processi dei guest tools", M_PROC, VDS_DETECTED, 12,
               "in esecuzione: %s", text);
        if (vendor) {
            vd_note_vendor(r, vendor, 54);
        }
    } else {
        vd_add(r, CAT, "Processi dei guest tools", M_PROC, VDS_CLEAN, 0,
               "nessun processo guest noto in esecuzione");
    }
}

/* Metodo Q. */
static void check_loaded_modules(VdReport *r)
{
    static const wchar_t *modules[] = {
        L"vm3dgl.dll", L"vm3dum.dll", L"vmhook.dll",
        L"vboxhook.dll", L"vboxogl.dll", L"vboxmrxnp.dll",
        L"vmhgfs.dll", L"vmci.dll",
    };
    char hits[512] = "";
    const char *vendor = NULL;

    for (size_t i = 0; i < sizeof(modules) / sizeof(modules[0]); ++i) {
        if (GetModuleHandleW(modules[i]) != NULL) {
            char name[64];
            vd_utf16_to_utf8(modules[i], name, sizeof(name));
            add_name(hits, sizeof(hits), name);
            if (!vendor) {
                vendor = vd_ci_contains(name, "vbox") ? VD_VENDOR_VBOX
                                                      : VD_VENDOR_VMWARE;
            }
        }
    }

    if (hits[0]) {
        vd_add(r, CAT, "DLL dei guest tools nel processo", M_MODULES,
               VDS_DETECTED, 8, "%s", hits);
        if (vendor) {
            vd_note_vendor(r, vendor, 45);
        }
    } else {
        vd_add(r, CAT, "DLL dei guest tools nel processo", M_MODULES,
               VDS_CLEAN, 0, "nessuna DLL guest caricata nel processo corrente");
    }
}

void checks_processes(VdReport *r)
{
    check_processes(r);
    check_loaded_modules(r);
}

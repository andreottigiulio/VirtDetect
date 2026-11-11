#include "checks.h"

/* ===========================================================================
   MAPPA DELLE PAROLE CHIAVE -> VENDOR

   Tutti i controlli producono stringhe (SMBIOS, BIOS, nomi di servizi,
   identificatori di dischi, descrizioni delle NIC). Invece di scrivere un
   confronto per ogni fonte, si usa un'unica tabella: se una stringa contiene
   una di queste parole, il vendor virtuale e' quello indicato.

   L'ordine conta: i pattern piu' specifici vengono prima (es. "virtualbox"
   prima di "vbox") e la ricerca e' case-insensitive.

   Attenzione: queste parole possono comparire anche in nomi legittimi di
   un PC fisico (un utente puo' chiamare il PC "XEN-server" o installare
   "Oracle Cloud" come gioco). Per questo ogni chiamante pesa il risultato
   in modo diverso e i controlli "di solo testo" valgono pochi punti.
   =========================================================================== */
static const struct {
    const char *needle;
    const char *vendor;
} patterns[] = {
    { "vmware",         VD_VENDOR_VMWARE },
    { "virtualbox",     VD_VENDOR_VBOX },
    { "innotek",        VD_VENDOR_VBOX },
    { "vbox",           VD_VENDOR_VBOX },
    { "qemu",           VD_VENDOR_QEMU },
    { "kvm",            VD_VENDOR_QEMU },
    { "xen",            VD_VENDOR_XEN },
    { "parallels",      VD_VENDOR_PARALLELS },
    { "bhyve",          VD_VENDOR_BHYVE },
    { "bochs",          VD_VENDOR_BOCHS },
    { "hyper-v",        VD_VENDOR_HYPERV },
    /* "Virtual Machine" e' il nome generico usato da Hyper-V; una VM
       VMware/VirtualBox di solito espone anche il proprio marchio, che
       compare prima in questa tabella. */
    { "virtual machine", VD_VENDOR_HYPERV },
    { "virtual platform", VD_VENDOR_GENERIC },
    { "virtio",         VD_VENDOR_QEMU },
    { "seabios",        VD_VENDOR_QEMU },
    { "ovmf",           VD_VENDOR_QEMU },
    { "amazon ec2",     VD_VENDOR_CLOUD },
    { "google compute", VD_VENDOR_CLOUD },
    { "openstack",      VD_VENDOR_CLOUD },
    { "alibaba",        VD_VENDOR_CLOUD },
    { "digitalocean",   VD_VENDOR_CLOUD },
    { "vultr",          VD_VENDOR_CLOUD },
    { "hetzner",        VD_VENDOR_CLOUD },
    { "oracle cloud",   VD_VENDOR_CLOUD },
};

const char *vd_vendor_from_text(const char *text)
{
    if (!text || !*text) {
        return NULL;
    }
    for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); ++i) {
        if (vd_ci_contains(text, patterns[i].needle)) {
            return patterns[i].vendor;
        }
    }
    return NULL;
}

#ifndef VD_CHECKS_H
#define VD_CHECKS_H

#include "common.h"

/* Etichette vendor usate nel verdetto finale. */
#define VD_VENDOR_VMWARE    "VMware"
#define VD_VENDOR_VBOX      "VirtualBox"
#define VD_VENDOR_QEMU      "QEMU/KVM"
#define VD_VENDOR_HYPERV    "Microsoft Hyper-V"
#define VD_VENDOR_XEN       "Xen"
#define VD_VENDOR_PARALLELS "Parallels"
#define VD_VENDOR_BOCHS     "Bochs"
#define VD_VENDOR_BHYVE     "bhyve"
#define VD_VENDOR_CLOUD     "cloud/VPS"
#define VD_VENDOR_GENERIC   "hypervisor"

/* Parole chiave che identificano un firmware/hardware virtuale. */
const char *vd_vendor_from_text(const char *text);

/* Probabilita' euristica ricavata da tutti i controlli (0..99%). */
typedef struct {
    int percent;
    const char *band;      /* "bassa", "media", "alta", "molto alta" */
    int detected_checks;   /* controlli positivi */
    int categories_hit;    /* categorie con almeno un positivo */
    int total_categories;  /* categorie valutate */
    int definitive;        /* e' presente una prova diretta */
    int contradictions;    /* combinazioni impossibili trovate */
    int contradiction_weight; /* peso complessivo delle incoerenze */
    double logit;          /* valore interno, mostrato con --verbose */
} VdProbability;

void vd_probability(const VdReport *r, VdProbability *out);

void checks_cpuid(VdReport *r);
void checks_firmware(VdReport *r);
void checks_registry(VdReport *r);
void checks_devices(VdReport *r);
void checks_timing(VdReport *r);
void checks_processes(VdReport *r);
void checks_coherence(VdReport *r);
void checks_privileged(VdReport *r);

/* Risposta ATA IDENTIFY DEVICE decodificata. Il parser e' separato dalla
   chiamata IOCTL per poterlo provare con un settore sintetico. */
typedef struct {
    char model[48];
    char serial[32];
    char firmware[16];
    int rotation;   /* 0 = non riportata, 1 = SSD, >= 1000 = RPM */
    int ncq;
    int trim;
    int valid;
} VdAtaIdentify;

void vd_ata_parse_identify(const unsigned char *sector, VdAtaIdentify *out);

#endif

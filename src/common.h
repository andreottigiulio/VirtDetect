#ifndef VD_COMMON_H
#define VD_COMMON_H

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00

#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#define VD_EVIDENCE_MAX 768
#define VD_MAX_CHECKS 200

typedef enum {
    VDS_DETECTED,       /* indizio positivo, si somma al punteggio */
    VDS_CONTRADICTION,  /* combinazione impossibile su un PC fisico */
    VDS_CLEAN,
    VDS_INFO,
    VDS_SKIP
} VdStatus;

typedef struct {
    const char *category;
    char name[96];
    const char *method;     /* tecnica usata, spiegata a schermo */
    VdStatus status;
    int weight;
    char evidence[VD_EVIDENCE_MAX];
} VdCheck;

typedef struct {
    VdCheck checks[VD_MAX_CHECKS];
    int count;
    int score;
    int contradictions;
    int contradiction_score;
    int definitive;
    int hypervisor_present;
    int vendor_priority;
    char vendor[64];
} VdReport;

extern int g_verbose;

void vd_add(VdReport *r, const char *category, const char *name,
            const char *method, VdStatus st, int weight,
            const char *fmt, ...);
/* Evidenza negativa: una combinazione che un PC fisico non puo' avere.
   Il peso non si somma al punteggio degli indizi ma ha un canale separato
   (r->contradictions / r->contradiction_score) usato dalla probabilita'. */
void vd_add_contradiction(VdReport *r, const char *category, const char *name,
                          const char *method, int weight,
                          const char *fmt, ...);
void vd_note_vendor(VdReport *r, const char *vendor, int priority);
void vd_mark_definitive(VdReport *r);

int vd_ci_contains(const char *hay, const char *needle);
const char *vd_ci_find_any(const char *hay, const char *const *needles);
void vd_lower_ascii(char *s);
int vd_str_has_prefix_ci(const char *s, const char *prefix);

int vd_utf16_to_utf8(const wchar_t *in, char *out, size_t outsz);
int vd_reg_read_sz(HKEY root, const wchar_t *path, const wchar_t *value,
                   char *out, size_t outsz);
int vd_reg_key_exists(HKEY root, const wchar_t *path);
int vd_file_exists(const wchar_t *path);

void vd_probe_init(void);
int vd_probe(void (*fn)(void));
extern volatile LONG g_last_exception;
uint64_t vd_rdtscp(void);

#endif

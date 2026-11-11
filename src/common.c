#include "common.h"

#include <setjmp.h>
#include <stdarg.h>
#include <string.h>

int g_verbose = 0;

static void copy_evidence(VdCheck *c, const char *fmt, va_list ap)
{
    if (!fmt) {
        c->evidence[0] = '\0';
        return;
    }
    vsnprintf(c->evidence, sizeof(c->evidence), fmt, ap);
}

static void add_check(VdReport *r, const char *category, const char *name,
                      const char *method, VdStatus st, int weight,
                      const char *fmt, va_list ap)
{
    if (r->count >= VD_MAX_CHECKS) {
        return;
    }

    VdCheck *c = &r->checks[r->count++];
    c->category = category;
    snprintf(c->name, sizeof(c->name), "%s", name ? name : "");
    c->method = method;
    c->status = st;
    c->weight = (st == VDS_DETECTED || st == VDS_CONTRADICTION) ? weight : 0;
    copy_evidence(c, fmt, ap);

    if (st == VDS_DETECTED) {
        r->score += weight;
    } else if (st == VDS_CONTRADICTION) {
        ++r->contradictions;
        r->contradiction_score += weight;
    }
}

void vd_add(VdReport *r, const char *category, const char *name,
            const char *method, VdStatus st, int weight,
            const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    add_check(r, category, name, method, st, weight, fmt, ap);
    va_end(ap);
}

void vd_add_contradiction(VdReport *r, const char *category, const char *name,
                          const char *method, int weight,
                          const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    add_check(r, category, name, method, VDS_CONTRADICTION, weight, fmt, ap);
    va_end(ap);
}

void vd_note_vendor(VdReport *r, const char *vendor, int priority)
{
    if (!vendor || !*vendor) {
        return;
    }
    if (priority >= r->vendor_priority) {
        snprintf(r->vendor, sizeof(r->vendor), "%s", vendor);
        r->vendor_priority = priority;
    }
}

void vd_mark_definitive(VdReport *r)
{
    r->definitive = 1;
}

int vd_ci_contains(const char *hay, const char *needle)
{
    if (!hay || !needle || !*needle) {
        return 0;
    }
    size_t nlen = strlen(needle);
    for (const char *p = hay; *p; ++p) {
        size_t i = 0;
        while (i < nlen && p[i]) {
            char a = p[i];
            char b = needle[i];
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
            if (a != b) break;
            ++i;
        }
        if (i == nlen) {
            return 1;
        }
    }
    return 0;
}

const char *vd_ci_find_any(const char *hay, const char *const *needles)
{
    for (int i = 0; needles[i]; ++i) {
        if (vd_ci_contains(hay, needles[i])) {
            return needles[i];
        }
    }
    return NULL;
}

void vd_lower_ascii(char *s)
{
    for (; s && *s; ++s) {
        if (*s >= 'A' && *s <= 'Z') {
            *s = (char)(*s - 'A' + 'a');
        }
    }
}

int vd_str_has_prefix_ci(const char *s, const char *prefix)
{
    if (!s || !prefix) return 0;
    while (*prefix) {
        char a = *s++;
        char b = *prefix++;
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return 0;
    }
    return 1;
}

int vd_utf16_to_utf8(const wchar_t *in, char *out, size_t outsz)
{
    out[0] = '\0';
    if (!in || !outsz) return 0;

    int n = WideCharToMultiByte(CP_UTF8, 0, in, -1, out, (int)outsz, NULL, NULL);
    if (n <= 0) {
        out[0] = '\0';
        return 0;
    }
    return 1;
}

int vd_reg_read_sz(HKEY root, const wchar_t *path, const wchar_t *value,
                   char *out, size_t outsz)
{
    out[0] = '\0';
    wchar_t buf[2048];
    DWORD bytes = sizeof(buf);
    DWORD type = 0;

    LONG rc = RegGetValueW(root, path, value,
                           RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
                           &type, buf, &bytes);
    if (rc != ERROR_SUCCESS) {
        return 0;
    }
    buf[(sizeof(buf) / sizeof(buf[0])) - 1] = L'\0';
    return vd_utf16_to_utf8(buf, out, outsz);
}

int vd_reg_key_exists(HKEY root, const wchar_t *path)
{
    HKEY key = NULL;
    LONG rc = RegOpenKeyExW(root, path, 0, KEY_READ, &key);
    if (rc != ERROR_SUCCESS) {
        return 0;
    }
    RegCloseKey(key);
    return 1;
}

int vd_file_exists(const wchar_t *path)
{
    DWORD attrs = GetFileAttributesW(path);
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

/* ------------------------------------------------------------------ probes
   Eccezioni hardware (#GP da istruzioni privilegiate) intercettate con un
   vectored handler e recuperate con longjmp, perche' GCC non supporta __try. */

static jmp_buf g_probe_jmp;
static volatile int g_probe_armed;
static PVOID g_probe_handle;
volatile LONG g_last_exception;

static LONG CALLBACK probe_handler(EXCEPTION_POINTERS *ep)
{
    if (!g_probe_armed) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    g_last_exception = ep->ExceptionRecord->ExceptionCode;
    g_probe_armed = 0;
    longjmp(g_probe_jmp, 1);
}

void vd_probe_init(void)
{
    if (!g_probe_handle) {
        g_probe_handle = AddVectoredExceptionHandler(1, probe_handler);
    }
}

int vd_probe(void (*fn)(void))
{
    vd_probe_init();
    g_last_exception = 0;
    if (setjmp(g_probe_jmp) == 0) {
        g_probe_armed = 1;
        fn();
        g_probe_armed = 0;
        return 1;
    }
    return 0;
}

uint64_t vd_rdtscp(void)
{
    uint32_t lo = 0, hi = 0, aux = 0;
    __asm__ __volatile__("rdtscp" : "=a"(lo), "=d"(hi), "=c"(aux));
    return ((uint64_t)hi << 32) | lo;
}

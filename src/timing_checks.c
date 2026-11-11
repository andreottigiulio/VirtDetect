/* ===========================================================================
   RILEVAMENTO BASATO SUI TEMPI
   ===========================================================================

   Un hypervisor deve intercettare alcune istruzioni e "girare" il controllo
   su di se' (VM exit). Questo costa migliaia di cicli in piu' rispetto a una
   CPU nativa, e il ritardo e' misurabile.

   Metodi implementati in questo file
   ----------------------------------
   M) Costo di CPUID.
      Si misura con RDTSC/RDTSCP il tempo di un'istruzione CPUID rispetto a
      un'istruzione innocua (due RDTSCP consecutivi). Su CPU nativa CPUID
      costa qualche centinaio di cicli; sotto un hypervisor che non usa
      l'esecuzione diretta (VMware, Xen, VirtualBox senza VT-x) puo'
      costarne decine di migliaia.
      Condizione per segnalare: costo > 1000 cicli E > 6 volte la baseline.
      Peso 6: rumoroso, falsi positivi con CPU molto lente o frequenze
      variabili, quindi solo un indizio.

   N) SIDT "red pill".
      L'istruzione SIDT legge il registro IDTR, che contiene l'indirizzo
      della tabella dei descrittori di interrupt. Su un PC fisico la IDT sta
      nel kernel (indirizzo alto, bit 47 a 1). Alcuni hypervisor legacy
      (soprattutto VMware su CPU senza VT-x) la mappano in memoria utente,
      lasciando un indirizzo con i bit alti a zero: e' la "red pill" di
      Joanna Rutkowska.
      Peso 8, solo indizio: non funziona con le VM moderne, e UMIP la
      blocca del tutto (in quel caso il controllo viene saltato).

   O) TSC vs QPC.
      Confronta la frequenza del Time Stamp Counter della CPU con quella del
      Query Performance Counter di Windows. Informativo: Windows espone un
      QPC a frequenza fissa (spesso 10 MHz) anche su hardware reale, quindi
      il rapporto da solo non prova nulla.

   P) Throughput di istruzioni dipendenti.
      Esegue un ciclo di un milione di ADD con dipendenza stretta (ogni ADD
      usa il risultato del precedente) e misura i cicli TSC per iterazione.
      Su una CPU nativa la catena esegue circa una ADD per ciclo (1 ciclo
      TSC per iterazione); su un emulatore TCG ogni istruzione viene tradotta
      ed eseguita a runtime e costa 10-50 cicli. Si prende il minimo di 5
      ripetizioni per ignorare interruzioni e scheduling.
      Condizione: > 6 cicli TSC per iterazione. Peso 8, indizio forte di
      emulazione ma non definitivo (hypervisor con accelerazione hardware
      non lo attivano).
   =========================================================================== */

#include "checks.h"

#include <cpuid.h>
#include <string.h>

#define CAT "Timing"

static const char *const M_CPUID_TIME =
    "Misura con RDTSCP il costo di una CPUID: un hypervisor la intercetta e "
    "la rallenta (VM exit), quindi costa molti piu' cicli.";
static const char *const M_SIDT =
    "Esegue SIDT e legge il base della IDT: se punta a memoria utente (bit "
    "alti a zero) e' il classico 'red pill' di una VM.";
static const char *const M_TSC =
    "Confronta la frequenza del TSC con quella del QPC di Windows (solo dato "
    "informativo).";
static const char *const M_CHAIN =
    "Esegue un milione di ADD dipendenti e misura i cicli TSC per iterazione: "
    "nativo ~1 ciclo, emulazione TCG 10-50 cicli.";

/* Misura il costo minimo di CPUID e di due RDTSCP consecutivi (baseline).
   Si usa il minimo su 200 iterazioni per eliminare interruzioni e rumore. */
static uint64_t cpuid_cost(uint64_t *baseline)
{
    uint64_t best = UINT64_MAX;
    uint64_t base_best = UINT64_MAX;

    for (int i = 0; i < 200; ++i) {
        uint64_t t0 = vd_rdtscp();
        uint64_t t1 = vd_rdtscp();
        if (t1 - t0 < base_best) {
            base_best = t1 - t0;
        }

        uint32_t a = 0, b = 0, c = 0, d = 0;
        t0 = vd_rdtscp();
        __asm__ __volatile__("cpuid" : "+a"(a), "+b"(b), "+c"(c), "+d"(d));
        t1 = vd_rdtscp();
        if (t1 - t0 < best) {
            best = t1 - t0;
        }
    }

    *baseline = base_best;
    return best;
}

/* Metodo M. Il bit 4 di EDX della foglia 1 indica la presenza del TSC. */
static void check_cpuid_timing(VdReport *r)
{
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (!__get_cpuid(1, &a, &b, &c, &d) || !(d & (1u << 4))) {
        vd_add(r, CAT, "Costo di CPUID", M_CPUID_TIME, VDS_SKIP, 0,
               "TSC non disponibile su questo processore");
        return;
    }

    uint64_t baseline = 0;
    uint64_t cost = cpuid_cost(&baseline);

    if (cost > 1000 && cost > 6 * (baseline + 50)) {
        vd_add(r, CAT, "Costo anomalo di CPUID", M_CPUID_TIME, VDS_DETECTED, 6,
               "%llu cicli (baseline RDTSCP %llu): possibile trap/exit "
               "dell'hypervisor",
               (unsigned long long)cost, (unsigned long long)baseline);
    } else {
        vd_add(r, CAT, "Costo di CPUID", M_CPUID_TIME, VDS_CLEAN, 0,
               "%llu cicli (baseline RDTSCP %llu) - coerente con CPU nativa",
               (unsigned long long)cost, (unsigned long long)baseline);
    }
}

/* SIDT non e' privilegiata ma puo' generare #GP con UMIP attivo: la si
   esegue dentro vd_probe() per poter recuperare l'eccezione. */
static volatile uint64_t sidt_base;
static volatile uint16_t sidt_limit;

static void probe_sidt(void)
{
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) idtr;

    idtr.limit = 0;
    idtr.base = 0;
    __asm__ __volatile__("sidt %0" : "=m"(idtr));
    sidt_base = idtr.base;
    sidt_limit = idtr.limit;
}

/* Metodo N. Su un PC fisico l'indirizzo della IDT e' nel kernel, quindi i
   bit 63..47 non sono tutti zero; in memoria utente si'. */
static void check_sidt(VdReport *r)
{
    if (!vd_probe(probe_sidt)) {
        vd_add(r, CAT, "SIDT (red pill)", M_SIDT, VDS_SKIP, 0,
               "istruzione SIDT bloccata (UMIP attivo)");
        return;
    }

    uint64_t base = sidt_base;
    int user_space = (base != 0) && ((base >> 47) == 0);

    if (user_space) {
        vd_add(r, CAT, "IDT in memoria utente (red pill)", M_SIDT,
               VDS_DETECTED, 8,
               "SIDT base=0x%llX limit=0x%X: su hardware reale la IDT e' nel "
               "kernel, questo e' un indizio di hypervisor legacy",
               (unsigned long long)base, sidt_limit);
        vd_note_vendor(r, VD_VENDOR_GENERIC, 30);
    } else {
        vd_add(r, CAT, "SIDT (red pill)", M_SIDT, VDS_CLEAN, 0,
               "base=0x%llX limit=0x%X (indirizzo kernel, coerente con PC fisico)",
               (unsigned long long)base, sidt_limit);
    }
}

/* Metodo P. La catena dipendente non puo' essere eseguita in parallelo:
   il tempo per iterazione e' il costo reale di una ADD. */
static void check_instruction_chain(VdReport *r)
{
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (!__get_cpuid(1, &a, &b, &c, &d) || !(d & (1u << 4))) {
        vd_add(r, CAT, "Throughput di istruzioni", M_CHAIN, VDS_SKIP, 0,
               "TSC non disponibile su questo processore");
        return;
    }

    const int iterations = 1000000;
    uint64_t best = UINT64_MAX;

    for (int rep = 0; rep < 5; ++rep) {
        uint64_t acc = 1;
        uint64_t t0 = vd_rdtscp();
        for (int i = 0; i < iterations; ++i) {
            __asm__ __volatile__("addq $1, %0" : "+r"(acc));
        }
        uint64_t t1 = vd_rdtscp();
        if (t1 - t0 < best) {
            best = t1 - t0;
        }
        (void)acc;
    }

    double per_iter = (double)best / (double)iterations;
    if (per_iter > 6.0) {
        vd_add(r, CAT, "Throughput di istruzioni anomalo", M_CHAIN,
               VDS_DETECTED, 8,
               "%.2f cicli TSC per ADD dipendente (nativo ~1, emulazione "
               "TCG 10-50): la CPU sta traducendo le istruzioni",
               per_iter);
    } else {
        vd_add(r, CAT, "Throughput di istruzioni", M_CHAIN, VDS_CLEAN, 0,
               "%.2f cicli TSC per ADD dipendente (coerente con esecuzione "
               "nativa)", per_iter);
    }
}

/* Metodo O: solo informativo. */
static void check_tsc_vs_qpc(VdReport *r)
{
    LARGE_INTEGER freq, q0, q1;
    if (!QueryPerformanceFrequency(&freq) || freq.QuadPart <= 0) {
        vd_add(r, CAT, "TSC vs QPC", M_TSC, VDS_SKIP, 0,
               "QueryPerformanceFrequency non disponibile");
        return;
    }

    QueryPerformanceCounter(&q0);
    uint64_t t0 = vd_rdtscp();
    Sleep(150);
    uint64_t t1 = vd_rdtscp();
    QueryPerformanceCounter(&q1);

    if (q1.QuadPart <= q0.QuadPart || t1 <= t0) {
        vd_add(r, CAT, "TSC vs QPC", M_TSC, VDS_SKIP, 0, "misura non valida");
        return;
    }

    double seconds = (double)(q1.QuadPart - q0.QuadPart) / (double)freq.QuadPart;
    double tsc_hz = (double)(t1 - t0) / seconds;
    double qpc_hz = (double)freq.QuadPart;
    double ratio = tsc_hz / qpc_hz;

    /* Windows puo' esporre un QPC a frequenza fissa (es. 10 MHz sotto
       Hyper-V) anche su hardware reale: per questo non assegna punti. */
    vd_add(r, CAT, "Frequenza TSC vs QPC", M_TSC, VDS_INFO, 0,
           "TSC ~%.2f GHz, QPC %.2f MHz, rapporto %.2f",
           tsc_hz / 1e9, qpc_hz / 1e6, ratio);
}

void checks_timing(VdReport *r)
{
    check_cpuid_timing(r);
    check_sidt(r);
    check_instruction_chain(r);
    check_tsc_vs_qpc(r);
}

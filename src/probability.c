/* ===========================================================================
   PROBABILITA' EURISTICA DI TROVARSI SU UNA VM
   ===========================================================================

   Il punteggio di VirtDetect e' una somma lineare di pesi: va bene per
   ordinare i casi, ma non e' una probabilita'. Questa funzione converte
   tutto quello che il programma ha raccolto in una percentuale leggibile.

   Modello (volutamente semplice e spiegabile)
   -------------------------------------------
   1) Si parte da un logit iniziale di -4.5, cioe' circa l'1%: la
      probabilita' a priori che una macchina Windows qualsiasi sia una VM
      senza nessun indizio. Non e' un dato statistico misurato, e' una
      scelta prudente per il verdetto "PC fisico".

   2) Se il bit hypervisor CPUID e' presente si aggiunge +1.2. Da solo non
      prova niente (Hyper-V/VBS/WSL2 lo impostano anche sull'host), ma
      alza le probabilita' rispetto a un PC senza.

   3) Ogni controllo positivo aggiunge weight/5 al logit (cioe' 0.2 per
      punto di peso). I pesi sono quelli gia' documentati nei vari moduli:
      una firma CPUID da 40 pesa +8.0, un disco virtuale da 25 pesa +5.0,
      una NIC da 10 pesa +2.0. L'uso del logit (invece della somma diretta)
      evita che tanti indizi debolissimi saturino la percentuale.

   4) "Ampiezza delle prove": ogni categoria indipendente (CPUID, firmware,
      registro, dispositivi, timing, processi) che contiene almeno un
      positivo aggiunge +0.4 oltre la prima. Cinque categorie diverse che
      concordano valgono piu' di cinque controlli tutti nello stesso
      modulo: hypervisor, firmware, dischi e driver non possono essere
      falsificati tutti insieme per caso.

   5) Se una prova e' "definitiva" (firma hypervisor reale, backdoor VMware,
      parametri guest Hyper-V) il logit viene alzato ad almeno +4.6, cioe'
      99%: non si scende sotto questa soglia nemmeno con pochi altri indizi.

   6) Le incoerenze (combinazioni impossibili su un PC fisico) hanno un
      canale separato e costano 0.25 per punto di peso, piu' di un indizio
      normale. Non si sommano al punteggio mostrato, ma alzano la
      probabilita': un subsystem PCI virtuale (35 punti) da solo porta al
      99%, una memoria SMBIOS incompatibile (20 punti) al 62%.
      Con DUE o piu' incoerenze il logit viene alzato ad almeno ln(9), cioe'
      90%: due regole indipendenti che si contraddicono non sono rumore.

   7) p = 1 / (1 + e^(-logit)), limitata a 1..99%. Il 100% non viene mai
      mostrato: una VM con passthrough hardware o un emulatore costruito
      ad hoc puo' ingannare anche le prove dirette.

   Fasce mostrate a schermo
   ------------------------
   < 10%      bassa          -> PC fisico o indizi isolati
   10..49%    media          -> possibile VM
   50..84%    alta           -> VM probabile
   >= 85%     molto alta     -> VM molto probabile

   Le fasce sono allineate al verdetto finale: la probabilita' e' quella
   che decide l'etichetta, il punteggio resta visibile come somma dei pesi.

   Limiti
   ------
   Non e' una probabilita' calibrata con dati reali: e' un indice euristico
   coerente con i pesi del report. Serve a dare un'idea immediata, non a
   sostituire la lettura delle singole prove.
   =========================================================================== */

#include "checks.h"

#include <math.h>
#include <string.h>

#define VD_LOGIT_PRIOR       (-4.5)
#define VD_LOGIT_HYPERVISOR    1.2
#define VD_LOGIT_PER_WEIGHT    0.2
#define VD_LOGIT_PER_CATEGORY  0.4
#define VD_LOGIT_DEFINITIVE    4.6
/* Le incoerenze costano piu' di un indizio dello stesso peso: 0.25 per
   punto. Due incoerenze impongono un minimo del 90% (logit ln(9)). */
#define VD_LOGIT_PER_CONTRA   0.25
#define VD_LOGIT_CONTRA_FLOOR 2.20

void vd_probability(const VdReport *r, VdProbability *out)
{
    memset(out, 0, sizeof(*out));

    /* Categorie distinte coinvolte (confronto di puntatori: ogni modulo usa
       una costante diversa per la propria categoria). */
    const char *cats[16];
    int hit[16] = { 0 };
    int cat_count = 0;

    double logit = VD_LOGIT_PRIOR;

    for (int i = 0; i < r->count; ++i) {
        const VdCheck *c = &r->checks[i];

        int index = -1;
        for (int k = 0; k < cat_count; ++k) {
            if (cats[k] == c->category) {
                index = k;
                break;
            }
        }
        if (index < 0) {
            if (cat_count >= 16) {
                continue;
            }
            index = cat_count;
            cats[cat_count++] = c->category;
        }

        if (c->status != VDS_DETECTED) {
            continue;
        }

        ++out->detected_checks;
        hit[index] = 1;
        logit += (double)c->weight * VD_LOGIT_PER_WEIGHT;
    }

    out->contradictions = r->contradictions;
    out->contradiction_weight = r->contradiction_score;
    logit += (double)r->contradiction_score * VD_LOGIT_PER_CONTRA;

    out->total_categories = cat_count;
    for (int k = 0; k < cat_count; ++k) {
        if (hit[k]) {
            ++out->categories_hit;
        }
    }

    if (r->hypervisor_present) {
        logit += VD_LOGIT_HYPERVISOR;
    }
    if (out->categories_hit > 1) {
        logit += VD_LOGIT_PER_CATEGORY * (double)(out->categories_hit - 1);
    }
    if (r->definitive) {
        out->definitive = 1;
        if (logit < VD_LOGIT_DEFINITIVE) {
            logit = VD_LOGIT_DEFINITIVE;
        }
    }
    if (r->contradictions >= 2 && logit < VD_LOGIT_CONTRA_FLOOR) {
        logit = VD_LOGIT_CONTRA_FLOOR;
    }

    double p = 100.0 / (1.0 + exp(-logit));
    if (p < 1.0)  p = 1.0;
    if (p > 99.0) p = 99.0;

    out->logit = logit;
    out->percent = (int)(p + 0.5);

    if (out->percent < 10)       out->band = "bassa";
    else if (out->percent < 50)  out->band = "media";
    else if (out->percent < 85)  out->band = "alta";
    else                         out->band = "molto alta";
}

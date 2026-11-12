#include "checks.h"

#include <string.h>

#define VD_VERSION "1.0.0"

static HANDLE g_out;
static int g_color;

static void set_color(int attr)
{
    if (g_color) {
        SetConsoleTextAttribute(g_out, (WORD)attr);
    }
}

static void reset_color(void)
{
    set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

/* Stampa un testo con a capo automatico. "prefix" e' l'etichetta iniziale
   (es. "       metodo: ") e la continuazione viene allineata al testo. */
static void print_wrapped(const char *text, int width, const char *prefix)
{
    if (!text || !*text) {
        return;
    }

    const char *p = text;
    int indent = (int)strlen(prefix);
    int column = indent;
    printf("%s", prefix);

    while (*p) {
        const char *start = p;
        while (*p && *p != ' ') {
            ++p;
        }
        int len = (int)(p - start);
        if (len == 0) {
            ++p;
            continue;
        }
        if (column > indent && column + 1 + len > width) {
            printf("\n%*s", indent, "");
            column = indent;
        }
        if (column > indent) {
            putchar(' ');
            ++column;
        }
        fwrite(start, 1, (size_t)len, stdout);
        column += len;
        while (*p == ' ') {
            ++p;
        }
    }
    putchar('\n');
}

/* Ogni controllo viene stampato in tre parti:
     [stato] nome                      +peso
          metodo: come e' stato fatto il controllo
          esito:  cosa ha trovato
   Cosi' il report spiega da solo cosa e' stato provato e con quale tecnica. */
static void print_check(const VdCheck *c)
{
    int attr = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    const char *tag = "i";

    switch (c->status) {
    case VDS_DETECTED:
        attr = FOREGROUND_RED | FOREGROUND_INTENSITY;
        tag = "!!";
        break;
    case VDS_CONTRADICTION:
        attr = FOREGROUND_RED | FOREGROUND_INTENSITY;
        tag = "XX";
        break;
    case VDS_CLEAN:
        attr = FOREGROUND_GREEN;
        tag = "ok";
        break;
    case VDS_SKIP:
        attr = FOREGROUND_INTENSITY;
        tag = "--";
        break;
    case VDS_INFO:
    default:
        attr = FOREGROUND_RED | FOREGROUND_GREEN;
        tag = "i ";
        break;
    }

    set_color(attr);
    printf("  [%s] %-58s", tag, c->name);
    if (c->status == VDS_DETECTED && c->weight > 0) {
        printf(" +%d", c->weight);
    } else if (c->status == VDS_CONTRADICTION && c->weight > 0) {
        printf(" !%d", c->weight);
    } else {
        printf("     ");
    }
    reset_color();
    printf("\n");

    if (c->method && c->method[0]) {
        set_color(FOREGROUND_INTENSITY);
        print_wrapped(c->method, 96, "       metodo: ");
        reset_color();
    }
    if (c->evidence[0]) {
        print_wrapped(c->evidence, 96, "       esito:  ");
    }
}

static void print_os_info(void)
{
    char product[128] = "Windows";
    char display[64] = "";
    char build[32] = "";
    char ubr[32] = "";
    const wchar_t *path = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";

    vd_reg_read_sz(HKEY_LOCAL_MACHINE, path, L"ProductName", product, sizeof(product));
    vd_reg_read_sz(HKEY_LOCAL_MACHINE, path, L"DisplayVersion", display, sizeof(display));
    vd_reg_read_sz(HKEY_LOCAL_MACHINE, path, L"CurrentBuildNumber", build, sizeof(build));
    vd_reg_read_sz(HKEY_LOCAL_MACHINE, path, L"UBR", ubr, sizeof(ubr));

    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    const char *arch = "x86";
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
        arch = "x64";
    } else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) {
        arch = "ARM64";
    }

    printf("Sistema: %s%s%s (build %s%s%s) - %s\n",
           product,
           display[0] ? " " : "", display,
           build[0] ? build : "?", ubr[0] ? "." : "", ubr,
           arch);
}

static void print_header(void)
{
    SYSTEMTIME st;
    GetLocalTime(&st);

    set_color(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    printf("VirtDetect %s - rilevamento macchina fisica / virtuale\n", VD_VERSION);
    reset_color();
    printf("Data: %04u-%02u-%02u %02u:%02u:%02u\n",
           st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    print_os_info();
    printf("\n");
}

static int parse_args(int argc, char **argv)
{
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            g_verbose = 1;
        } else if (strcmp(argv[i], "--no-color") == 0) {
            g_color = 0;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Uso: VirtDetect [--verbose] [--no-color]\n\n");
            printf("  --verbose, -v   aggiunge dati grezzi (SMBIOS, BIOS, driver,\n");
            printf("                  processi, TSC); in ogni caso il report mostra\n");
            printf("                  il metodo di ogni controllo e il suo esito\n");
            printf("  --no-color      disabilita i colori\n");
            printf("  --help, -h      questo aiuto\n\n");
            printf("Codici di uscita:\n");
            printf("  0 = nessun segno di virtualizzazione (PC fisico)\n");
            printf("  1 = VM rilevata (prova diretta o combinazioni impossibili)\n");
            printf("  2 = incerto (hypervisor attivo o indizi deboli)\n");
            printf("  3 = errore interno\n");
            return 1;
        } else {
            fprintf(stderr, "Opzione sconosciuta: %s (usa --help)\n", argv[i]);
            return -1;
        }
    }
    return 0;
}

static int print_verdict(const VdReport *r)
{
    int detected = 0, clean = 0, info = 0, skip = 0;
    for (int i = 0; i < r->count; ++i) {
        switch (r->checks[i].status) {
        case VDS_DETECTED: ++detected; break;
        case VDS_CONTRADICTION: break;  /* conteggiate a parte in r->contradictions */
        case VDS_CLEAN:    ++clean; break;
        case VDS_INFO:     ++info; break;
        case VDS_SKIP:     ++skip; break;
        }
    }

    VdProbability prob;
    vd_probability(r, &prob);

    printf("\n");
    set_color(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    printf("------------------------------------------------------------\n");
    reset_color();
    printf("Controlli: %d (positivi %d, incoerenze %d, negativi %d, info %d, "
           "non eseguiti %d)\n",
           r->count, detected, r->contradictions, clean, info, skip);
    printf("Punteggio VM: %d  (somma dei pesi dei controlli positivi)\n",
           r->score);
    printf("Incoerenze: %d combinazioni impossibili (peso %d, non sommate al "
           "punteggio)\n", r->contradictions, r->contradiction_score);
    printf("Bit hypervisor CPUID: %s\n",
           r->hypervisor_present ? "presente" : "assente");

    int prob_attr = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    if (prob.percent >= 50) {
        prob_attr = FOREGROUND_RED | FOREGROUND_INTENSITY;
    } else if (prob.percent >= 10) {
        prob_attr = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    }
    set_color(prob_attr);
    printf("Probabilita' VM (euristica): %d%% [%s]\n", prob.percent, prob.band);
    reset_color();
    printf("  basata su %d controlli positivi in %d/%d categorie%s%s%s\n",
           prob.detected_checks, prob.categories_hit, prob.total_categories,
           r->hypervisor_present ? ", bit hypervisor presente" : "",
           prob.definitive ? ", prova diretta presente" : "",
           prob.contradictions ? ", combinazioni impossibili" : "");
    if (prob.contradictions) {
        printf("  piu' %d incoerenze (peso %d, contributo separato)\n",
               prob.contradictions, prob.contradiction_weight);
    }
    if (g_verbose) {
        printf("  dettaglio euristica: logit %.2f (la base senza indizi e' "
               "-4.50)\n", prob.logit);
    }

    printf("Legenda: [ok] nessuna traccia, [!!] traccia di VM (+peso), "
           "[XX] combinazione impossibile (!peso), [i ] informativo, "
           "[--] non eseguito\n");
    printf("Ogni voce riporta il metodo usato e l'esito ottenuto.\n");

    const char *verdict;
    const char *vendor = r->vendor[0] ? r->vendor : "hypervisor non identificato";
    int code;

    /* Il verdetto segue la probabilita' euristica, cosi' percentuale e
       etichetta non si contraddicono; la prova diretta ha sempre la
       precedenza. */
    if (r->definitive) {
        verdict = "VM RILEVATA (firma hypervisor diretta)";
        code = 1;
    } else if (r->contradictions >= 2) {
        verdict = "VM RILEVATA (combinazioni impossibili per un PC fisico)";
        code = 1;
    } else if (prob.percent >= 85) {
        verdict = "VM MOLTO PROBABILE";
        code = 1;
    } else if (prob.percent >= 50) {
        verdict = "VM PROBABILE";
        code = 2;
    } else if (prob.percent >= 10) {
        verdict = "POSSIBILE VM";
        code = 2;
    } else if (r->hypervisor_present) {
        verdict = "PC FISICO CON HYPERVISOR ATTIVO (Hyper-V/VBS/WSL2?)";
        code = 2;
    } else {
        verdict = "PC FISICO (nessun segno di virtualizzazione)";
        code = 0;
    }

    int verdict_attr = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    if (code == 1) {
        verdict_attr = FOREGROUND_RED | FOREGROUND_INTENSITY;
    } else if (code == 2) {
        verdict_attr = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    }

    printf("\n");
    set_color(verdict_attr);
    printf("VERDETTO: %s\n", verdict);
    if (r->definitive || r->contradictions >= 2 || prob.percent >= 50) {
        printf("Vendor probabile: %s\n", vendor);
    }
    reset_color();

    if (r->contradictions >= 2) {
        printf("Le %d incoerenze sono combinazioni che un PC fisico non puo'\n"
               "produrre: non dipendono da una firma o da una parola chiave.\n",
               r->contradictions);
    }
    if (r->hypervisor_present && prob.percent < 10) {
        printf("Nota: il bit hypervisor CPUID e' impostato anche su un PC fisico con\n"
               "Hyper-V, VBS/Device Guard, Windows Sandbox o WSL2 attivi. Senza altre\n"
               "tracce (SMBIOS, dischi, PCI, driver guest) si tratta quasi sempre del PC host.\n");
    }

    printf("Nota: nessun metodo e' affidabile al 100%% (VM indurite, nested virt,\n"
           "emulatori custom). Il report elenca le singole prove con il loro peso.\n");
    printf("La probabilita' e' un indice euristico ricavato dai pesi, non una\n"
           "misura statistica.\n");

    printf("\nCodice di uscita: %d\n", code);
    return code;
}

int main(int argc, char **argv)
{
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    g_out = GetStdHandle(STD_OUTPUT_HANDLE);

    DWORD mode = 0;
    g_color = GetConsoleMode(g_out, &mode) ? 1 : 0;

    int args = parse_args(argc, argv);
    if (args != 0) {
        return args > 0 ? 0 : 3;
    }

    vd_probe_init();

    VdReport report;
    memset(&report, 0, sizeof(report));

    print_header();

    checks_cpuid(&report);
    checks_firmware(&report);
    checks_registry(&report);
    checks_devices(&report);
    checks_timing(&report);
    checks_processes(&report);
    checks_coherence(&report);
    checks_privileged(&report);

    const char *category = NULL;
    for (int i = 0; i < report.count; ++i) {
        VdCheck *c = &report.checks[i];
        if (!category || strcmp(category, c->category) != 0) {
            category = c->category;
            printf("\n");
            set_color(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            printf("%s\n", category);
            reset_color();
        }
        print_check(c);
    }

    int exit_code = print_verdict(&report);
    reset_color();
    return exit_code;
}

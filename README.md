# VirtDetect

Piccolo programma console in **C** per Windows x64 che raccoglie, con tutte le
tecniche note, le prove che la macchina sia fisica oppure virtuale (VMware,
VirtualBox, QEMU/KVM, Hyper-V, Xen, Parallels, Bochs, bhyve, cloud/VPS).
L'uso normale non richiede privilegi di amministratore; se l'eseguibile viene
avviato come amministratore esegue in piu' il blocco **ATA IDENTIFY** sui
dischi ATA/SATA (vedi [Controlli privilegiati](#controlli-privilegiati-opzionali)).

Alla fine mostra ogni controllo con il suo peso e un verdetto complessivo.
Ogni voce del report riporta **il metodo usato** e **l'esito ottenuto**; i
sorgenti contengono la documentazione estesa di tutte le tecniche (vedi
[Documentazione nel codice](#documentazione-nel-codice)).

Oltre alle firme note, VirtDetect cerca **combinazioni impossibili su un PC
fisico** (coerenza CPU/brand, core/thread, PCI, memoria SMBIOS, inventario
firmware, seriali disco): una VM costruita per non avere firme viene comunque
scoperta quando i dati che dichiara non tornano fra loro.
La build e' **autosufficiente**: al primo avvio lo script scarica da solo la
stessa toolchain portatile usata da CindyLooper (winlibs GCC 16.2.0), senza
installare nulla nel sistema e senza toccare il PATH.

## Cosa controlla

| Area | Tecniche |
|------|----------|
| CPUID | bit hypervisor `CPUID.1:ECX[31]`, firma `0x40000000` (VMware, Hyper-V, KVM, Xen, VirtualBox, TCG, Parallels, bhyve, ACRN), brand CPU virtuale, backdoor VMware sulla porta `0x5658`, larghezza indirizzi fisici |
| Firmware | parsing della tabella **SMBIOS/DMI** (BIOS, sistema, board, chassis, UUID, moduli RAM), OEM ID delle tabelle **ACPI** (FADT + registro `HARDWARE\ACPI`), inventario tabelle con `EnumSystemFirmwareTables`, dati secondari **MSDM/thermal zone/PNP0C14**, stringhe BIOS in `HARDWARE\DESCRIPTION\System\BIOS` e `Control\SystemInformation` |
| Registro | servizi e driver **guest tools** (VMware Tools, VirtualBox Guest Additions, QEMU GA, Xen, Parallels), identificatori in `Services\Disk\Enum`, device **PCI** con vendor ID virtuali (`15AD`, `80EE`, `1AF4`, `1B36`, `5853`, `1AB8`, `1234`), device **ACPI** (`QEMU0002`, `VBOX0001`, `VMBUS`, `AMZN...`), dischi `Enum\SCSI/IDE`, programmi installati |
| Dispositivi | modello e **formato del seriale** dei dischi fisici via `IOCTL_STORAGE_QUERY_PROPERTY`, descrizione/MAC delle schede di rete, adattatore video virtuale, batteria |
| Timing | costo di `CPUID` (exit dell'hypervisor), `SIDT` "red pill", **throughput di una catena dipendente** (nativo ~1 ciclo, emulazione 10-50), confronto frequenza TSC/QPC |
| Coerenza | CPUID.1 family/model/stepping contro il nome commerciale, core/thread contro brand + topologia + SMBIOS, **device e subsystem ID PCI** contro la piattaforma, memoria SMBIOS contro la RAM di Windows, inventario SMBIOS, clamp delle foglie CPUID |
| Privilegi (opzionale) | **ATA IDENTIFY DEVICE** dei dischi ATA/SATA (modello, seriale, firmware, rotazione, NCQ, TRIM), coerenza tra livello ATA e descrizione Windows, SSD/NVMe dichiarati contro i dati reali; si attiva solo se il programma e' avviato come amministratore |
| Processi | processi dei guest tools e DLL guest caricate nel processo |

Alcune prove sono **dirette** (firma hypervisor, backdoor VMware, parametri
guest Hyper-V) e da sole determinano il verdetto; altre sono indizi con peso
diverso. Le **incoerenze** sono un canale separato: non si sommano al
punteggio, ma due o piu' combinazioni impossibili portano il verdetto a "VM
rilevata". Ogni controllo stampa il valore misurato, cosi' il risultato e'
verificabile a mano.

## Requisiti

- Windows 10 o 11 a 64 bit (testato su Windows 11 build 26200).
- Solo per la **build**: PowerShell 5.1 (incluso in Windows) e connessione a
  internet al primo avvio. `curl.exe` e `tar.exe` di sistema vengono usati se
  presenti, altrimenti lo script usa i fallback nativi di PowerShell.
- Nessun privilegio di amministratore per l'uso normale, nessuna installazione,
  nessuna modifica permanente al PATH. Il blocco ATA opzionale richiede di
  avviare l'exe come amministratore; il programma non chiede l'elevazione da
  solo.

Al primo setup lo script scarica circa **264 MB** (winlibs GCC 16.2.0
posix-seh, UCRT, x64) e occupa circa **950 MB** in `.tools\` piu' 264 MB in
`.cache\`. Le build successive sono offline. L'eseguibile finale pesa circa
100 KB e non richiede DLL MinGW.

## Build

```bat
build.cmd
```

Equivale a `scripts\build.ps1 -BuildType Release` e produce
`dist\VirtDetect.exe` con risorse di versione e link statico al runtime MinGW.

Opzioni:

```bat
build.cmd -BuildType Debug          :: -O0 -g, senza strip
build.cmd -SetupOnly                :: scarica solo la toolchain
build.cmd -Force                    :: riscarica e reinstallla la toolchain
build.cmd -GccPath C:\...\mingw64\bin   :: usa un gcc gia' presente, nessun download
build.cmd -Test                     :: esegue l'exe al termine
```

Se PowerShell blocca gli script:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build.ps1
```

Il wrapper `build.cmd` non forza `-ExecutionPolicy Bypass`: se serve, va
abilitata consapevolmente per l'utente o per il processo, come sopra.

Verifica manuale dell'hash dell'archivio scaricato:

```powershell
Get-FileHash .\.cache\downloads\winlibs-gcc-16.2.0-mingw-w64ucrt-14.0.0.zip -Algorithm SHA256
```

Deve corrispondere a
`3c69305081e4a647144339a936244fcf7d3d9e558319e1ad7be2cd2886d4b6a1`.

## Uso

```bat
dist\VirtDetect.exe
dist\VirtDetect.exe --verbose
dist\VirtDetect.exe --no-color
```

- `--verbose`, `-v`: aggiunge i dati grezzi (dettaglio SMBIOS, singole voci
  del registro, driver elencati, frequenze TSC/QPC). Il metodo e l'esito di
  ogni controllo sono mostrati comunque.
- `--no-color`: output senza colori (utile per file di log).
- `--help`, `-h`: aiuto.

Ogni controllo e' stampato in tre righe:

```
  [ok] Stringhe BIOS
       metodo: Confronta vendor, versione e data del BIOS con i firmware tipici delle VM.
       esito:  American Megatrends Inc. | P3.80 | 04/06/2018
```

`[ok]` = nessuna traccia, `[!!]` = traccia di VM (con il peso aggiunto a
destra), `[XX]` = combinazione impossibile su un PC fisico (con il peso
negativo a destra), `[i ]` = informativo, `[--]` = controllo non eseguibile.

Codici di uscita:

| Codice | Significato |
|--------|-------------|
| 0 | nessun segno di virtualizzazione (PC fisico) |
| 1 | VM rilevata (prova diretta, 2+ incoerenze o probabilita' >= 85%) |
| 2 | incerto: hypervisor attivo o indizi deboli |
| 3 | errore interno / opzione non valida |

Esempio di verdetto con prova diretta:

```
Probabilita' VM (euristica): 99% [molto alta]
  basata su 4 controlli positivi in 3/7 categorie, bit hypervisor presente,
  prova diretta presente
VERDETTO: VM RILEVATA (firma hypervisor diretta)
Vendor probabile: VMware
```

Esempio con sole incoerenze (VM senza firme note):

```
Incoerenze: 2 combinazioni impossibili (peso 65, non sommate al punteggio)
Probabilita' VM (euristica): 99% [molto alta]
  basata su 0 controlli positivi in 0/7 categorie, combinazioni impossibili
  piu' 2 incoerenze (peso 65, contributo separato)
VERDETTO: VM RILEVATA (combinazioni impossibili per un PC fisico)
```

Il pavimento del 90% scatta quando la somma dei pesi delle incoerenze e'
bassa; con due incoerenze reali (peso tipico 20-35 ciascuna) la percentuale
arriva di norma al 97-99%.

## Probabilita' euristica

Oltre al punteggio, VirtDetect calcola una percentuale che combina tutto
quello che ha trovato. Il modello e' documentato in
`src/probability.c` e riassunto qui:

1. si parte da un logit di **-4.50** (circa 1%, rischio di base di una
   macchina Windows qualsiasi);
2. **+1.20** se il bit hypervisor CPUID e' presente (da solo non prova nulla);
3. **+0.20 per ogni punto di peso** dei controlli positivi (firma CPUID 40 →
   +8.0; disco virtuale 25 → +5.0; NIC 10 → +2.0);
4. **+0.40 per ogni categoria indipendente** coinvolta oltre la prima
   (CPUID, firmware, registro, dispositivi, timing, coerenza, processi,
   privilegi ATA);
5. **+0.25 per ogni punto di peso** delle incoerenze (canale separato, non
   sommato al punteggio): un subsystem PCI virtuale da 35 punti vale +8.75;
6. una **prova diretta** (firma hypervisor reale, backdoor VMware, parametri
   guest Hyper-V) porta il logit ad almeno **+4.60**, cioe' 99%;
7. con **due o piu' incoerenze** il logit viene alzato ad almeno **+2.20**
   (90%): due regole indipendenti che si contraddicono non sono rumore;
8. `p = 1 / (1 + e^(-logit))`, limitata a 1..99% (il 100% non viene mai
   mostrato).

Fasce: `<10%` bassa, `10-49%` media, `50-84%` alta, `>=85%` molto alta.
Il verdetto segue queste fasce (`>=85%` = VM molto probabile, `>=50%` = VM
probabile, `>=10%` = possibile VM), con la prova diretta sempre in testa.
Il punteggio resta visibile come somma dei pesi grezzi.

Il modello e' un **indice euristico**, non una probabilita' calibrata su dati
reali: serve a dare un'idea immediata e a rendere coerenti percentuale,
punteggio e verdetto. Con `--verbose` viene mostrato anche il logit interno.

Valori calcolati dal modello su scenari sintetici:

| Scenario | Punteggio | Probabilita' |
|----------|-----------|--------------|
| PC fisico senza indizi | 0 | 1% |
| Host fisico con Hyper-V/VBS | 0 | 4% |
| Solo scheda di rete virtuale | 10 | 21% (con bit hypervisor) |
| Solo disco virtuale | 25 | 62-85% |
| Firma hypervisor sconosciuta | 20 | 67% |
| Backdoor VMware | 60 | 99% |
| Guest Hyper-V (`Guest\Parameters`) | 30 | 99% |
| VM VMware completa | 192 | 99% |
| Una sola incoerenza (brand vs family, 30) | 0 | 95% |
| Una sola incoerenza (memoria, 20) | 0 | 62% |
| Due incoerenze qualunque | 0 | >= 90% (pavimento; 97-99% con pesi reali) |

## Controlli di coerenza

Sono le regole pensate per una VM che non espone nessuna firma nota. Ognuna
confronta due fonti indipendenti e scatta solo quando entrambe sono
leggibili.

| Regola | Confronto | Peso |
|--------|-----------|------|
| Family/model/stepping vs brand | `CPUID.1 EAX` contro il nome commerciale (es. un i7-5820K e' family 6 model 63, non family 15) e vendor CPUID contro Intel/AMD | 30-35 |
| Core/thread vs brand | brand noto (es. 6C/12T) contro topologia `0x1F/0xB`, thread di Windows e tipo 4 SMBIOS | 20-30 |
| Subsystem PCI virtuale | `SUBSYS` con vendor `1AF4`/`1B36`/`15AD`/`80EE`... sopravvive allo spoofing di `VEN_`/`DEV_` | 35 |
| Platform/device PCI | iGPU Intel su CPU `-E` (senza GPU integrata), chipset ICH9 su X99/C610 | 25-30 |
| Memoria SMBIOS vs Windows | un modulo piu' grande della RAM totale, somma dei moduli incompatibile con `GlobalMemoryStatusEx` | 20-25 |
| Inventario SMBIOS | meno di 16 strutture con 3+ tipi mancanti fra 7/9/11/32, oppure assenza dei tipi memoria 16/17 | 12-20 |
| Clamp foglie CPUID | su Intel una foglia oltre il massimo deve restituire la foglia massima | 4 (indizio) |
| Seriale disco | un seriale che e' un percorso bus (`1-0000:00:1d.7-1`) invece del seriale del produttore | 20 |

Un controllo che non puo' essere eseguito (fonte non leggibile) viene
mostrato come `[--]`, non come `[ok]`: il report distingue "nessuna traccia"
da "non ho potuto guardare".

## Controlli privilegiati (opzionali)

Se VirtDetect viene avviato **come amministratore**, Windows concede
l'apertura in lettura/scrittura di `\\.\PhysicalDriveN` e il programma invia
anche il comando **ATA IDENTIFY DEVICE** (`0xEC`) ai dischi ATA/SATA. Senza
elevazione il blocco produce una sola riga `[--]` con il motivo e il resto
del report non cambia.

| Regola | Confronto | Peso |
|--------|-----------|------|
| Disco virtuale a livello ATA | modello, seriale o firmware restituiti da IDENTIFY contengono un marchio di virtualizzazione | 25 |
| Livelli disco incoerenti | solo uno tra descrizione Windows e IDENTIFY dichiara un disco virtuale | 30 (incoerenza) |
| SSD dichiarato ma disco rotante | il nome del disco contiene "SSD" ma la word 217 riporta almeno 1000 RPM | 20 (incoerenza) |
| NVMe su bus non NVMe | il modello contiene "NVMe" ma il bus e' ATA/SATA/SCSI/RAID | 20 (incoerenza) |

IDENTIFY fornisce anche modello, seriale, firmware, rotazione, NCQ e TRIM,
mostrati come dati `[i]`. I dischi USB sono esclusi dalla regola NVMe per non
segnalare box esterni che riportano il nome dell'unita' interna.

Il comando si esegue da un terminale gia' aperto come amministratore:

```bat
dist\VirtDetect.exe --verbose
```

Limiti dichiarati: NVMe, RAID hardware, USB e dischi VHD non supportano ATA
IDENTIFY e compaiono in una riga `[--]` con il bus, non come `[ok]`. Il
confronto e' tra due livelli del disco emulato: un hypervisor che falsifica
anche IDENTIFY (modello, seriale e rotazione credibili) non viene
smascherato da questo blocco. MSR, spazio di configurazione PCI e memoria
EBDA richiederebbero un driver kernel, non solo l'elevazione.

## Come leggere il risultato

- **Bit hypervisor + firma CPUID**: e' la prova piu' diretta, ma il solo bit
  `CPUID.1:ECX[31]` e' impostato anche su un PC fisico con **Hyper-V**, VBS /
  Device Guard, Windows Sandbox o WSL2 attivi. VirtDetect distingue i due casi:
  senza altre tracce parla di "PC fisico con hypervisor attivo".
- **Software di virtualizzazione installato sull'host**: VMware Workstation,
  VirtualBox o i driver Hyper-V installano servizi e driver sul PC fisico
  (`vmci`, `vmnet`, `pvscsi`, `VBoxNetAdp`, `VBoxUSB`, `vmbus`, `vmic`...).
  Questi non vengono conteggiati: contano solo i componenti esclusivi dei
  guest tools (`VBoxGuest`, `VBoxSF`, `vmmouse`, `vmhgfs`, `vmtools`,
  `qemu-ga`, driver Xen/Parallels, ecc.).
- **MAC OUI**: gli adattatori host-only/host virtual switch vengono esclusi
  per evitare falsi positivi; il controllo pesa poco perche' il MAC e'
  modificabile.
- **Coerenza**: sono le prove piu' difficili da falsificare per una VM
  costruita ad hoc. Non serve trovare una parola chiave: basta che due fonti
  indipendenti (CPUID, SMBIOS, registro PCI, API di Windows) dicano cose
  incompatibili. Le regole scattano solo quando entrambe le fonti sono
  leggibili, per non generare falsi positivi su hardware insolito.
- **Timing**: il costo di `CPUID` e `SIDT` sono indizi, non prove; su CPU e
  hypervisor moderni possono risultare normali anche in VM. Il throughput di
  una catena dipendente e' piu' robusto (un interprete TCG non riesce a
  eseguire una ADD per ciclo), ma non distingue un hypervisor con
  esecuzione diretta. La frequenza TSC/QPC e' solo informativa (Windows puo'
  esporre un QPC a 10 MHz anche su hardware reale).
- **Fonti non disponibili**: quando un dato non e' leggibile il controllo
  risulta `[--]` (non eseguito) con il motivo, mai `[ok]`. Esempi: `FIRM`
  bloccata da un BIOS legacy (si usa l'inventario ACPI e il registro
  `HARDWARE\ACPI`, mentre la scansione EBDA/F-segment richiede un driver
  kernel), `\\\\.\\PhysicalDriveN` non apribile da utente standard (il limite
  viene dichiarato). Un "[ok]" con dati mancanti non deve essere letto come
  prova di PC fisico.
- **Privilegi**: da utente normale il blocco ATA e' `[--]`; avviato come
  amministratore confronta il livello ATA con la descrizione Windows. Un
  modello virtuale letto da IDENTIFY pesa 25, mentre un SSD o NVMe dichiarato
  contro dati reali diversi produce un'incoerenza da 20-30.
- **Probabilita'**: e' l'indice che decide il verdetto (vedi la sezione
  precedente). Pesa i controlli positivi, le incoerenze, la varieta' delle
  categorie coinvolte e il bit hypervisor; una prova diretta la porta al 99%
  e due o piu' incoerenze impongono almeno il 90%.
- **Nessun metodo e' affidabile al 100%**: VM indurite, nested virtualization
  ed emulatori personalizzati possono nascondere o falsificare queste tracce.
  Il report permette di valutare le singole prove invece di fidarsi di un solo
  indicatore.

VirtDetect non invia dati in rete, non scrive nel registro e non modifica il
sistema: legge SMBIOS/ACPI, il registro e le API di Windows.

## Documentazione nel codice

Ogni file di rilevamento si apre con un blocco di commento che elenca i
metodi implementati, spiega come funzionano, il peso assegnato e i falsi
positivi noti. Le funzioni di controllo hanno a loro volta un commento con
il riferimento al metodo (`Metodo A`, `Metodo B`, ...) e il testo mostrato a
schermo e' una costante `M_...` dichiarata in testa al file, cosi' il
commento e l'output restano allineati.

| File | Metodi documentati |
|------|--------------------|
| `src/cpuid_checks.c` | bit hypervisor, foglia `0x40000000`, brand CPU, backdoor VMware |
| `src/firmware_checks.c` | SMBIOS (identita', BIOS, UUID, RAM, chassis), inventario ACPI, FADT ACPI, registro ACPI/BIOS, SystemInformation |
| `src/registry_checks.c` | servizi, driver su disco, chiavi guest tools, `Disk\Enum`, PCI, ACPI, SCSI/IDE, programmi installati |
| `src/device_checks.c` | dischi via IOCTL (modello e formato del seriale), NIC/MAC OUI, GPU, batteria |
| `src/timing_checks.c` | costo CPUID, SIDT "red pill", catena dipendente, TSC vs QPC |
| `src/coherence.c` | family/model/stepping vs brand, core/thread, PCI device/subsystem, memoria SMBIOS, inventario, clamp CPUID |
| `src/process_checks.c` | processi guest, DLL caricate |
| `src/privileged_checks.c` | elevazione del token, ATA IDENTIFY, coerenza livelli disco, SSD/NVMe contro dati reali |
| `src/vendor.c` | tabella delle parole chiave che identificano i vendor |

Oltre ai metodi, ogni modulo documenta nel commento iniziale i **falsi
positivi** noti e le condizioni che disattivano la regola (dati mancanti,
hardware non in tabella, UMIP attivo, ecc.).

## Struttura

```
.
├── build.cmd                 # entry point build
├── clean.cmd                 # pulizia binari / toolchain
├── scripts/
│   ├── build.ps1             # download, verifica SHA-256, build
│   └── clean.ps1
├── src/
│   ├── common.h/.c           # report, registro, probe eccezioni, TSC
│   ├── checks.h
│   ├── vendor.c              # riconoscimento marchi di virtualizzazione
│   ├── cpuid_checks.c
│   ├── firmware_checks.c     # SMBIOS, ACPI, BIOS
│   ├── registry_checks.c     # servizi, driver, PCI/ACPI, dischi
│   ├── device_checks.c       # dischi, NIC/MAC, GPU
│   ├── timing_checks.c
│   ├── coherence.c           # combinazioni impossibili (CPU, PCI, SMBIOS)
│   ├── process_checks.c
│   ├── privileged_checks.c   # ATA IDENTIFY (solo amministratore)
│   ├── probability.c         # probabilita' euristica (logit)
│   └── main.c
├── res/VirtDetect.rc         # VERSIONINFO
├── dist/                     # eseguibile compilato (ignorato da git)
├── .tools/                   # toolchain portatile (ignorata da git)
└── .cache/                   # archivio scaricato (ignorato da git)
```

## Toolchain fissata

| Strumento | Versione | Cartella |
|-----------|----------|----------|
| winlibs GCC (posix-seh, UCRT, x64) | 16.2.0 | `.tools\mingw64` |

E' lo stesso pacchetto usato da CindyLooper. Per aggiornare versione, URL,
nome file e SHA-256 si modificano i campi `$Gcc` in `scripts/build.ps1`.
Il download viene verificato prima dell'estrazione; in caso di hash errato
l'archivio viene eliminato e la build si interrompe.

## Pulizia

```bat
clean.cmd                  :: due domande: binari e toolchain
clean.cmd -Binaries        :: solo dist\ e obj\
clean.cmd -Tools           :: solo .tools\ e .cache\
clean.cmd -All             :: tutto
```

Dopo `clean.cmd -Tools`, il successivo `build.cmd` riscarica la toolchain.

## Collaudo

- Build Release e Debug verificate con GCC 16.2.0 della toolchain inclusa.
- Host di prova: Windows 11 build 26200 su ASRock X99, i7-5820K (6C/12T),
  BIOS AMI legacy, 4 moduli da 4 GB, dischi SATA reali. Risultato con
  `--verbose`: **50 controlli, 0 positivi, 0 incoerenze, 1%, "PC FISICO",
  codice 0** (senza `--verbose`: 37). La sessione di prova non era elevata,
  quindi il blocco ATA compare come `[--]` con il motivo.
  Le regole di coerenza sono state calibrate su questo host (family 6 vs
  brand Core, 6C/12T concordi su CPUID/Windows/SMBIOS, 78 device PCI con PCH
  moderno e nessun subsystem virtuale, 32 strutture SMBIOS complete, clamp
  CPUID corretto, nessun seriale disco in formato bus) e non scattano.
- Falsi positivi gia' corretti in sessioni precedenti: servizi e driver di
  VMware Workstation, VirtualBox e Hyper-V **installati sull'host** vengono
  riconosciuti come tali e non conteggiati come guest tools. Nel blocco ATA
  i dischi USB sono esclusi dalla regola NVMe e la ricerca del vendor non usa
  il seriale, per non confondere una stringa casuale con un marchio.
- Il parser ATA IDENTIFY e' stato provato con settori sintetici (SSD con
  rotazione 1, HDD a 7200 RPM, risposta ATAPI e modello vuoto): tutti i casi
  superati. Il percorso elevato con un disco reale non e' stato eseguito in
  questa sessione: avvia l'exe come amministratore per verificarlo.
- Le regole di coerenza sono state provate anche con un harness offline che
  costruisce profili sintetici: family 15 + brand i7-5820K -> incoerenza 30;
  4C/4T + brand 6C/12T -> incoerenza 30; inventario SMBIOS da 10 strutture
  -> incoerenza 20; una incoerenza da 30 -> 95%; due incoerenze -> 99% e
  pavimento a 90% verificato. I predicati PCI (`SUBSYS 1AF4`, ICH9 `2922`,
  iGPU `29C2`, piattaforma `-E`) risultano tutti attivi.
- I percorsi di rilevamento VM usano artefatti standard (SMBIOS, ACPI, PCI,
  guest tools). Il profilo avversario descritto nella specifica (CPU family
  15 con brand i7-5820K, 4C/4T, `SUBSYS_1af4`, modulo da 8 GB con 4 GB totali,
  inventario SMBIOS ridotto, seriale disco `1-0000:00:1d.7-1`) e' stato
  verificato a livello di logica, pesi e probabilita', ma **non e' stato
  eseguito dentro una VM reale** in questa sessione: provalo sul tuo
  hypervisor e confronta le singole voci.

## Licenza

PolyForm Noncommercial License 1.0.0 (vedi `LICENSE.md`): uso libero per
scopi non commerciali, senza consentire a terzi di rivendere il software o
lavori derivati.

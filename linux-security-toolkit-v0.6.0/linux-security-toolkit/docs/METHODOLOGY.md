# Metodologia di risk assessment

LSTK adotta un approccio **qualitativo probabilità × impatto** (matrice 5×5), ispirato a NIST SP 800-30 e ISO/IEC 27005.
È un'ispirazione metodologica: **LSTK non è certificato né conforme a tali standard** e non produce attestazioni di conformità.

## 1. Cosa viene valutato
Ogni controllo produce un *finding* con `status`:

| status | significato | entra nel punteggio |
|---|---|---|
| `pass` | verificato, nessun problema | no |
| `info` | informativo | no |
| `fail` | problema confermato | **sì** |
| `warn` | problema probabile/di hardening | **sì** |
| `manual` / `unknown` | **non verificato** (privilegi, strumento mancante, errore) | no, ma conteggiato come *lacuna di copertura* |

Principio cardine: **un controllo non conclusivo non è mai "sicuro"**. Viene riportato in una sezione dedicata e abbassa la copertura.

## 2. Impatto (1–5)
Derivato dalla `severity` del controllo: critical=5, high=4, medium=3, low=2, info=1.

## 3. Probabilità (1–5)
- `fail` = 4 (5 se confidenza alta); `warn` = 3; confidenza bassa: −1.
- I controlli possono impostare la probabilità in modo esplicito: es. porta esposta in rete = 4 (critica) / 3; suggerimenti Lynis e parametri di hardening = 2.
- Nmap: un servizio in ascolto **solo su loopback** non è mai un rischio di esposizione (status `info`).

## 4. Livello di rischio
`punteggio = probabilità × impatto` → **critical ≥ 20**, **high ≥ 12**, **medium ≥ 8**, **low ≥ 1**.

## 5. Punteggio di postura (0–100) e voto
`100 − Σ penalità`, con penalità per livello (peso → tetto): critical 20 → 100, high 8 → 45, medium 3 → 30, low 1 → 15.
I tetti impediscono che decine di suggerimenti a basso rischio dominino il punteggio.

Voto: **A** ≥ 90 · **B** ≥ 80 · **C** ≥ 65 · **D** ≥ 50 · **F** < 50. Limiti di onestà:
- almeno un rischio **critico** ⇒ voto non migliore di **C**;
- valutazione **parziale** (non root, modulo mancante/saltato/fallito, modalità quick/deep, copertura < 70%) ⇒ voto non migliore di **B**.

Il punteggio è **indicativo**: serve a confrontare nel tempo lo stesso sistema, non a confrontare strumenti diversi.

## 6. Moduli
| Modulo | Cosa fa | Note |
|---|---|---|
| native | ~25 controlli di sola lettura (account, SSH, firewall, kernel, filesystem, pacchetti, logging…) | alcuni richiedono root |
| nmap | scansione TCP (e UDP top-50 come root in `full`), servizi/versioni, script `default` in `full` | solo sistema locale se non diversamente indicato; nessun NSE `vuln`, nessun invio dati a terzi |
| integrity | `dpkg --verify` / `rpm -Va`: binari e librerie (bin, sbin, lib, boot) con contenuto diverso dal pacchetto; file critici mancanti | config e documentazione modificate sono attese e ignorate; non rileva file aggiunti; falsi positivi possibili (update-alternatives) |
| trivy | `trivy rootfs /`: CVE dei pacchetti OS e delle librerie, segreti nei file, OS fuori supporto | un finding per pacchetto (CVE raggruppate). Probabilità: 4 se esiste una correzione e la gravità è critical/high, 3 se esiste una correzione, 2 se non esiste. Senza database le vulnerabilità risultano **non valutate** (unknown, severità alta). Contenuto dei segreti mai riportato |
| lynis | `lynis audit system` con report in directory temporanea privata, importato come finding | senza root usa `--pentest` (copertura ridotta); severità mappata da LSTK (warning=high, suggestion=low) |

## 7. Limiti noti
Una CVE presente non implica sfruttabilità (nessuna analisi di raggiungibilità/exploitability); Nmap non correla i servizi alle CVE; solo IPv4 per Nmap; nessuna baseline CIS/SCAP; l'host compromesso può falsare i risultati; i risultati sono un'istantanea.

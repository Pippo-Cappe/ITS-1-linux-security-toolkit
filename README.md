# Linux Security Toolkit (LSTK) v0.6.0

**Assessment di sicurezza automatico per macchine Linux, con risk assessment `rischio = probabilità × impatto`.**

LSTK integra **più fonti di informazione** in un unico comando e riporta quanto rilevato in una tabella di rischio:

| Fonte | Cosa contribuisce |
|---|---|
| Controlli nativi (Python, sola lettura) | account, SSH, firewall, kernel/sysctl, permessi, SUID, logging, aggiornamenti in sospeso… |
| `dpkg --verify` / `rpm -Va` | integrità dei file installati rispetto ai pacchetti |
| [Nmap](https://nmap.org/) | porte e servizi realmente esposti in rete (distingue loopback da interfacce di rete) |
| [Trivy](https://trivy.dev) | CVE dei pacchetti e delle librerie, segreti nei file, OS fuori supporto |
| [Lynis](https://cisofy.com/lynis/) | audit di hardening, importato come finding |

> **Non è una certificazione** né un sostituto di un penetration test. Un controllo non conclusivo non viene mai presentato come "sicuro": finisce tra i *non verificati* e rende la valutazione **parziale**. Vedi [Limiti](#limiti).

## Avvio rapido (un solo comando dopo il clone)

```bash
git clone (https://github.com/Pippo-Cappe/ITS-1-linux-security-toolkit.git)
cd <ITS-1-linux-security-toolkit>
./run.sh            # al primo avvio esegue install.sh (chiede conferma prima di installare qualsiasi cosa)
```

Nel prompt `lstk` scrivi `/scan` e conferma. Per una tabella senza console interattiva: `./run.sh scan --format table`.
Se i permessi di esecuzione si perdono: `bash run.sh`.

## Esempio di output

Scansione reale (modalità `quick`, container di test):

```text
Voto: C · postura 77/100 · rischio complessivo: high
Rischi: critical: 0 · high: 2 · medium: 1 · low: 4 · Copertura conclusiva 88% · non verificati 2
⚠ Valutazione PARZIALE: modalità quick, Trivy e Lynis non eseguiti

 ID        Rischio   P  I  P×I  Esito  Fonte   Controllo
 PKG-002   high      4  4   16  warn   native  Aggiornamenti pacchetti in sospeso
 FW-001    high      4  3   12  fail   native  Nessun firewall attivo rilevato
 LOG-001   medium    3  3    9  warn   native  Servizio di logging
 KRN-001   low       2  3    6  warn   native  Parametri kernel (sysctl)
```

P = probabilità (1–5), I = impatto (1–5). Livelli: critical ≥ 20, high ≥ 12, medium ≥ 8, low ≥ 1. Metodologia completa: [docs/METHODOLOGY.md](docs/METHODOLOGY.md).

## Modalità di assessment

LSTK lavora **da dentro la macchina** (agent-less, in sola lettura). Nmap può inoltre valutare **dall'esterno** altri host (`--target`); non entra però automaticamente nella macchina remota (vedi [Sviluppi futuri](#sviluppi-futuri)).

| Modalità | Controlli nativi | Integrità file | Nmap | Trivy | Lynis |
|---|---|---|---|---|---|
| `quick` | base | no | top-1000 porte TCP | no | no |
| `deep` | estesi (SUID, world-writable, orfani, servizi) | sì | tutte le porte TCP | no | no |
| **`full`** (default) | estesi | sì | tutte le porte TCP + script `default` + UDP top-50 (se root) | sì | sì |

## Requisiti

**Sistema:** Linux (testato in container Ubuntu 24.04; Kali, Debian, Fedora, Rocky previsti, vedi [roadmap](ROADMAP.md)). Python ≥ 3.10.

**Pacchetti** (li installa `install.sh`, oppure il programma li propone quando servono): `python3`, `python3-venv`, `python3-pip`, `nmap`, `lynis`, `iproute2` (comandi `ip`/`ss`) e [Trivy](https://trivy.dev) (scaricato dalla release ufficiale con SHA-256 fissato nel codice). Dipendenze Python: `typer`, `rich`.
Nmap, Lynis e Trivy sono **opzionali**: se mancano, il modulo viene saltato e dichiarato nel rapporto.

**Privilegi:** per l'audit completo serve root (`./run.sh` usa `sudo`). Senza root funziona, ma shadow, sudoers, `sshd -T`, regole firewall, UDP e parte di Trivy/Lynis non sono verificabili → valutazione parziale (voto massimo B).

**Servizi:** nessun servizio deve essere attivo per far girare LSTK. Quelli presenti vengono *valutati*, non richiesti:
- `systemd` (`systemctl`, `timedatectl`): serve ai controlli su servizi, logging, NTP; se manca quei controlli risultano `unknown`;
- `sshd`, `ufw`/`firewalld`/nftables, `auditd`, `chrony`/`timesyncd`: se presenti vengono analizzati.

**Rete:**
- `github.com` (solo per installare Trivy) e i repository della distribuzione (solo per installare pacchetti);
- **registry OCI di Trivy** (`mirror.gcr.io` / `ghcr.io`) per scaricare il database delle vulnerabilità: senza, le vulnerabilità risultano *non valutate*. In ambienti isolati: precaricare la cache su un host connesso (`trivy image --download-db-only`), copiarla e usare `--offline` (opz. `LSTK_TRIVY_CACHE_DIR`);
- nessuna connessione ad altri servizi: Nmap contatta solo i bersagli indicati.

## Dati da inserire per provare il sistema nella sua interezza

Nessuna credenziale né API key. Parametri opzionali:

| Cosa | Come | Note |
|---|---|---|
| Profilo | `/profile server` oppure `--profile server` | influenza severità/probabilità di alcuni controlli |
| Bersaglio esterno | `/scan full --target 192.168.1.10` (anche CIDR ≤ /24, hostname) | richiede di digitare `AUTORIZZO`; in CLI `--authorized`. Solo sistemi per cui hai autorizzazione scritta |
| Firma dei rapporti | `export LSTK_SIGNING_KEY='…'` (≥ 16 caratteri) | aggiunge HMAC-SHA256; chiave fuori dal repository |
| Cartella rapporti | `LSTK_REPORT_DIR=/percorso` | default `./lstk-reports` (0700, file 0600) |
| Timeout | `LSTK_TRIVY_TIMEOUT`, `LSTK_LYNIS_TIMEOUT`, `LSTK_INTEGRITY_TIMEOUT` | secondi |

### Prova completa in una VM di laboratorio (usa-e-getta)

1. `./run.sh` e poi `/scan` → baseline.
2. Per vedere risultati più ricchi, in una VM **di test** crea condizioni deboli volute:
   ```bash
   sudo apt install -y vsftpd                                    # FTP in chiaro esposto → Nmap (high) + servizio legacy
   echo "GITHUB_TOKEN=ghp_$(tr -dc A-Za-z0-9 </dev/urandom | head -c 36)" | sudo tee /root/demo.env   # finto segreto → Trivy
   sudo cp /usr/bin/ischroot /tmp/ischroot.bak && echo x | sudo tee -a /usr/bin/ischroot             # binario alterato → integrità
   ```
3. Rilancia `/scan`, poi `/findings high`, `/details INT-001`, `/report all`, `lstk verify lstk-reports/audit-*.json`.
4. Ripristina: `sudo cp /tmp/ischroot.bak /usr/bin/ischroot; sudo apt remove -y vsftpd; sudo rm /root/demo.env`.
5. Da una seconda VM: `/scan full --target <IP della prima VM>` (valuta dall'esterno).

## Comandi

```text
/scan [quick|deep|full] [--target T] [--no-nmap|--no-lynis|--no-trivy|--no-integrity] [--offline]
/risk · /findings [issues|all|critical|high|medium|low|unverified] · /details ID
/report [json|html|all] · /verify FILE
/vuln · /integrity · /lynis        (singoli moduli)
/doctor · /install [nmap|lynis|trivy|iproute2|all]
/profile desktop|server · /checks · /status · /fix ID · /help · /exit
```

Modalità non interattiva (JSON su stdout, avanzamento su stderr):

```bash
sudo .venv/bin/lstk scan --profile server --mode full --format table      # tabella di rischio
sudo .venv/bin/lstk scan --mode full --save --fail-on high > out.json      # JSON + rapporti; exit 3 se rischio >= high
lstk install trivy --yes ; lstk doctor ; lstk verify lstk-reports/audit-*.json
```
Exit code: `0` ok · `1` errore · `2` argomenti/autorizzazione non validi · `3` soglia `--fail-on` superata.

## Sicurezza dello strumento (in sintesi)

- `/scan` è **in sola lettura**. L'unico modulo che modifica il sistema è l'installer, e solo dopo conferma esplicita (mostra i comandi esatti; in CLI richiede `--yes`/`--install-missing`).
- Trivy: release a versione fissata e **SHA-256 fissato nel codice**; se non coincide non si installa nulla. Flag `--offline-scan`; il contenuto dei segreti non viene mai riportato.
- Nessuna shell, PATH ristretto a directory di sistema, ambiente minimo, timeout con kill del gruppo di processi.
- Bersagli non locali solo con autorizzazione dichiarata; input validato.
- Rapporti 0600, SHA-256 + HMAC opzionale (`lstk verify`), elenco dei comandi eseguiti, limiti dichiarati.

Dettagli: [SECURITY.md](SECURITY.md). I rapporti contengono dati sensibili (host, account, porte, configurazioni): trattarli come riservati.

## Test

```bash
.venv/bin/pip install -e ".[test]" && .venv/bin/pytest -q     # 108 test, nessun comando reale (runner simulato)
```

## Struttura

```
install.sh / run.sh   bootstrap dopo git clone / avvio con sudo
lstk/audit.py         controlli nativi          lstk/nmapscan.py   Nmap: validazione, parsing, regole
lstk/trivy.py         CVE e segreti             lstk/lynis.py      esecuzione e import
lstk/integrity.py     dpkg/rpm verify           lstk/risk.py       probabilità × impatto, voto
lstk/scan.py          orchestratore             lstk/report.py     JSON/HTML, hash, HMAC
lstk/installer.py     installazione guidata     lstk/runner.py     esecuzione sicura
lstk/remediation.py   primitive file (non collegate ai finding)
```

## Limiti

- Valutazione best-effort: dipende da privilegi, distribuzione e strumenti installati.
- Una CVE presente non implica che sia sfruttabile; il voto non analizza raggiungibilità/exploitability. Nmap non correla i servizi alle CVE. Solo IPv4.
- L'integrità dei file non rileva file *aggiunti* né rootkit e può dare falsi positivi (es. `update-alternatives`); i segreti sono rilevati per pattern.
- Nessuna baseline CIS/SCAP né verifica di conformità (ISO 27001, PCI-DSS…).
- Le correzioni automatiche **non** sono implementate, per scelta: `/fix` non modifica nulla.
- Assessment "da fuori e poi dentro" (accesso remoto automatico) non implementato.
- Un host compromesso può falsare i risultati; hash/HMAC provano la non alterazione del rapporto, non la veridicità dei dati.

## Sviluppi futuri

Elenco completo in [ROADMAP.md](ROADMAP.md). Principali:

- **Assessment remoto agent-less**: scansione dall'esterno con Nmap seguita da ingresso automatico via SSH (con credenziali/chiavi fornite dall'operatore) per eseguire i controlli interni.
- Baseline **CIS/SCAP** e controlli di conformità.
- Correlazione CVE per i servizi rilevati da Nmap; analisi di raggiungibilità/exploitability (es. EPSS/KEV).
- Storico e confronto tra scansioni (nuovi/risolti, trend); esecuzione pianificata.
- Rilevamento rootkit e file aggiunti (AIDE, rkhunter/chkrootkit); scansione di immagini container/Kubernetes con Trivy.
- Correzioni guidate per singolo finding, con validazione per distribuzione e rollback.
- Supporto IPv6; export SARIF/CSV; test d'integrazione su Kali, Debian, Ubuntu, Fedora, Rocky; supply chain (lockfile con hash, SBOM, rilasci firmati).

## Riferimenti

- Metodologia di rischio: [NIST SP 800-30 Rev. 1 – Guide for Conducting Risk Assessments](https://csrc.nist.gov/pubs/sp/800/30/r1/final) · [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology) · ISO/IEC 27005
- Strumenti: [Nmap](https://nmap.org/book/man.html) · [Lynis](https://cisofy.com/lynis/) · [Trivy](https://trivy.dev) ([repo](https://github.com/aquasecurity/trivy))
- Vulnerabilità: [NVD](https://nvd.nist.gov/) · [CVE](https://www.cve.org/) · [CVSS](https://www.first.org/cvss/)
- Hardening: [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) · [CISOfy – controlli Lynis](https://cisofy.com/lynis/controls/)
- Librerie: [Typer](https://typer.tiangolo.com/) · [Rich](https://rich.readthedocs.io/)



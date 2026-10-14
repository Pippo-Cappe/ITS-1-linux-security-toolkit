# Sicurezza di LSTK

## Principi di progetto
1. **Sola lettura**: `/scan` non modifica il sistema (nessun fix automatico, nessun aggiornamento di indici pacchetti, nessun avvio/stop di servizi). Il modulo `remediation` non è collegato ai finding.
2. **Nessuna shell, PATH sicuro, ambiente minimo**: i comandi esterni sono eseguiti con argv come lista, binari risolti solo in `/usr/local/{s,}bin:/usr/{s,}bin:/{s,}bin` (anti PATH-hijacking quando si usa `sudo`), `stdin` chiuso, timeout con kill dell'intero gruppo di processi.
3. **Bersagli di rete**: di default si scansiona solo il sistema locale. Bersagli non locali richiedono un'autorizzazione esplicita (digitare `AUTORIZZO` in interattivo, `--authorized` in CLI) e sono registrati nel rapporto. Input validato (IPv4, CIDR ≤ /24, hostname), mai opzioni iniettabili.
4. **Rete sotto controllo**: LSTK non apre connessioni proprie. Nmap contatta solo i bersagli indicati; non vengono usati script NSE che interrogano servizi terzi (es. `vulners`). Trivy è lanciato con `--offline-scan` (nessuna API esterna per identificare le dipendenze, es. hash di JAR) e `--skip-version-check`; il solo accesso di rete è il **download del database pubblico delle vulnerabilità** dal registry OCI di Trivy (nessun file della macchina viene caricato). Con `--offline` si usa solo la cache locale e non avviene alcun download.
   Trivy e Lynis sono strumenti di terze parti: installarli da fonti ufficiali verificandone firma/checksum.
5. **Dati non fidati**: banner di servizi, report Lynis e file di configurazione sono trattati come input ostile: caratteri di controllo/ESC/bidi rimossi, markup Rich neutralizzato, HTML escapato con CSP restrittiva (`default-src 'none'`), parsing XML che rifiuta entità.
6. **Rapporti protetti**: directory `0700` (rifiuta symlink e directory scrivibili da altri), file `0600`, creazione esclusiva (`O_EXCL|O_NOFOLLOW`), hash SHA-256 (`.sha256` compatibile con `sha256sum -c` + hash interno) e **firma HMAC-SHA256 opzionale** (`LSTK_SIGNING_KEY`, ≥16 caratteri). Verifica: `lstk verify FILE`.
7. **Trasparenza**: ogni comando eseguito (argv, exit code, durata) è elencato nel rapporto.
8. **Segreti**: la ricerca di segreti riporta solo file, righe e regola; `Match` e `Code` di Trivy vengono scartati. Il report JSON temporaneo di Trivy sta in una directory 0700 rimossa al termine.
9. **Fail-safe**: un controllo che fallisce produce `unknown`, mai `pass`; un errore interno non interrompe l'audit.
10. **Dipendenze minime**: solo `typer` e `rich`.

## Installer (unico modulo che modifica il sistema)
- Mai in automatico: `/scan` mostra i comandi esatti e chiede conferma (default **No**); in CLI servono `--yes` oppure `--install-missing`.
- nmap/lynis/iproute2: dal gestore pacchetti della distribuzione (firmato). Trivy: release GitHub a versione fissata, **SHA-256 fissato nel codice**; se non coincide non viene installato nulla; si estrae solo il membro `trivy` dell'archivio; sono ammessi solo HTTPS e redirect HTTPS.
- Nessuna shell, percorsi assoluti; i privilegi (sudo) servono solo al passo di installazione, il download avviene da utente.
- `install.sh`/`run.sh`: leggere gli script prima di eseguirli. `run.sh` avvia lo strumento con sudo da un ambiente virtuale di proprietà dell'utente: chi può modificare `.venv` o il codice può far eseguire codice come root; non condividere la cartella con utenti non fidati.
- Aggiornare Trivy = modificare `TRIVY_VERSION` e `TRIVY_SHA256` in `lstk/installer.py` con i checksum ufficiali della release.

## Privilegi
Per un audit completo eseguire con `sudo "$(command -v lstk)"` (o `sudo .venv/bin/lstk`) **dopo aver verificato provenienza e integrità del pacchetto**. Senza root l'audit funziona ma è marcato *parziale*.

## Dati sensibili nei rapporti
I rapporti contengono hostname, utente, configurazioni, nomi di account, porte e servizi: **trattarli come riservati** (cifrarli a riposo, limitarne la distribuzione).

## Segnalare una vulnerabilità
Aprire una segnalazione privata al maintainer (indicare qui il contatto aziendale, es. security@vostrodominio) con versione, passi di riproduzione e impatto.

## Cosa serve prima di un uso aziendale critico
Questo repository fornisce le basi tecniche; **non sostituisce**: revisione indipendente del codice, penetration test dello strumento, firma/rilascio controllato dei pacchetti (SBOM, hash delle dipendenze), test su tutte le distribuzioni supportate, scelta della licenza e policy di supporto. Vedi `ROADMAP.md`.

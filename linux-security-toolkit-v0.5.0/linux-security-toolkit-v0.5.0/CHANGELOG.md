# Changelog

## 0.5.0
### Nuovo
- **Trivy** (`trivy rootfs /`): CVE dei pacchetti OS e delle librerie raggruppate per pacchetto, **segreti nei file** (contenuto mai riportato), OS fuori supporto. Flag privacy `--offline-scan`/`--skip-version-check`; `--offline` per usare solo la cache. Senza database: ripiego sui soli segreti e vulnerabilità dichiarate **non valutate** (valutazione parziale).
- **Integrità dei file installati** (`dpkg --verify` / `rpm -Va`): rileva binari e librerie diversi dal pacchetto e file critici mancanti; annota i link simbolici (falsi positivi tipici).
- Nuovi controlli deep: file world-writable (FS-005) e file senza proprietario (FS-006).
- Comandi `/vuln` e `/integrity`; flag `--no-trivy`, `--no-integrity`, `--offline` (anche in `lstk scan`).
- Modalità aggiornate: `deep` include l'integrità, `full` include anche Trivy.

## 0.4.0
### Nuovo
- `/scan` ora esegue un **risk assessment completo**: controlli nativi + **Nmap** + **Lynis**, con modalità `quick`, `deep`, `full` (default).
- **Risk engine**: probabilità × impatto, matrice 5×5, punteggio di postura, voto A–F, copertura e lacune "non verificato"; voto limitato se la valutazione è parziale.
- **Importazione del report Lynis** nel modello findings (warning, suggerimenti, pacchetti vulnerabili, hardening index).
- **Nmap**: validazione bersagli, autorizzazione esplicita per bersagli non locali, distinzione loopback/rete, regole di rischio per servizi noti.
- Nuovi controlli: password vuote, sudo NOPASSWD, sshd effettivo (`sshd -T`) e cifrari deboli, permessi file critici, SUID/world-writable, sysctl, MAC, logging/auditd, NTP, cifratura disco, aggiornamenti in sospeso (sola lettura), servizi legacy.
- Rapporti con **integrità** (SHA-256, HMAC opzionale), permessi 0600, `lstk verify`, elenco dei comandi eseguiti, limiti dichiarati.
- CLI non interattiva con `--fail-on` (exit code 3) per pipeline CI e `--save`.
- Comandi `/risk`, `/verify`; `/findings` con filtri.
### Sicurezza
- Runner con PATH sicuro, ambiente minimo, nessuna shell, timeout con kill del gruppo.
- Sanificazione di caratteri di controllo e markup in tutti i testi esterni; HTML con CSP.
- `remediation`: gestione symlink, proprietà preservata, fsync della directory.
### Modifiche di comportamento
- `PermitRootLogin prohibit-password|without-password` non è più segnalato come warning (consente solo chiavi).
- Il parser sshd_config usa "prima occorrenza vince", espande `Include` e ferma al primo `Match`.
- `NET-001`/`SRV-001` sono `info` (prima `pass`).
- Rimosso lo stato globale `STATE["findings"]` a favore di `STATE["assessment"]`.

## 0.3.0
Console interattiva, profili, esportazione JSON/HTML, primitive di remediation.

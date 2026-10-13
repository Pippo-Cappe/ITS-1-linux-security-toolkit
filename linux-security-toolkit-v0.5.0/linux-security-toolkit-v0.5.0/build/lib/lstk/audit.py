"""Controlli di sicurezza nativi: sola lettura, best-effort, nessuna modifica al sistema.

Ogni controllo è isolato: un errore imprevisto produce un finding "unknown" invece di
interrompere l'audit. Gli esiti non conclusivi (manual/unknown) non sono mai "pass".
"""
from __future__ import annotations

import glob
import os
import platform
import re
import socket
import stat
from dataclasses import dataclass
from pathlib import Path

from .models import Finding
from .runner import Runner, is_root

SERVICE_TOOLS = ("ufw", "firewall-cmd", "nft", "iptables")


@dataclass
class Ctx:
    profile: str
    deep: bool
    runner: Runner
    root: bool

    @property
    def server(self) -> bool:
        return self.profile == "server"

    def run(self, args, timeout=10):
        return self.runner.run(args, timeout)

    def which(self, name):
        return self.runner.which(name)


def F(fid, title, severity, status, category, evidence, recommendation, confidence="medium", **extra) -> Finding:
    return Finding(fid, title, severity, status, category, evidence, recommendation, confidence, **extra)


def _read(path: str) -> str | None:
    try:
        return Path(path).read_text(errors="replace").strip()
    except OSError:
        return None


# --------------------------------------------------------------------------- sistema
def check_system(ctx: Ctx) -> list[Finding]:
    out = [F("SYS-001", "Sistema operativo", "info", "info", "system",
             f"{platform.platform()} | kernel={platform.release()} | arch={platform.machine()} | host={socket.gethostname()}",
             "Verificare che il sistema sia supportato e riceva aggiornamenti di sicurezza.", "high")]
    container = Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()
    ev = ("Esecuzione come root (copertura completa)." if ctx.root else
          "Esecuzione come utente non privilegiato: shadow, sudoers, sshd -T e regole firewall non sono leggibili (copertura ridotta).")
    if container:
        ev += " Ambiente container rilevato: i risultati potrebbero non rappresentare l'host."
    out.append(F("SYS-003", "Contesto di esecuzione", "info", "info", "system", ev,
                 "Per un audit completo eseguire con privilegi amministrativi (sudo), dopo aver verificato provenienza e integrità dello strumento.", "high"))
    if Path("/run/reboot-required").exists():
        out.append(F("SYS-004", "Riavvio richiesto", "low", "warn", "system",
                     "Presente /run/reboot-required: aggiornamenti (es. kernel) non ancora attivi.",
                     "Pianificare il riavvio del sistema.", "high", likelihood=2))
    return out


# --------------------------------------------------------------------------- pacchetti
def _updates(ctx: Ctx, manager: str):
    """(totali, sicurezza) da cache locale degli indici; None se non determinabile."""
    if manager == "apt-get":
        r = ctx.run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"], timeout=45)
        if not r.ok:
            return None
        inst = [l for l in r.out.splitlines() if l.startswith("Inst ")]
        return len(inst), sum(1 for l in inst if "security" in l.lower())
    if manager in ("dnf", "yum"):
        r = ctx.run([manager, "-q", "--cacheonly", "check-update"], timeout=60)
        if r.timed_out or r.rc not in (0, 100):
            return None
        if r.rc == 0:
            return 0, 0

        def count(text):
            n = 0
            for line in text.splitlines():
                if line.startswith("Obsoleting"):
                    break
                if len(line.split()) >= 3:
                    n += 1
            return n
        s = ctx.run([manager, "-q", "--cacheonly", "check-update", "--security"], timeout=60)
        return count(r.out), (count(s.out) if s.rc == 100 else 0)
    if manager == "zypper":
        r = ctx.run(["zypper", "--non-interactive", "--no-refresh", "-q", "list-updates"], timeout=60)
        if not r.ok:
            return None
        return sum(1 for l in r.out.splitlines() if l.startswith("v |")), 0
    return None


def check_packages(ctx: Ctx) -> list[Finding]:
    manager = next((m for m in ("apt-get", "dnf", "yum", "zypper", "pacman") if ctx.which(m)), None)
    if not manager:
        return [F("PKG-001", "Gestore pacchetti", "medium", "unknown", "packages",
                  "Nessun gestore supportato rilevato.", "Verificare manualmente il sistema di gestione dei pacchetti.", "low")]
    out = [F("PKG-001", "Gestore pacchetti rilevato", "info", "pass", "packages", f"Trovato: {manager}",
             "Usare i repository ufficiali e applicare regolarmente gli aggiornamenti.", "high")]
    res = _updates(ctx, manager)
    if res is None:
        out.append(F("PKG-002", "Aggiornamenti pacchetti", "medium", "manual", "packages",
                     "Stato non determinabile in sola lettura (cache indici assente o gestore non supportato).",
                     f"Verificare gli aggiornamenti con {manager}. Nessun aggiornamento è stato eseguito.", "low"))
    else:
        total, sec = res
        ev = (f"Aggiornamenti disponibili (da cache locale, gli indici non vengono aggiornati): {total}, "
              f"di cui di sicurezza: {sec}.")
        if total == 0:
            out.append(F("PKG-002", "Aggiornamenti pacchetti", "medium", "pass", "packages", ev,
                         "Mantenere gli aggiornamenti automatici o pianificati.", "medium"))
        else:
            sev = "high" if sec else "medium"
            out.append(F("PKG-002", "Aggiornamenti pacchetti in sospeso", sev, "warn", "packages", ev,
                         "Applicare gli aggiornamenti (priorità a quelli di sicurezza) dopo test e finestra di manutenzione.", "medium",
                         likelihood=4 if sec else 3))
    return out


# --------------------------------------------------------------------------- firewall
def check_firewall(ctx: Ctx) -> list[Finding]:
    tools = [c for c in SERVICE_TOOLS if ctx.which(c)]
    active = []
    if ctx.which("systemctl"):
        for svc in ("ufw", "firewalld", "nftables"):
            if ctx.run(["systemctl", "is-active", svc], timeout=3).out == "active":
                active.append(svc)
    sev = "high" if ctx.server else "medium"
    reco = "Verificare policy in ingresso e regole effettive con gli strumenti firewall della distribuzione."
    base = f"Strumenti presenti: {', '.join(tools) or 'nessuno'}."
    if active:
        return [F("FW-001", "Firewall", sev, "pass", "firewall", f"{base} Servizi attivi: {', '.join(active)}.", reco,
                  "high" if ctx.root else "medium")]
    if ctx.root:
        rules = ""
        if ctx.which("nft"):
            r = ctx.run(["nft", "list", "ruleset"], timeout=8)
            if r.ok and re.search(r"hook input", r.out):
                rules += "nft: catene input presenti. "
        if ctx.which("iptables"):
            r = ctx.run(["iptables", "-S"], timeout=8)
            if r.ok and re.search(r"^-P INPUT (DROP|REJECT)|^-A INPUT ", r.out, re.M):
                rules += "iptables: policy/regole INPUT presenti. "
        if rules:
            return [F("FW-001", "Firewall", sev, "pass", "firewall", f"{base} {rules}Policy non valutata in dettaglio.", reco, "medium")]
        return [F("FW-001", "Nessun firewall attivo rilevato", sev, "fail", "firewall",
                  f"{base} Nessun servizio firewall attivo e nessuna regola di ingresso trovata.",
                  "Attivare un firewall con policy di ingresso di default deny e aprire solo le porte necessarie.", "medium")]
    return [F("FW-001", "Firewall", sev, "manual", "firewall",
              f"{base} Nessun servizio firewall attivo rilevato; le regole richiedono privilegi root.", reco, "low")]


# --------------------------------------------------------------------------- SSH
def _parse_sshd_file(path: Path, depth: int = 0) -> dict[str, str]:
    """Parser approssimato: prima occorrenza vince, Include espansi, si ferma al primo Match."""
    d: dict[str, str] = {}
    if depth > 3:
        return d
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return d
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        key, val = parts[0].lower(), parts[1].strip()
        if key == "match":
            break
        if key == "include":
            for pat in val.split():
                full = pat if os.path.isabs(pat) else os.path.join("/etc/ssh", pat)
                for m in sorted(glob.glob(full)):
                    for k, v in _parse_sshd_file(Path(m), depth + 1).items():
                        d.setdefault(k, v)
            continue
        d.setdefault(key, val)
    return d


def _sshd_effective(ctx: Ctx) -> dict[str, str] | None:
    sshd = ctx.which("sshd")
    if not sshd or not ctx.root:
        return None
    r = ctx.run([sshd, "-T"], timeout=10)
    if not r.ok:
        return None
    d: dict[str, str] = {}
    for line in r.out.splitlines():
        p = line.split(None, 1)
        if len(p) == 2:
            d.setdefault(p[0].lower(), p[1].strip())
    return d or None


WEAK_CRYPTO = ("cbc", "arcfour", "3des", "md5", "group1-sha1")


def check_ssh(ctx: Ctx) -> list[Finding]:
    cfg = Path("/etc/ssh/sshd_config")
    eff = _sshd_effective(ctx)
    if eff is None and not cfg.is_file():
        if ctx.which("sshd"):
            return [F("SSH-001", "Configurazione SSH", "medium", "unknown", "ssh",
                      "sshd presente ma configurazione non leggibile.", "Verificare la configurazione con sshd -T come root.", "low")]
        return [F("SSH-001", "Server SSH", "info", "info", "ssh", "OpenSSH server non rilevato.",
                  "Nessuna azione se il servizio non è necessario.", "medium")]
    d = eff if eff is not None else _parse_sshd_file(cfg)
    effective = eff is not None
    low = lambda k: d.get(k, "").lower()  # noqa: E731
    problems, status = [], "pass"
    if low("permitrootlogin") == "yes":
        problems.append("PermitRootLogin=yes")
        status = "fail" if effective else "warn"
    if low("permitemptypasswords") == "yes":
        problems.append("PermitEmptyPasswords=yes")
        status = "fail" if effective else "warn"
    if low("passwordauthentication") == "yes":
        problems.append("PasswordAuthentication=yes")
        if status == "pass":
            status = "warn"
    if not effective and status == "pass":
        status = "manual"
    src = ("valori effettivi (sshd -T)" if effective else
           "parser limitato al file di configurazione (Include espansi, Match ignorati); valori effettivi non confermati")
    rl = d.get("permitrootlogin", "non impostato")
    out = [F("SSH-001", "Accesso SSH (root/password)", "high", status, "ssh",
             f"PermitRootLogin={rl}; PasswordAuthentication={d.get('passwordauthentication', 'non impostato')}; "
             f"PermitEmptyPasswords={d.get('permitemptypasswords', 'non impostato')}. Fonte: {src}."
             + (f" Problemi: {', '.join(problems)}." if problems else ""),
             "Disabilitare il login root diretto e l'autenticazione a password (chiavi + MFA), poi verificare con sshd -T.",
             "high" if effective else "low")]
    issues = []
    if low("x11forwarding") == "yes":
        issues.append("X11Forwarding=yes")
    if d.get("maxauthtries", "").isdigit() and int(d["maxauthtries"]) > 6:
        issues.append(f"MaxAuthTries={d['maxauthtries']}")
    if low("permituserenvironment") == "yes":
        issues.append("PermitUserEnvironment=yes")
    if effective:
        for key in ("ciphers", "macs", "kexalgorithms"):
            weak = [a for a in d.get(key, "").split(",") if any(w in a.lower() for w in WEAK_CRYPTO)]
            if weak:
                issues.append(f"{key} deboli: {', '.join(weak[:6])}")
    if issues:
        out.append(F("SSH-002", "Hardening SSH incompleto", "medium", "warn", "ssh", "; ".join(issues),
                     "Allineare sshd_config alle linee guida (disattivare forwarding non necessari, cifrari moderni, MaxAuthTries<=4).",
                     "high" if effective else "low", likelihood=2))
    elif effective:
        out.append(F("SSH-002", "Hardening SSH", "medium", "pass", "ssh", "Nessuna impostazione debole rilevata tra quelle controllate.",
                     "Mantenere la configurazione sotto revisione periodica.", "medium"))
    return out


# --------------------------------------------------------------------------- account
def check_accounts(ctx: Ctx) -> list[Finding]:
    out: list[Finding] = []
    try:
        uid0 = []
        with open("/etc/passwd", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                p = line.rstrip("\n").split(":")
                if len(p) >= 7 and p[2] == "0":
                    uid0.append(p[0])
        out.append(F("ACC-001", "Account con UID 0", "high", "pass" if uid0 == ["root"] else "warn", "accounts",
                     ", ".join(uid0) if uid0 else "Nessun account UID 0 trovato.",
                     "Solo root dovrebbe avere UID 0.", "high"))
    except OSError as exc:
        out.append(F("ACC-001", "Account con UID 0", "medium", "unknown", "accounts",
                     f"Impossibile leggere /etc/passwd: {exc}", "Verificare manualmente gli account locali.", "low"))

    try:
        empty = []
        with open("/etc/shadow", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                p = line.rstrip("\n").split(":")
                if len(p) > 1 and p[1] == "":
                    empty.append(p[0])
        out.append(F("ACC-002", "Account senza password", "critical", "fail" if empty else "pass", "accounts",
                     ("Account con password vuota: " + ", ".join(empty)) if empty else "Nessun account con hash vuoto.",
                     "Impostare una password robusta o bloccare gli account (passwd -l).", "high"))
    except OSError:
        out.append(F("ACC-002", "Account senza password", "critical", "manual", "accounts",
                     "/etc/shadow non leggibile senza privilegi root.", "Rieseguire l'audit con privilegi amministrativi.", "low"))

    if ctx.root:
        hits = []
        files = ["/etc/sudoers", *sorted(glob.glob("/etc/sudoers.d/*"))]
        for fp in files:
            text = _read(fp)
            for line in (text or "").splitlines():
                if re.match(r"^\s*[^#\s].*NOPASSWD", line):
                    hits.append(f"{fp}: {line.strip()[:160]}")
        out.append(F("ACC-003", "Sudo senza password (NOPASSWD)", "medium", "warn" if hits else "pass", "accounts",
                     "; ".join(hits[:10]) if hits else "Nessuna regola NOPASSWD attiva trovata.",
                     "Limitare NOPASSWD ai soli comandi indispensabili e documentati.", "high"))
    else:
        out.append(F("ACC-003", "Sudo senza password (NOPASSWD)", "medium", "manual", "accounts",
                     "sudoers non leggibile senza privilegi root.", "Rieseguire l'audit con privilegi amministrativi.", "low"))

    defs = _read("/etc/login.defs")
    m = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", defs or "", re.M)
    if m:
        days = int(m.group(1))
        out.append(F("ACC-004", "Scadenza password", "low", "warn" if days > 365 else "pass", "accounts",
                     f"PASS_MAX_DAYS={days} in /etc/login.defs (vale per i nuovi account).",
                     "Definire una policy di rotazione/robustezza coerente con gli standard aziendali.", "medium", likelihood=2))
    return out


# --------------------------------------------------------------------------- filesystem
CRITICAL_FILES = [("/etc/passwd", 0o644), ("/etc/group", 0o644), ("/etc/shadow", 0o640),
                  ("/etc/gshadow", 0o640), ("/etc/ssh/sshd_config", 0o644), ("/etc/sudoers", 0o440)]


def check_filesystem(ctx: Ctx) -> list[Finding]:
    out, bad, seen = [], [], 0
    for path, maxmode in CRITICAL_FILES:
        try:
            st = os.stat(path)
        except OSError:
            continue
        seen += 1
        mode = stat.S_IMODE(st.st_mode)
        if mode & ~maxmode:
            bad.append(f"{path} modo {oct(mode)} (max {oct(maxmode)})")
        if st.st_uid != 0:
            bad.append(f"{path} non appartiene a root (uid {st.st_uid})")
    out.append(F("FS-001", "Permessi file di sistema critici", "high", "fail" if bad else "pass", "filesystem",
                 "; ".join(bad) if bad else f"{seen} file controllati: permessi e proprietario conformi.",
                 "Ripristinare permessi e proprietario (es. chmod 640 /etc/shadow; chown root).", "high"))
    mounts = _read("/proc/mounts") or ""
    tmp = next((l.split() for l in mounts.splitlines() if len(l.split()) >= 4 and l.split()[1] == "/tmp"), None)
    if tmp is None:
        out.append(F("FS-002", "Opzioni di mount /tmp", "low", "manual", "filesystem",
                     "/tmp non è un mount separato.", "Valutare partizione/tmpfs dedicata con nodev,nosuid,noexec.", "medium"))
    else:
        missing = [o for o in ("nodev", "nosuid", "noexec") if o not in tmp[3].split(",")]
        out.append(F("FS-002", "Opzioni di mount /tmp", "low", "warn" if missing else "pass", "filesystem",
                     f"/tmp montato con: {tmp[3]}" + (f"; mancano: {', '.join(missing)}" if missing else ""),
                     "Aggiungere nodev,nosuid,noexec a /tmp (verificando l'impatto sulle applicazioni).", "high", likelihood=2))
    if ctx.deep:
        out += _deep_filesystem(ctx)
    return out


def _deep_filesystem(ctx: Ctx) -> list[Finding]:
    out = []
    roots = [p for p in ("/usr", "/bin", "/sbin", "/opt", "/home", "/tmp", "/var", "/srv") if os.path.isdir(p)]
    r = ctx.run(["find", *roots, "-xdev", "-type", "f", "-perm", "-4000", "-print"], timeout=120)
    if r.timed_out or (not r.out and r.rc not in (0, 1)):
        out.append(F("FS-003", "File SUID", "medium", "unknown", "filesystem", "Ricerca non completata (timeout o errore).",
                     "Eseguire manualmente: find / -xdev -perm -4000 -type f", "low"))
    else:
        files = sorted(set(r.out.splitlines()))
        sus = [f for f in files if f.startswith(("/tmp/", "/var/tmp/", "/home/", "/dev/shm/", "/srv/"))]
        out.append(F("FS-003", "File SUID in percorsi non standard" if sus else "File SUID", "high",
                     "warn" if sus else "info", "filesystem",
                     (f"SUID in percorsi scrivibili/utente: {', '.join(sus[:15])}" if sus else
                      f"{len(files)} file SUID trovati nei percorsi di sistema (elenco da confrontare con la baseline della distribuzione)."),
                     "Rimuovere il bit SUID dove non necessario (chmod u-s) e indagare l'origine dei file sospetti.", "medium", likelihood=3))
    dirs = ["/etc", "/usr", "/opt", "/srv", "/var"]
    r = ctx.run(["find", *[d for d in dirs if os.path.isdir(d)], "-xdev", "-type", "d", "-perm", "-0002", "!", "-perm", "-1000", "-print"], timeout=120)
    if r.timed_out:
        out.append(F("FS-004", "Directory world-writable senza sticky bit", "medium", "unknown", "filesystem",
                     "Ricerca non completata (timeout).", "Eseguire manualmente la ricerca.", "low"))
    else:
        found = sorted(set(r.out.splitlines()))
        out.append(F("FS-004", "Directory world-writable senza sticky bit", "medium", "warn" if found else "pass", "filesystem",
                     (f"{len(found)} directory: " + ", ".join(found[:15])) if found else "Nessuna directory trovata nei percorsi controllati.",
                     "Rimuovere la scrittura per 'others' o impostare lo sticky bit (chmod o-w / chmod +t).", "high"))
    scan_roots = [d for d in ("/etc", "/usr", "/opt", "/srv", "/var", "/home") if os.path.isdir(d)]
    r = ctx.run(["find", *scan_roots, "-xdev", "-type", "f", "-perm", "-0002", "-print"], timeout=120)
    if r.timed_out:
        out.append(F("FS-005", "File scrivibili da tutti", "high", "unknown", "filesystem", "Ricerca non completata (timeout).",
                     "Eseguire manualmente la ricerca.", "low"))
    else:
        found = sorted(set(r.out.splitlines()))
        out.append(F("FS-005", "File scrivibili da tutti (world-writable)", "high", "warn" if found else "pass", "filesystem",
                     (f"{len(found)} file: " + ", ".join(found[:15])) if found else "Nessun file world-writable nei percorsi controllati.",
                     "Rimuovere la scrittura per 'others' (chmod o-w) e verificare l'origine dei file.", "high", likelihood=3))
    r = ctx.run(["find", *scan_roots, "-xdev", "(", "-nouser", "-o", "-nogroup", ")", "-print"], timeout=120)
    if r.timed_out:
        out.append(F("FS-006", "File senza proprietario", "medium", "unknown", "filesystem", "Ricerca non completata (timeout).",
                     "Eseguire manualmente la ricerca.", "low"))
    else:
        found = sorted(set(r.out.splitlines()))
        out.append(F("FS-006", "File senza utente/gruppo valido", "medium", "warn" if found else "pass", "filesystem",
                     (f"{len(found)} file: " + ", ".join(found[:15])) if found else "Nessun file orfano nei percorsi controllati.",
                     "Assegnare un proprietario valido o rimuovere: possono indicare account cancellati o file residui di un'intrusione.", "medium", likelihood=2))
    return out


# --------------------------------------------------------------------------- kernel
SYSCTL_CHECKS = [
    ("kernel.randomize_va_space", lambda v: v == "2", "2"),
    ("kernel.kptr_restrict", lambda v: v in ("1", "2"), "1 o 2"),
    ("kernel.dmesg_restrict", lambda v: v == "1", "1"),
    ("kernel.yama.ptrace_scope", lambda v: v.isdigit() and int(v) >= 1, ">=1"),
    ("fs.suid_dumpable", lambda v: v == "0", "0"),
    ("fs.protected_symlinks", lambda v: v == "1", "1"),
    ("fs.protected_hardlinks", lambda v: v == "1", "1"),
    ("net.ipv4.tcp_syncookies", lambda v: v == "1", "1"),
    ("net.ipv4.conf.all.rp_filter", lambda v: v in ("1", "2"), "1 o 2"),
    ("net.ipv4.conf.all.accept_redirects", lambda v: v == "0", "0"),
    ("net.ipv4.conf.all.accept_source_route", lambda v: v == "0", "0"),
    ("net.ipv4.icmp_echo_ignore_broadcasts", lambda v: v == "1", "1"),
]


def check_kernel(ctx: Ctx) -> list[Finding]:
    checks = list(SYSCTL_CHECKS)
    if not ctx.server:
        checks.append(("net.ipv4.ip_forward", lambda v: v == "0", "0"))
    dev, checked = [], 0
    for key, ok, expected in checks:
        val = _read("/proc/sys/" + key.replace(".", "/"))
        if val is None:
            continue
        checked += 1
        if not ok(val):
            dev.append(f"{key}={val} (atteso {expected})")
    if not checked:
        return [F("KRN-001", "Parametri kernel (sysctl)", "medium", "unknown", "kernel", "/proc/sys non leggibile.",
                  "Verificare i parametri con sysctl -a.", "low")]
    return [F("KRN-001", "Parametri kernel (sysctl)", "medium", "warn" if dev else "pass", "kernel",
              "; ".join(dev) if dev else f"{checked} parametri controllati: tutti conformi.",
              "Impostare i valori consigliati in /etc/sysctl.d/ e ricaricare con sysctl --system, verificando l'impatto (es. Docker richiede ip_forward=1).",
              "high", likelihood=2)]


# --------------------------------------------------------------------------- rete
def _is_loop(addr: str) -> bool:
    return addr.startswith("127.") or addr in ("[::1]", "::1")


def check_network(ctx: Ctx) -> list[Finding]:
    if not ctx.which("ss"):
        return [F("NET-001", "Socket in ascolto", "info", "unknown", "network", "Comando ss non disponibile.",
                  "Installare iproute2 o controllare le porte manualmente.", "low")]
    r = ctx.run(["ss", "-H", "-lntup"], timeout=8)
    if not r.ok:
        return [F("NET-001", "Socket in ascolto", "info", "unknown", "network", r.err or "Nessun output",
                  "Verificare manualmente i servizi in ascolto.", "low")]
    exposed = local = 0
    for line in r.out.splitlines():
        p = line.split()
        if len(p) < 5:
            continue
        addr = p[4].rsplit(":", 1)[0].split("%")[0]
        if _is_loop(addr):
            local += 1
        else:
            exposed += 1
    return [F("NET-001", "Socket in ascolto", "info", "info", "network",
              f"{exposed} socket su interfacce non-loopback, {local} solo loopback.\n{r.out[:6000]}",
              "Riconoscere ogni porta/servizio esposto e disabilitare solo ciò che non è necessario. La scansione Nmap valuta il rischio di esposizione.",
              "high")]


# --------------------------------------------------------------------------- hardening di sistema
def check_hardening(ctx: Ctx) -> list[Finding]:
    out = []
    sel = _read("/sys/fs/selinux/enforce")
    aa = _read("/sys/module/apparmor/parameters/enabled")
    sev = "medium" if ctx.server else "low"
    if sel == "1":
        out.append(F("MAC-001", "Controllo di accesso obbligatorio", sev, "pass", "hardening", "SELinux in modalità enforcing.",
                     "Mantenere enforcing.", "high"))
    elif aa and aa.upper().startswith("Y"):
        out.append(F("MAC-001", "Controllo di accesso obbligatorio", sev, "pass", "hardening", "AppArmor abilitato.",
                     "Verificare che i profili dei servizi esposti siano in enforce.", "high"))
    else:
        out.append(F("MAC-001", "Nessun MAC attivo (SELinux/AppArmor)", sev, "warn", "hardening",
                     "SELinux non in enforcing e AppArmor non abilitato." if sel is not None or aa is not None else
                     "Né SELinux né AppArmor rilevati.",
                     "Abilitare SELinux (enforcing) o AppArmor, se supportati dalla distribuzione.", "medium", likelihood=2))
    if ctx.which("systemctl"):
        act = lambda s: ctx.run(["systemctl", "is-active", s], timeout=3).out == "active"  # noqa: E731
        logs = [s for s in ("systemd-journald", "rsyslog", "syslog-ng") if act(s)]
        out.append(F("LOG-001", "Servizio di logging", "medium", "pass" if logs else "warn", "logging",
                     f"Attivi: {', '.join(logs)}." if logs else "Nessun servizio di logging attivo rilevato.",
                     "Garantire log persistenti e, in ambito aziendale, inoltro centralizzato.", "medium"))
        aud = act("auditd")
        if aud:
            out.append(F("AUD-001", "Auditing (auditd)", "low", "pass", "logging", "auditd attivo.", "Mantenere regole di audit allineate alla policy.", "high"))
        elif ctx.server:
            out.append(F("AUD-001", "auditd non attivo", "low", "warn", "logging", "auditd non risulta attivo.",
                         "Valutare auditd per tracciare accessi privilegiati e modifiche a file sensibili.", "medium", likelihood=2))
        else:
            out.append(F("AUD-001", "Auditing (auditd)", "info", "info", "logging", "auditd non attivo (profilo desktop).",
                         "Facoltativo su workstation.", "medium"))
    r = ctx.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], timeout=5)
    if r.ok and r.out in ("yes", "no"):
        out.append(F("TIME-001", "Sincronizzazione oraria", "low", "pass" if r.out == "yes" else "warn", "time",
                     f"NTPSynchronized={r.out}", "Usare NTP/chrony: tempi coerenti sono indispensabili per log e forensics.", "high", likelihood=2))
    else:
        out.append(F("TIME-001", "Sincronizzazione oraria", "low", "unknown", "time", "Stato non determinabile.",
                     "Verificare chrony/systemd-timesyncd.", "low"))
    r = ctx.run(["lsblk", "-rno", "TYPE"], timeout=5)
    if r.ok:
        enc = "crypt" in r.out.split()
        out.append(F("ENC-001", "Cifratura del disco", "low", "pass" if enc else ("manual" if ctx.server else "warn"), "hardening",
                     "Volumi cifrati (dm-crypt/LUKS) rilevati." if enc else "Nessun volume cifrato rilevato.",
                     "Su portatili e dati sensibili usare LUKS/cifratura completa del disco.", "medium", likelihood=2))
    return out


# --------------------------------------------------------------------------- integrazioni e servizi
def check_integrations(ctx: Ctx) -> list[Finding]:
    p = ctx.which("lynis")
    return [F("LYN-001", "Disponibilità Lynis", "info", "pass" if p else "manual", "integrations",
              f"lynis: {p or 'non trovato nelle directory di sistema'}",
              "Lynis viene eseguito da /scan (modalità full) o /lynis, sempre in sola lettura.", "high")]


LEGACY_SERVICES = ("telnet", "rsh", "rlogin", "rexec", "tftp", "xinetd", "ypserv", "talk", "vsftpd", "proftpd", "pure-ftpd")


def check_services(ctx: Ctx) -> list[Finding]:
    out = []
    if ctx.which("systemctl"):
        r = ctx.run(["systemctl", "list-unit-files", "--state=enabled", "--no-pager"], timeout=10)
    else:
        r = None
    if r is None or not r.ok:
        out.append(F("SRV-001", "Servizi abilitati", "medium", "unknown", "services",
                     (r.err if r else "systemctl assente") or "Nessun output",
                     "Elencare manualmente i servizi abilitati.", "low"))
    else:
        out.append(F("SRV-001", "Servizi abilitati", "info", "info", "services", r.out[:6000],
                     "Rivedere i servizi abilitati e disabilitare quelli non necessari dopo averne verificato l'impatto.", "medium"))
        names = [l.split()[0] for l in r.out.splitlines() if l.strip()]
        legacy = [n for n in names if any(n.lower().startswith(s) for s in LEGACY_SERVICES)]
        out.append(F("SRV-002", "Servizi legacy/in chiaro abilitati", "high", "warn" if legacy else "pass", "services",
                     ("Abilitati: " + ", ".join(legacy)) if legacy else "Nessun servizio legacy noto tra quelli abilitati.",
                     "Sostituire con alternative cifrate (SSH/SFTP) o disabilitare.", "high"))
    out.append(F("SYS-002", "Profilo selezionato", "info", "info", "system",
                 f"Profilo: {ctx.profile}; modalità approfondita: sì.",
                 "Il profilo orienta severità e probabilità in alcuni controlli; non sostituisce una baseline specifica per la distribuzione.", "high"))
    return out


CHECKS = [check_system, check_packages, check_firewall, check_ssh, check_accounts, check_filesystem,
          check_kernel, check_network, check_hardening, check_integrations]


def collect(profile: str = "desktop", deep: bool = False, runner: Runner | None = None) -> list[Finding]:
    ctx = Ctx(profile, deep, runner or Runner(), is_root())
    checks = CHECKS + ([check_services] if deep else [])
    results: list[Finding] = []
    for chk in checks:
        try:
            results.extend(chk(ctx))
        except Exception as exc:  # un controllo non deve mai interrompere l'audit
            name = chk.__name__.removeprefix("check_").upper()
            results.append(F(f"ERR-{name}", f"Errore nel controllo {name.lower()}", "medium", "unknown", "internal",
                             f"{type(exc).__name__}: {exc}", "Segnalare il problema agli sviluppatori allegando la versione dello strumento.", "low"))
    return results

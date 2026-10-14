"""Installazione guidata degli strumenti mancanti (nmap, lynis, trivy, iproute2).

Questo modulo è l'UNICO che modifica il sistema, e solo su richiesta esplicita dell'utente:
- mai in automatico: la CLI mostra i comandi esatti e chiede conferma (o richiede --yes / --install-missing);
- nmap, lynis, iproute2: dai repository ufficiali della distribuzione (apt / dnf / yum / zypper / pacman), firmati dal gestore pacchetti;
- trivy: release ufficiale GitHub a versione FISSATA, con SHA-256 FISSATO nel codice (non scaricato dallo stesso sito del file):
  se l'hash non coincide, nulla viene installato;
- nessuna shell: argv come lista, percorsi assoluti, ambiente minimo; i privilegi si ottengono con sudo solo per il passo che li richiede.
"""
from __future__ import annotations

import hashlib
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .runner import SAFE_PATH, Runner

# Per aggiornare Trivy: scegliere una release su https://github.com/aquasecurity/trivy/releases, leggere i checksum dal file
# trivy_<versione>_checksums.txt della stessa release (idealmente verificandone la firma cosign) e aggiornare le due costanti.
TRIVY_VERSION = "0.75.0"
TRIVY_SHA256 = {
    "64bit": "c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f",
    "ARM64": "a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3",
}
ARCH = {"x86_64": "64bit", "amd64": "64bit", "aarch64": "ARM64", "arm64": "ARM64"}
MAX_DOWNLOAD = 200_000_000
MAX_BINARY = 600_000_000
DEFAULT_DEST = "/usr/local/bin"

MANAGERS = ("apt-get", "dnf", "yum", "zypper", "pacman")


class InstallError(RuntimeError):
    pass


@dataclass(frozen=True)
class Tool:
    name: str
    binary: str
    description: str
    packages: dict = field(default_factory=dict)   # gestore -> nome pacchetto; vuoto = download diretto
    download: bool = False


TOOLS = {
    "nmap": Tool("nmap", "nmap", "scansione porte e servizi", {m: "nmap" for m in MANAGERS}),
    "lynis": Tool("lynis", "lynis", "audit di hardening", {m: "lynis" for m in MANAGERS}),
    "iproute2": Tool("iproute2", "ss", "comandi ip/ss (rete locale)",
                     {"apt-get": "iproute2", "dnf": "iproute", "yum": "iproute", "zypper": "iproute2", "pacman": "iproute2"}),
    "trivy": Tool("trivy", "trivy", f"vulnerabilità e segreti (release ufficiale v{TRIVY_VERSION}, hash SHA-256 fissato)", download=True),
}
ALL = tuple(TOOLS)


@dataclass
class Step:
    tool: str            # nome strumento o "pacchetti"
    description: str
    argv: list | None = None        # comando da eseguire (con privilegi)
    download: bool = False          # passo di download verificato (Trivy)
    optional: bool = False          # un errore non blocca i passi successivi (es. apt-get update)


@dataclass
class InstallResult:
    tool: str
    ok: bool
    detail: str
    method: str = ""
    at: str = ""

    def to_dict(self) -> dict:
        return {"tool": self.tool, "ok": self.ok, "detail": self.detail, "method": self.method, "at": self.at}


def missing_tools(runner: Runner, names=ALL) -> list[str]:
    return [n for n in names if n in TOOLS and not runner.which(TOOLS[n].binary)]


def detect_manager(runner: Runner) -> str | None:
    return next((m for m in MANAGERS if runner.which(m)), None)


def _abs(runner: Runner, name: str) -> str:
    path = runner.which(name)
    if not path:
        raise InstallError(f"comando non trovato: {name}")
    return path


def plan_install(runner: Runner, names) -> list[Step]:
    """Costruisce i passi di installazione per gli strumenti richiesti (non esegue nulla)."""
    unknown = [n for n in names if n not in TOOLS]
    if unknown:
        raise InstallError("strumenti sconosciuti: " + ", ".join(unknown) + f" (disponibili: {', '.join(ALL)})")
    steps: list[Step] = []
    pkg_tools = [n for n in names if not TOOLS[n].download]
    if pkg_tools:
        mgr = detect_manager(runner)
        if mgr is None:
            raise InstallError("nessun gestore pacchetti supportato (apt-get, dnf, yum, zypper, pacman): installare " +
                               ", ".join(pkg_tools) + " manualmente.")
        pkgs = sorted({TOOLS[n].packages[mgr] for n in pkg_tools})
        exe = _abs(runner, mgr)
        label = "pacchetti: " + ", ".join(pkgs)
        if mgr == "apt-get":
            steps.append(Step("pacchetti", "aggiorna l'elenco dei pacchetti", [exe, "update"], optional=True))
            steps.append(Step("pacchetti", f"installa {label} dal repository della distribuzione", [exe, "install", "-y", *pkgs]))
        elif mgr in ("dnf", "yum"):
            steps.append(Step("pacchetti", f"installa {label} dal repository della distribuzione", [exe, "install", "-y", *pkgs]))
        elif mgr == "zypper":
            steps.append(Step("pacchetti", f"installa {label} dal repository della distribuzione", [exe, "--non-interactive", "install", *pkgs]))
        else:
            steps.append(Step("pacchetti", f"installa {label} dal repository della distribuzione", [exe, "-S", "--noconfirm", "--needed", *pkgs]))
    if "trivy" in names:
        steps.append(Step("trivy", f"scarica Trivy v{TRIVY_VERSION} da github.com, verifica lo SHA-256 fissato e installa in {DEFAULT_DEST}/trivy",
                          None, True))
    return steps


def _env() -> dict:
    env = {"PATH": SAFE_PATH, "LC_ALL": "C", "LANG": "C", "DEBIAN_FRONTEND": "noninteractive"}
    for k in ("HOME", "TERM"):
        if k in os.environ:
            env[k] = os.environ[k]
    return env


def _exec(argv: list[str], to_stderr: bool = False) -> int:
    """Esegue il comando ereditando il terminale (così sudo può chiedere la password e si vede l'avanzamento)."""
    out = sys.stderr if to_stderr else None
    return subprocess.run(argv, env=_env(), stdout=out, check=False).returncode


def _privileged(argv: list[str], root: bool, runner: Runner) -> list[str]:
    if root:
        return argv
    sudo = runner.which("sudo")
    if not sudo:
        raise InstallError("servono privilegi di amministratore e 'sudo' non è disponibile: rieseguire come root.")
    return [sudo, "--", *argv]


# --------------------------------------------------------------------------- download verificato
class _HttpsOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            raise urllib.error.URLError(f"reindirizzamento non HTTPS rifiutato: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_file(url: str, dest: str, max_bytes: int = MAX_DOWNLOAD) -> str:
    """Scarica via HTTPS (certificato verificato, solo redirect HTTPS) e ritorna lo SHA-256."""
    if not url.lower().startswith("https://"):
        raise InstallError("solo URL HTTPS ammessi")
    opener = urllib.request.build_opener(_HttpsOnly)
    h, total = hashlib.sha256(), 0
    try:
        with opener.open(urllib.request.Request(url, headers={"User-Agent": "lstk-installer"}), timeout=60) as resp, \
                open(dest, "wb") as out:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise InstallError("download troppo grande: interrotto")
                h.update(chunk)
                out.write(chunk)
    except (urllib.error.URLError, OSError) as exc:
        raise InstallError(f"download fallito: {exc}") from exc
    return h.hexdigest()


def install_trivy(runner: Runner, *, root: bool, dest_dir: str = DEFAULT_DEST, machine: str | None = None,
                  fetch=fetch_file, exec_fn=_exec, to_stderr: bool = False) -> str:
    arch = ARCH.get((machine or platform.machine()).lower())
    if not arch:
        raise InstallError(f"architettura non supportata dall'installer ({machine or platform.machine()}): installare Trivy manualmente da https://trivy.dev")
    expected = TRIVY_SHA256[arch]
    url = f"https://github.com/aquasecurity/trivy/releases/download/v{TRIVY_VERSION}/trivy_{TRIVY_VERSION}_Linux-{arch}.tar.gz"
    tmp = tempfile.mkdtemp(prefix="lstk-install-")   # 0700
    try:
        archive = os.path.join(tmp, "trivy.tar.gz")
        got = fetch(url, archive)
        if got != expected:
            raise InstallError(f"SHA-256 NON coincide (atteso {expected[:12]}…, ottenuto {got[:12]}…): file scartato, NULLA è stato installato.")
        binary = os.path.join(tmp, "trivy")
        try:
            with tarfile.open(archive, "r:gz") as tf:
                member = tf.getmember("trivy")            # solo questo membro, per nome esatto: niente estrazione di percorsi arbitrari
                if not member.isfile() or member.size > MAX_BINARY:
                    raise InstallError("contenuto dell'archivio non valido")
                src = tf.extractfile(member)
                fd = os.open(binary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o755)
                with os.fdopen(fd, "wb") as out:
                    shutil.copyfileobj(src, out)
        except (KeyError, tarfile.TarError, OSError) as exc:
            raise InstallError(f"archivio non valido: {exc}") from exc
        target = os.path.join(dest_dir, "trivy")
        argv = _privileged([_abs(runner, "install"), "-m", "0755", binary, target], root, runner)
        if exec_fn(argv, to_stderr) != 0:
            raise InstallError("installazione del binario non riuscita")
        return target
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------- esecuzione
def run_install(runner: Runner, steps: list[Step], *, root: bool, log=print, to_stderr: bool = False,
                exec_fn=_exec, fetch=fetch_file, dest_dir: str = DEFAULT_DEST, names=ALL) -> list[InstallResult]:
    """Esegue i passi in ordine; si ferma al primo errore. Verifica poi che i binari siano comparsi."""
    results: list[InstallResult] = []
    stamp = lambda: time.strftime("%Y-%m-%dT%H:%M:%S%z")  # noqa: E731
    pkg_ok = True
    for step in steps:
        try:
            if step.download:
                log(f"→ {step.description}")
                target = install_trivy(runner, root=root, dest_dir=dest_dir, fetch=fetch, exec_fn=exec_fn, to_stderr=to_stderr)
                results.append(InstallResult("trivy", True, f"installato in {target}", f"download verificato v{TRIVY_VERSION}", stamp()))
            else:
                argv = _privileged(step.argv, root, runner)
                log(f"→ {' '.join(argv)}")
                rc = exec_fn(argv, to_stderr)
                if rc != 0 and step.optional:
                    log(f"  (avviso: il passo è terminato con codice {rc}, si prosegue)")
                elif rc != 0:
                    pkg_ok = False
                    results.append(InstallResult(step.tool, False, f"comando terminato con codice {rc}", "gestore pacchetti", stamp()))
                    break
        except InstallError as exc:
            results.append(InstallResult(step.tool, False, str(exc), "download verificato" if step.download else "gestore pacchetti", stamp()))
            if not step.download:
                pkg_ok = False
                break
    if pkg_ok:
        for n in names:
            t = TOOLS.get(n)
            if t and not t.download and n in _planned(steps):
                found = runner.which(t.binary)
                results.append(InstallResult(n, bool(found), found or "installato ma non trovato nelle directory di sistema", "gestore pacchetti", stamp()))
    return results


def _planned(steps: list[Step]) -> set[str]:
    names: set[str] = set()
    for s in steps:
        if s.argv:
            names |= {n for n, t in TOOLS.items() if not t.download and any(p in s.argv for p in t.packages.values())}
    return names

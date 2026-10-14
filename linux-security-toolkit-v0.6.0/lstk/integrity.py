"""Verifica dell'integrità dei file installati dai pacchetti (dpkg --verify / rpm -Va). Sola lettura.

Confronta i file di sistema con i metadati del database dei pacchetti: un binario o una libreria con
contenuto diverso dal pacchetto può indicare manomissione (o modifica manuale non tracciata).
Limite: non rileva file *aggiunti* da un attaccante né una manomissione del database dei pacchetti stesso.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

from .models import Finding
from .runner import Runner

INTEGRITY_TIMEOUT = int(os.environ.get("LSTK_INTEGRITY_TIMEOUT", "900"))
CRITICAL_PREFIXES = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/lib64/", "/lib/", "/lib64/",
                     "/usr/libexec/", "/boot/")
_LINE = re.compile(r"^(missing|\S{8,9})\s+(?:([cdglr])\s+)?(/.*)$")


@dataclass
class IntegrityOutcome:
    findings: list
    status: str     # ok | skipped | failed
    detail: str


def parse_verify(text: str) -> tuple[list[str], list[str], int]:
    """Ritorna (file critici modificati, file critici mancanti, config/doc modificati)."""
    modified, missing, benign = [], [], 0
    for line in text.splitlines():
        m = _LINE.match(line.rstrip())
        if not m:
            continue
        flags, attr, path = m.groups()
        if attr in ("c", "d", "l", "g", "r") or not path.startswith(CRITICAL_PREFIXES):
            if flags != "missing":
                benign += 1
            continue
        if flags == "missing":
            missing.append(path)
        elif len(flags) >= 3 and flags[2] == "5":
            modified.append(path)
    return sorted(set(modified)), sorted(set(missing)), benign


def run_integrity(runner: Runner, *, root: bool) -> IntegrityOutcome:
    if runner.which("dpkg"):
        cmd, tool = ["dpkg", "--verify"], "dpkg --verify"
    elif runner.which("rpm"):
        cmd, tool = ["rpm", "-Va"], "rpm -Va"
    else:
        f = Finding("INT-001", "Integrità dei file di pacchetto", "high", "manual", "integrity",
                    "Né dpkg né rpm disponibili: verifica non supportata su questo sistema.",
                    "Usare lo strumento della distribuzione (es. 'pacman -Qkk') o un controllo di integrità dei file (AIDE/Tripwire).", "low")
        return IntegrityOutcome([f], "skipped", "gestore pacchetti non supportato")
    r = runner.run(cmd, timeout=INTEGRITY_TIMEOUT)
    if r.timed_out or (r.rc not in (0, 1) and not r.out):
        msg = f"Timeout dopo {INTEGRITY_TIMEOUT}s." if r.timed_out else f"{tool} non completato (exit {r.rc}): {r.err[:300]}"
        f = Finding("INT-001", "Integrità dei file di pacchetto", "high", "unknown", "integrity", msg,
                    f"Eseguire manualmente '{tool}'.", "low")
        return IntegrityOutcome([f], "failed", msg)
    modified, missing, benign = parse_verify(r.out)
    note = "" if root else " Eseguito senza root: i file non leggibili non sono stati verificati."
    out = []
    if modified:
        shown = [m + (" [link simbolico: possibile update-alternatives]" if os.path.islink(m) else "") for m in modified[:20]]
        out.append(Finding("INT-001", "File di sistema con contenuto diverso dal pacchetto", "high", "fail", "integrity",
                           f"{len(modified)} file: " + ", ".join(shown) + (" …" if len(modified) > 20 else "") +
                           f" (verifica: {tool}). Possibile manomissione o modifica manuale non tracciata.{note}",
                           "Se le modifiche non sono attese trattarle come potenziale compromissione: isolare l'host, preservare le prove, "
                           "reinstallare i pacchetti interessati da fonte attendibile e indagare.", "medium", likelihood=4))
    else:
        out.append(Finding("INT-001", "Integrità dei file di pacchetto", "high", "pass", "integrity",
                           f"Nessun file critico (bin, sbin, lib) con contenuto diverso dal pacchetto; {benign} modifiche a configurazioni/documentazione (attese).{note}",
                           "Complementare con un controllo di integrità continuo (AIDE/Tripwire) per rilevare anche file aggiunti.",
                           "medium" if root else "low"))
    if missing:
        out.append(Finding("INT-002", "File di sistema critici mancanti", "medium", "warn", "integrity",
                           f"{len(missing)} file: " + ", ".join(missing[:20]) + (" …" if len(missing) > 20 else ""),
                           "Verificare se rimozioni intenzionali; altrimenti reinstallare i pacchetti.", "medium", likelihood=3))
    return IntegrityOutcome(out, "ok", f"{tool}: {len(modified)} modificati, {len(missing)} mancanti, {benign} config/doc")

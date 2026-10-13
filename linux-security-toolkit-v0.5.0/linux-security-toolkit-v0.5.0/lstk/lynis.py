"""Integrazione Lynis: esecuzione in sola lettura e importazione del report nel modello findings.

Lynis scrive il proprio report (report.dat) in una directory temporanea privata (0700) che viene
rimossa al termine. Senza root viene usata la modalità non privilegiata (--pentest): copertura ridotta.
La severità è una mappatura di LSTK (Lynis non assegna gravità): warning -> high, suggestion -> low.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass, field

from .models import Finding, sanitize
from .runner import Runner

LYNIS_TIMEOUT = int(os.environ.get("LSTK_LYNIS_TIMEOUT", "900"))

CATEGORY = {
    "AUTH": "accounts", "ACCT": "accounting", "SSH": "ssh", "KRNL": "kernel", "FIRE": "firewall", "NETW": "network",
    "PKGS": "packages", "FILE": "filesystem", "LOGG": "logging", "BOOT": "boot", "USB": "devices", "STRG": "storage",
    "TIME": "time", "CRYP": "crypto", "SHLL": "shell", "HRDN": "hardening", "MALW": "malware", "NAME": "dns",
    "MAIL": "mail", "WEBS": "webserver", "DBS": "database", "PHP": "php", "CONT": "containers", "TOOL": "tools",
    "HOME": "home", "INSE": "services", "BANN": "banners", "SQD": "proxy", "SNMP": "snmp", "PRNT": "printing",
    "LDAP": "ldap", "NFS": "nfs", "FINT": "integrity", "DEB": "packages", "RHEL": "packages", "LYNIS": "lynis",
}


@dataclass
class LynisReport:
    version: str = ""
    hardening_index: int | None = None
    tests_done: int | None = None
    warnings: list = field(default_factory=list)       # (id, text, details, solution)
    suggestions: list = field(default_factory=list)
    vulnerable_packages: list = field(default_factory=list)


def _entry(value: str) -> tuple[str, str, str, str]:
    p = (value.split("|") + ["", "", "", ""])[:4]
    clean = lambda s: "" if s.strip() in ("-", "") else s.strip()  # noqa: E731
    return p[0].strip(), clean(p[1]), clean(p[2]), clean(p[3])


def parse_report(text: str) -> LynisReport:
    rep = LynisReport()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key == "warning[]":
            rep.warnings.append(_entry(value))
        elif key == "suggestion[]":
            rep.suggestions.append(_entry(value))
        elif key == "vulnerable_package[]":
            rep.vulnerable_packages.append(value.strip())
        elif key == "hardening_index" and value.strip().isdigit():
            rep.hardening_index = int(value)
        elif key == "lynis_version":
            rep.version = value.strip()
        elif key == "lynis_tests_done" and value.strip().isdigit():
            rep.tests_done = int(value)
    return rep


def _category(test_id: str) -> str:
    return CATEGORY.get(test_id.split("-")[0], "lynis")


def report_to_findings(rep: LynisReport) -> list[Finding]:
    out: list[Finding] = []
    seen = set()
    used_ids: set[str] = set()
    for kind, entries, sev, status, lik in (("warning", rep.warnings, "high", "fail", 0),
                                             ("suggestion", rep.suggestions, "low", "warn", 2)):
        for tid, text, details, solution in entries:
            if (tid, text) in seen or not tid:
                continue
            if tid == "PKGS-7392" and rep.vulnerable_packages:
                continue   # sostituito da LYN-VULNPKG, che elenca i pacchetti (evita doppio conteggio)
            seen.add((tid, text))
            fid = f"LYN-{sanitize(tid, 40)}"
            if fid in used_ids:                       # ID univoci: /details deve essere non ambiguo
                n = 2
                while f"{fid}-{n}" in used_ids:
                    n += 1
                fid = f"{fid}-{n}"
            used_ids.add(fid)
            ev = f"Segnalato da Lynis come {kind} (test {tid}): {text or 'nessuna descrizione'}"
            if details:
                ev += f" | Dettagli: {details}"
            out.append(Finding(
                fid, (text or f"Test Lynis {tid}")[:140], sev, status, _category(tid), ev,
                solution or "Consultare la scheda del controllo Lynis per i passi di rimedio.", "medium", source="lynis",
                likelihood=lik, references=[f"https://cisofy.com/lynis/controls/{sanitize(tid, 40)}/"]))
    if rep.vulnerable_packages:
        out.append(Finding("LYN-VULNPKG", "Pacchetti vulnerabili segnalati da Lynis", "high", "fail", "packages",
                           f"{len(rep.vulnerable_packages)} pacchetti: " + ", ".join(rep.vulnerable_packages[:30]),
                           "Aggiornare i pacchetti indicati e verificare con il gestore pacchetti.", "medium", source="lynis"))
    idx = rep.hardening_index
    out.insert(0, Finding("LYN-INDEX", "Indice di hardening Lynis", "info", "info" if idx is not None else "unknown", "lynis",
                          (f"Hardening index: {idx}/100; test eseguiti: {rep.tests_done}; Lynis {rep.version}. "
                           "L'indice è calcolato da Lynis e non è confrontabile con il punteggio di postura LSTK.")
                          if idx is not None else "Report Lynis privo di hardening_index.",
                          "Usare l'indice come indicatore di tendenza, non come metrica di conformità.", "high", source="lynis"))
    return out


@dataclass
class LynisOutcome:
    findings: list
    status: str      # ok | skipped | failed
    detail: str
    hardening_index: int | None = None


def run_lynis(runner: Runner, *, root: bool) -> LynisOutcome:
    lynis = runner.which("lynis")
    if not lynis:
        f = Finding("LYN-000", "Audit Lynis non eseguito", "medium", "manual", "lynis",
                    "lynis non è installato (ricerca solo in directory di sistema).",
                    "Installare Lynis dai repository ufficiali della distribuzione e rieseguire /scan.", "high", source="lynis")
        return LynisOutcome([f], "skipped", "lynis non installato")
    tmp = tempfile.mkdtemp(prefix="lstk-lynis-")   # permessi 0700
    try:
        report, log = os.path.join(tmp, "report.dat"), os.path.join(tmp, "lynis.log")
        cmd = [lynis, "audit", "system", "--quick", "--no-colors", "--quiet", "--auditor", "LSTK",
               "--report-file", report, "--logfile", log]
        if not root:
            cmd.append("--pentest")
        r = runner.run(cmd, timeout=LYNIS_TIMEOUT)
        text = ""
        try:
            with open(report, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            pass
        if r.timed_out or not text:
            msg = f"Timeout dopo {LYNIS_TIMEOUT}s." if r.timed_out else f"Nessun report prodotto (exit {r.rc}): {(r.err or r.out)[-400:]}"
            f = Finding("LYN-000", "Audit Lynis non completato", "medium", "unknown", "lynis", msg,
                        "Verificare permessi/installazione di Lynis ed eseguire manualmente 'lynis audit system'.", "low", source="lynis")
            return LynisOutcome([f], "failed", msg)
        rep = parse_report(text)
        mode = "privilegiata" if root else "non privilegiata (--pentest, copertura ridotta)"
        return LynisOutcome(report_to_findings(rep), "ok",
                            f"Lynis {rep.version}: {len(rep.warnings)} warning, {len(rep.suggestions)} suggerimenti, modalità {mode}",
                            rep.hardening_index)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

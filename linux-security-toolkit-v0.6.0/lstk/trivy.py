"""Integrazione Trivy: vulnerabilità di pacchetti/librerie e segreti nei file (modalità rootfs).

Scelte di sicurezza e privacy:
- `--offline-scan`: Trivy non interroga API esterne per identificare dipendenze (es. hash dei JAR verso Maven Central);
- l'unico accesso di rete di Trivy è il download del database pubblico delle vulnerabilità (e, se servono, del DB Java);
  con `offline=True` si usa solo la cache locale (`--skip-db-update`);
- dei segreti NON viene mai riportato il contenuto (né `Match` né `Code`): solo file, righe, regola e categoria;
- il report JSON di Trivy vive in una directory temporanea privata (0700) rimossa al termine;
- se il database non è disponibile si ripiega sulla sola ricerca di segreti e il risultato è dichiarato PARZIALE.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field

from .models import Finding, sanitize
from .runner import Runner

TRIVY_TIMEOUT = int(os.environ.get("LSTK_TRIVY_TIMEOUT", "1800"))
MAX_REPORT_BYTES = 500_000_000
MAX_PACKAGES = 500
MAX_SECRETS = 200
SKIP_DIRS = ("/proc", "/sys", "/dev", "/run", "/mnt", "/media", "/var/lib/docker", "/var/lib/containers", "/snap")
SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "low"}
RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_URL = re.compile(r"^https?://[\w./:%#?&=+~@-]{1,300}$")


@dataclass
class Vuln:
    id: str
    severity: str
    fixed: str
    url: str


@dataclass
class VulnPkg:
    target: str
    kind: str
    pkg: str
    installed: str
    vulns: list = field(default_factory=list)


@dataclass
class SecretHit:
    path: str
    rule: str
    title: str
    category: str
    severity: str
    start: int
    end: int


@dataclass
class TrivyResult:
    version: str = ""
    packages_analyzed: int = 0
    pkgs: list = field(default_factory=list)
    secrets: list = field(default_factory=list)
    os_name: str = ""
    eosl: bool = False


def build_command(trivy: str, out: str, *, scanners: str, offline: bool, skip_dirs, cache_dir: str | None = None,
                  target: str = "/") -> list[str]:
    cmd = [trivy, "rootfs", "--format", "json", "--output", out, "--scanners", scanners, "--quiet", "--no-progress",
           "--skip-version-check", "--offline-scan", "--timeout", f"{TRIVY_TIMEOUT}s"]
    if offline:
        cmd += ["--skip-db-update", "--skip-java-db-update"]
    if cache_dir:
        cmd += ["--cache-dir", cache_dir]
    for d in skip_dirs:
        cmd += ["--skip-dirs", d]
    cmd.append(target)
    return cmd


def _cache_skips() -> list[str]:
    cands = {os.path.expanduser("~/.cache/trivy"), "/root/.cache/trivy",
             os.environ.get("LSTK_TRIVY_CACHE_DIR", ""), os.environ.get("TRIVY_CACHE_DIR", "")}
    return sorted(c for c in cands if c)


def parse_report(data: dict) -> TrivyResult:
    res = TrivyResult(version=str((data.get("Trivy") or {}).get("Version", "")))
    osm = (data.get("Metadata") or {}).get("OS") or {}
    res.os_name = f"{osm.get('Family', '')} {osm.get('Name', '')}".strip()
    res.eosl = bool(osm.get("EOSL"))
    groups: dict = {}
    for r in data.get("Results") or []:
        target, kind = str(r.get("Target", "")), f"{r.get('Class', '')}/{r.get('Type', '')}"
        res.packages_analyzed += len(r.get("Packages") or [])
        for v in r.get("Vulnerabilities") or []:
            key = (target, str(v.get("PkgName", "?")), str(v.get("InstalledVersion", "")))
            g = groups.setdefault(key, VulnPkg(target, kind, key[1], key[2]))
            url = str(v.get("PrimaryURL", ""))
            g.vulns.append(Vuln(str(v.get("VulnerabilityID", "?")), SEV.get(str(v.get("Severity", "UNKNOWN")).upper(), "low"),
                                str(v.get("FixedVersion", "") or ""), url if _URL.match(url) else ""))
        for s in r.get("Secrets") or []:
            res.secrets.append(SecretHit(target, str(s.get("RuleID", "")), str(s.get("Title", "")), str(s.get("Category", "")),
                                         SEV.get(str(s.get("Severity", "HIGH")).upper(), "high"),
                                         int(s.get("StartLine", 0) or 0), int(s.get("EndLine", 0) or 0)))
            # NB: Match e Code vengono volutamente ignorati (potrebbero contenere il segreto o segreti vicini).
    res.pkgs = list(groups.values())
    return res


def _h(*parts) -> str:
    return hashlib.sha1("|".join(map(str, parts)).encode()).hexdigest()[:6]


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._+-]", "_", name)[:40] or "pkg"


def build_findings(res: TrivyResult, *, scanners: str, offline: bool) -> list[Finding]:
    out: list[Finding] = []
    counts = {k: 0 for k in RANK}
    pkgs = []
    for g in res.pkgs:
        g.vulns.sort(key=lambda v: (-RANK[v.severity], v.id))
        for v in g.vulns:
            counts[v.severity] += 1
        pkgs.append(g)
    pkgs.sort(key=lambda g: (-RANK[g.vulns[0].severity], -len(g.vulns), g.pkg))
    for g in pkgs[:MAX_PACKAGES]:
        top = g.vulns[0].severity
        fixes = sorted({v.fixed for v in g.vulns if v.fixed})
        lik = 4 if fixes and top in ("critical", "high") else 3 if fixes else 2
        listed = "; ".join(f"{v.id} [{v.severity}] correzione: {v.fixed or 'non disponibile'}" for v in g.vulns[:8])
        more = f"; … e altre {len(g.vulns) - 8}" if len(g.vulns) > 8 else ""
        reco = (f"Aggiornare {g.pkg} a una versione corretta (es. {fixes[0]}) con il gestore pacchetti, dopo test. " if fixes else
                "Nessuna correzione disponibile: valutare mitigazioni, esposizione del servizio e advisory della distribuzione. ")
        reco += "La presenza di una CVE non implica che sia sfruttabile nel proprio contesto."
        out.append(Finding(f"TRV-{_safe(g.pkg)}-{_h(g.target, g.installed)}",
                           f"{g.pkg} {g.installed}: {len(g.vulns)} vulnerabilità note (max {top})"[:140], top, "warn", "vulnerabilities",
                           f"Origine: {g.target} ({g.kind}). {listed}{more}", reco, "medium", source="trivy", likelihood=lik,
                           references=[v.url for v in g.vulns[:3] if v.url]))
    if len(pkgs) > MAX_PACKAGES:
        out.append(Finding("TRV-TRUNC", "Elenco vulnerabilità troncato", "medium", "manual", "vulnerabilities",
                           f"{len(pkgs) - MAX_PACKAGES} pacchetti con vulnerabilità non elencati (limite {MAX_PACKAGES}); i totali nel riepilogo sono completi.",
                           "Ripetere la scansione con Trivy direttamente per l'elenco completo.", "high", source="trivy"))
    for s in res.secrets[:MAX_SECRETS]:
        path = "/" + s.path.lstrip("/")
        out.append(Finding(f"TRV-SEC-{_safe(s.rule)}-{_h(path, s.start)}", f"Possibile segreto in file: {s.title or s.rule}"[:140],
                           s.severity, "warn", "secrets",
                           f"File: {path}, righe {s.start}-{s.end}; regola {s.rule}; categoria {s.category}. Il contenuto non viene riportato.",
                           "Verificare se è un segreto reale (falsi positivi possibili); se lo è, revocarlo/ruotarlo, rimuoverlo dal file e limitarne i permessi.",
                           "medium", source="trivy", likelihood=3))
    if len(res.secrets) > MAX_SECRETS:
        out.append(Finding("TRV-SEC-TRUNC", "Elenco segreti troncato", "medium", "manual", "secrets",
                           f"{len(res.secrets) - MAX_SECRETS} ulteriori possibili segreti non elencati (limite {MAX_SECRETS}).",
                           "Ripetere la ricerca con Trivy direttamente.", "high", source="trivy"))
    if res.eosl:
        out.append(Finding("TRV-EOL", "Sistema operativo fuori supporto (EOL)", "high", "fail", "vulnerabilities",
                           f"Trivy segnala {res.os_name or 'il sistema'} come fine supporto: non riceve più correzioni di sicurezza.",
                           "Pianificare la migrazione a una versione supportata.", "medium", source="trivy"))
    vuln_run = "vuln" in scanners
    total_v, total_s = sum(counts.values()), len(res.secrets)
    summary = (f"Trivy {res.version}; scanner: {scanners}; database: {'non utilizzato' if not vuln_run else 'solo cache locale' if offline else 'aggiornato online'}; "
               f"pacchetti analizzati: {res.packages_analyzed}; ")
    summary += (f"vulnerabilità: critical {counts['critical']}, high {counts['high']}, medium {counts['medium']}, low {counts['low']}; "
                if vuln_run else "vulnerabilità: NON valutate; ")
    summary += f"possibili segreti: {total_s}."
    status = "info" if (total_v or total_s or not vuln_run) else "pass"
    out.insert(0, Finding("TRV-001", "Scansione vulnerabilità e segreti (Trivy)", "info", status, "vulnerabilities", summary,
                          "Ripetere la scansione regolarmente e dopo ogni aggiornamento; mantenere aggiornato il database.", "high", source="trivy"))
    return out


@dataclass
class TrivyOutcome:
    findings: list
    status: str       # ok | partial | skipped | failed
    detail: str


def _load(path: str) -> dict | None:
    try:
        if os.path.getsize(path) > MAX_REPORT_BYTES:
            return None
        with open(path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def run_trivy(runner: Runner, *, root: bool, offline: bool = False, target: str = "/") -> TrivyOutcome:
    trivy = runner.which("trivy")
    if not trivy:
        f = Finding("TRV-000", "Scansione Trivy non eseguita", "medium", "manual", "vulnerabilities",
                    "trivy non è installato (ricerca solo in directory di sistema).",
                    "Installare Trivy da una fonte ufficiale verificando firma/checksum (https://trivy.dev) e rieseguire /scan.", "high", source="trivy")
        return TrivyOutcome([f], "skipped", "trivy non installato")
    tmp = tempfile.mkdtemp(prefix="lstk-trivy-")   # 0700
    cache = os.environ.get("LSTK_TRIVY_CACHE_DIR") or None
    skips = [*SKIP_DIRS, tmp, *_cache_skips()]
    try:
        out = os.path.join(tmp, "report.json")

        def attempt(scanners: str, off: bool):
            r = runner.run(build_command(trivy, out, scanners=scanners, offline=off, skip_dirs=skips, cache_dir=cache, target=target),
                           timeout=TRIVY_TIMEOUT + 60)
            return r, (None if r.timed_out or r.rc != 0 else _load(out))

        r, data = attempt("vuln,secret", offline)
        if data is not None:
            res = parse_report(data)
            note = "" if root else " (senza root: file non leggibili esclusi, copertura ridotta)"
            return TrivyOutcome(build_findings(res, scanners="vuln,secret", offline=offline), "ok",
                                f"{res.packages_analyzed} pacchetti, {len(res.pkgs)} con vulnerabilità, {len(res.secrets)} possibili segreti{note}")
        err = sanitize((r.err or r.out or "nessun output")[-500:], 500)
        if r.timed_out:
            msg = f"Timeout dopo {TRIVY_TIMEOUT}s."
            return TrivyOutcome([Finding("TRV-000", "Scansione Trivy non completata", "medium", "unknown", "vulnerabilities", msg,
                                         "Aumentare LSTK_TRIVY_TIMEOUT o eseguire Trivy manualmente.", "low", source="trivy")], "failed", msg)
        if "DB" in err or "database" in err.lower():
            # Fallback: senza database si possono comunque cercare i segreti.
            r2, data2 = attempt("secret", True)
            reason = ("Database vulnerabilità non disponibile (offline senza cache o rete bloccata verso il registry): "
                      "le vulnerabilità NON sono state valutate.")
            f0 = Finding("TRV-000", "Vulnerabilità non valutate (database Trivy non disponibile)", "high", "unknown", "vulnerabilities",
                         f"{reason} Dettaglio: {err}",
                         "Consentire l'accesso di rete al registry di Trivy oppure, in ambienti isolati, precaricare la cache "
                         "(es. 'trivy image --download-db-only' su un host connesso, poi copiare la cache e usare --offline).",
                         "high", source="trivy")
            if data2 is not None:
                res = parse_report(data2)
                return TrivyOutcome([f0, *build_findings(res, scanners="secret", offline=True)], "partial",
                                    f"{reason} Eseguita solo la ricerca di segreti ({len(res.secrets)} possibili).")
            return TrivyOutcome([f0], "failed", reason)
        msg = f"Trivy terminato con errore (exit {r.rc}): {err}"
        return TrivyOutcome([Finding("TRV-000", "Scansione Trivy non completata", "medium", "unknown", "vulnerabilities", msg,
                                     "Verificare l'installazione di Trivy ed eseguirlo manualmente.", "low", source="trivy")], "failed", msg)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

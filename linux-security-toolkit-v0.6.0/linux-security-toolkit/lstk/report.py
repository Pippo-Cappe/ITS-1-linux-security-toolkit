"""Rapporti JSON/HTML con garanzie di integrità (SHA-256, HMAC opzionale) e scrittura sicura."""
from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from . import __version__
from .risk import LEVELS
from .scan import MODE_TABLE, Assessment

SCHEMA_VERSION = "1.0"
LIMITATIONS = [
    "Valutazione tecnica automatizzata e best-effort: NON è una certificazione né una verifica di conformità (ISO 27001, CIS, PCI-DSS, ecc.) e non sostituisce un penetration test o una revisione professionale.",
    "I controlli dipendono da privilegi, distribuzione e strumenti installati; gli esiti 'manual' e 'unknown' sono lacune di copertura e NON equivalgono a 'sicuro'.",
    "Nmap: l'esposizione osservata dipende dal punto di scansione; il rilevamento di versione non implica vulnerabilità e non è effettuata alcuna correlazione CVE. Solo IPv4.",
    "Lynis: i finding sono importati e mappati con una severità definita da LSTK (warning=high, suggestion=low); i testi originali restano in inglese.",
    "Trivy: la presenza di una CVE nel database non implica che sia sfruttabile nel proprio contesto; la qualità dipende dall'aggiornamento del database. I segreti sono rilevati per pattern (falsi positivi/negativi possibili) e il loro contenuto non è riportato.",
    "Integrità: dpkg/rpm confrontano i file con il database dei pacchetti; non rilevano file aggiunti né la manomissione del database stesso. Falsi positivi possibili (es. update-alternatives).",
    "Il punteggio di postura è indicativo (metodologia in docs/METHODOLOGY.md) e non confrontabile tra strumenti diversi.",
    "Hash e firma HMAC dimostrano che il rapporto non è stato alterato dopo la generazione, non che l'host fosse integro durante la scansione.",
]


class ReportError(RuntimeError):
    pass


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def build_payload(a: Assessment) -> dict:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unverified": 4, "none": 5}
    findings = sorted(a.findings, key=lambda f: (order.get(f.risk_level, 9), -f.risk_score, f.id))
    body = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "Linux Security Toolkit", "version": __version__},
        "run": {"id": a.run_id, "started_at": a.started_at, "finished_at": a.finished_at, "profile": a.options.profile,
                "mode": a.options.mode, "mode_description": MODE_TABLE[a.options.mode], "privileged": a.privileged, "host": a.host},
        "scope": a.scope,
        "summary": a.summary.to_dict(),
        "modules": [asdict(m) for m in a.modules],
        "findings": [f.to_dict() for f in findings],
        "installs": list(a.installs),
        "executions": [e.to_dict() for e in a.executions],
        "limitations": LIMITATIONS,
    }
    return seal(body)


def seal(body: dict) -> dict:
    integ = {"algorithm": "sha256", "payload_sha256": hashlib.sha256(canonical(body)).hexdigest()}
    key = os.environ.get("LSTK_SIGNING_KEY", "").encode()
    if len(key) >= 16:
        integ["hmac_sha256"] = hmac.new(key, canonical(body), hashlib.sha256).hexdigest()
    return {**body, "integrity": integ}


# --------------------------------------------------------------------------- HTML
LEVEL_COLORS = {"critical": "#b00020", "high": "#d9480f", "medium": "#e8a400", "low": "#2b8a9e", "none": "#2f9e44", "unverified": "#7048e8"}


def _e(v) -> str:
    return html.escape(str(v), quote=True)


def _cell_color(lik: int, imp: int) -> str:
    s = lik * imp
    return LEVEL_COLORS["critical" if s >= 20 else "high" if s >= 12 else "medium" if s >= 8 else "low"]


def render_html(p: dict) -> str:
    s, run = p["summary"], p["run"]
    badge = lambda lvl, txt=None: f'<span class="b" style="background:{LEVEL_COLORS.get(lvl, "#666")}">{_e(txt or lvl)}</span>'  # noqa: E731
    issues = [f for f in p["findings"] if f["risk_level"] in LEVELS]
    unver = [f for f in p["findings"] if f["risk_level"] == "unverified"]
    rest = [f for f in p["findings"] if f["risk_level"] == "none"]

    def rows(fs, cols=("id", "title", "source", "category", "status", "evidence", "recommendation")):
        out = []
        for f in fs:
            tds = "".join(f"<td>{_e(f[c])}</td>" for c in cols)
            pi = f"<td>{f['likelihood'] or '-'}</td><td>{f['impact'] or '-'}</td><td>{f['risk_score'] or '-'}</td>"
            out.append(f"<tr><td>{badge(f['risk_level'])}</td>{pi}{tds}</tr>")
        return "".join(out)
    head = "".join(f"<th>{h}</th>" for h in ("Rischio", "P", "I", "P×I", "ID", "Titolo", "Fonte", "Categoria", "Esito", "Evidenza", "Raccomandazione"))
    matrix = ""
    for lik in range(5, 0, -1):
        cells = "".join(
            f'<td style="background:{_cell_color(lik, imp)};color:#fff">{s["matrix"][lik - 1][imp - 1] or ""}</td>' for imp in range(1, 6))
        matrix += f"<tr><th>{lik}</th>{cells}</tr>"
    counts = "".join(f'<div class="card">{badge(l)}<strong>{s["counts"].get(l, 0)}</strong></div>' for l in LEVELS)
    mods = "".join(f"<tr><td>{_e(m['name'])}</td><td>{_e(m['status'])}</td><td>{_e(m['detail'])}</td></tr>" for m in p["modules"])
    reasons = "".join(f"<li>{_e(r)}</li>" for r in s["partial_reasons"] + s["grade_notes"])
    execs = "".join(f"<tr><td>{_e(' '.join(e['argv']))}</td><td>{e['returncode']}</td><td>{e['duration_s']}s</td></tr>" for e in p["executions"])
    inst = "".join(f"<tr><td>{_e(i.get('tool'))}</td><td>{'ok' if i.get('ok') else 'ERRORE'}</td><td>{_e(i.get('method'))}</td><td>{_e(i.get('detail'))}</td><td>{_e(i.get('at'))}</td></tr>" for i in p.get("installs", []))
    inst_html = ('<h2>Installazioni eseguite prima della scansione</h2><table><tr><th>Strumento</th><th>Esito</th><th>Metodo</th><th>Dettaglio</th><th>Quando</th></tr>' + inst + '</table>') if inst else ""
    lims = "".join(f"<li>{_e(x)}</li>" for x in p["limitations"])
    li = f" · Indice Lynis {s['lynis_hardening_index']}/100" if s.get("lynis_hardening_index") is not None else ""
    partial = '<p class="warn">⚠ Valutazione PARZIALE (vedi motivi sotto): il voto è limitato.</p>' if s["partial"] else ""
    return f"""<!doctype html><html lang="it"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>LSTK – Rapporto di risk assessment</title>
<style>:root{{color-scheme:light dark}}body{{font:15px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:1200px;padding:0 1rem}}
table{{border-collapse:collapse;width:100%;margin:.5rem 0 1.5rem}}td,th{{border:1px solid #8886;padding:.4rem .5rem;text-align:left;vertical-align:top;font-size:13px;word-break:break-word}}
th{{background:#8882}}.b{{color:#fff;border-radius:4px;padding:1px 7px;font-size:12px;white-space:nowrap}}.cards{{display:flex;gap:1rem;flex-wrap:wrap}}
.card{{border:1px solid #8886;border-radius:8px;padding:.7rem 1rem;display:flex;gap:.6rem;align-items:center;font-size:20px}}.grade{{font-size:48px;font-weight:700}}
.warn{{color:#d9480f;font-weight:600}}code{{font-size:12px}}table.m{{width:auto}}table.m td{{text-align:center;width:3rem;height:2.2rem}}@media print{{body{{margin:0}}}}</style></head><body>
<h1>Linux Security Toolkit – Rapporto di risk assessment</h1>
<p>Host <strong>{_e(run['host']['hostname'])}</strong> · {_e(run['host']['os'])} · profilo {_e(run['profile'])} · modalità {_e(run['mode'])} ·
{'root' if run['privileged'] else 'utente non privilegiato'} · {_e(run['started_at'])} → {_e(run['finished_at'])} · LSTK {_e(p['tool']['version'])} · run {_e(run['id'])}</p>
<p>Ambito: <strong>{_e(p['scope']['type'])}</strong> ({_e(', '.join(p['scope']['targets']))}) · {_e(p['scope']['authorization']['note'])}</p>
<h2>Sintesi esecutiva</h2>{partial}
<div class="cards"><div class="card"><span class="grade">{_e(s['grade'])}</span><span>Voto<br>postura {s['posture_score']}/100</span></div>{counts}
<div class="card" style="font-size:15px">Rischio complessivo: {badge(s['overall_level'])}</div>
<div class="card" style="font-size:15px">Copertura conclusiva {s['coverage_pct']}% · non verificati {s['unverified']} · superati {s['passed']}{_e(li)}</div></div>
{('<h3>Motivi di parzialità / note sul voto</h3><ul>' + reasons + '</ul>') if reasons else ''}
<h2>Moduli eseguiti</h2><table><tr><th>Modulo</th><th>Stato</th><th>Dettaglio</th></tr>{mods}</table>
<h2>Matrice di rischio (probabilità × impatto)</h2><table class="m"><tr><th>P \\ I</th>{''.join(f'<th>{i}</th>' for i in range(1, 6))}</tr>{matrix}</table>
<h2>Registro dei rischi ({len(issues)})</h2><table><tr>{head}</tr>{rows(issues)}</table>
<h2>Controlli non verificati ({len(unver)})</h2><p>Lacune di copertura: non indicano assenza di rischio.</p><table><tr>{head}</tr>{rows(unver)}</table>
<details><summary><h2 style="display:inline">Esiti positivi e informativi ({len(rest)})</h2></summary><table><tr>{head}</tr>{rows(rest)}</table></details>
<h2>Comandi eseguiti</h2><table><tr><th>Comando</th><th>Exit</th><th>Durata</th></tr>{execs}</table>
{inst_html}<h2>Limiti</h2><ul>{lims}</ul>
<h2>Integrità</h2><p>SHA-256 del contenuto: <code>{_e(p['integrity']['payload_sha256'])}</code>{' · firma HMAC-SHA256 presente' if 'hmac_sha256' in p['integrity'] else ''}. Verifica con <code>lstk verify FILE.json</code>.</p>
</body></html>"""


# --------------------------------------------------------------------------- scrittura sicura
def reports_dir() -> Path:
    d = Path(os.environ.get("LSTK_REPORT_DIR") or (Path.cwd() / "lstk-reports"))
    if d.is_symlink():
        raise ReportError(f"{d} è un link simbolico: rifiutato.")
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = d.stat()
    if st.st_mode & 0o022:
        raise ReportError(f"{d} è scrivibile da altri utenti (modo {oct(st.st_mode & 0o777)}): correggere con chmod 700.")
    if hasattr(os, "geteuid") and st.st_uid not in (0, os.geteuid()):
        raise ReportError(f"{d} appartiene a un altro utente.")
    return d


def _write_exclusive(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def write_report(payload: dict, fmt: str = "json", directory: Path | None = None) -> Path:
    if fmt not in ("json", "html"):
        raise ReportError("Formato non supportato")
    d = directory or reports_dir()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = d / f"audit-{stamp}-{payload['run']['id'][:8]}.{fmt}"
    data = (json.dumps(payload, indent=2, ensure_ascii=False) if fmt == "json" else render_html(payload)).encode("utf-8")
    try:
        _write_exclusive(path, data)
        _write_exclusive(Path(str(path) + ".sha256"), f"{hashlib.sha256(data).hexdigest()}  {path.name}\n".encode())
    except OSError as exc:
        raise ReportError(f"Scrittura rapporto fallita: {exc}") from exc
    return path


@dataclass
class VerifyResult:
    ok: bool
    checks: list   # (True|False|None, messaggio)


def verify_report(path: str | Path) -> VerifyResult:
    p = Path(path)
    try:
        data = p.read_bytes()
    except OSError as exc:
        return VerifyResult(False, [(False, f"Impossibile leggere il file: {exc}")])
    checks, ok, any_proof = [], True, False
    side = Path(str(p) + ".sha256")
    if side.is_file():
        any_proof = True
        parts = side.read_text().split()
        match = bool(parts) and hmac.compare_digest(parts[0], hashlib.sha256(data).hexdigest())
        ok &= match
        checks.append((match, "Hash SHA-256 del file coerente con il file .sha256" if match else "Hash SHA-256 del file NON coerente: file alterato"))
    else:
        checks.append((None, "Nessun file .sha256 accanto al rapporto"))
    if p.suffix == ".json":
        try:
            payload = json.loads(data)
            integ = payload.get("integrity")
            body = {k: v for k, v in payload.items() if k != "integrity"}
        except (ValueError, AttributeError):
            return VerifyResult(False, checks + [(False, "JSON non valido")])
        if integ and "payload_sha256" in integ:
            any_proof = True
            good = hmac.compare_digest(integ["payload_sha256"], hashlib.sha256(canonical(body)).hexdigest())
            ok &= good
            checks.append((good, "Hash interno del contenuto coerente" if good else "Hash interno NON coerente: contenuto alterato"))
            if "hmac_sha256" in integ:
                key = os.environ.get("LSTK_SIGNING_KEY", "").encode()
                if len(key) < 16:
                    checks.append((None, "Firma HMAC presente ma LSTK_SIGNING_KEY non impostata: non verificabile"))
                    ok = False
                else:
                    good = hmac.compare_digest(integ["hmac_sha256"], hmac.new(key, canonical(body), hashlib.sha256).hexdigest())
                    ok &= good
                    checks.append((good, "Firma HMAC valida" if good else "Firma HMAC NON valida"))
        else:
            checks.append((False, "Sezione integrity assente"))
            ok = False
    if not any_proof:
        ok = False
    return VerifyResult(ok, checks)

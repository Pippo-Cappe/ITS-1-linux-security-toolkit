"""Orchestratore dell'assessment: controlli nativi + Nmap + Lynis + risk assessment.

È il motore del comando /scan. Non modifica mai il sistema.
"""
from __future__ import annotations

import os
import platform
import socket
import uuid
from dataclasses import dataclass, field
from datetime import datetime

from .audit import collect
from .integrity import run_integrity
from .lynis import run_lynis
from .models import Finding
from .nmapscan import Target, TargetError, local_addresses, run_nmap, validate_target
from .risk import RiskSummary, assess
from .runner import Execution, Runner, is_root
from .trivy import run_trivy

MODES = ("quick", "deep", "full")
PROFILES = ("desktop", "server")

MODE_TABLE = {
    "quick": "controlli base + Nmap top-1000 porte TCP",
    "deep": "controlli estesi + integrità file di pacchetto + Nmap tutte le porte TCP",
    "full": "controlli estesi + integrità file + Nmap (tutte le porte, script default, UDP top-50 se root) + Trivy (vulnerabilità e segreti) + Lynis",
}


class AuthorizationError(RuntimeError):
    pass


@dataclass
class ScanOptions:
    profile: str = "desktop"
    mode: str = "full"
    targets: list = field(default_factory=list)   # vuoto = sistema locale
    authorized: bool = False
    use_nmap: bool = True
    use_lynis: bool | None = None                  # None = in base alla modalità (solo full)
    use_trivy: bool | None = None                  # None = in base alla modalità (solo full)
    use_integrity: bool | None = None              # None = in base alla modalità (deep e full)
    offline: bool = False                          # Trivy: usa solo la cache locale del database

    def lynis_enabled(self) -> bool:
        return self.mode == "full" if self.use_lynis is None else self.use_lynis

    def trivy_enabled(self) -> bool:
        return self.mode == "full" if self.use_trivy is None else self.use_trivy

    def integrity_enabled(self) -> bool:
        return self.mode in ("deep", "full") if self.use_integrity is None else self.use_integrity

    def validate(self) -> None:
        if self.mode not in MODES:
            raise ValueError(f"Modalità non valida: {self.mode}")
        if self.profile not in PROFILES:
            raise ValueError(f"Profilo non valido: {self.profile}")


@dataclass
class ModuleResult:
    name: str
    status: str      # ok | skipped | failed
    detail: str = ""


@dataclass
class Assessment:
    run_id: str
    started_at: str
    finished_at: str
    options: ScanOptions
    privileged: bool
    findings: list
    modules: list
    summary: RiskSummary
    executions: list
    scope: dict
    host: dict
    installs: list = field(default_factory=list)


def resolve_targets(raw_targets: list[str], runner: Runner) -> tuple[list[Target], list[str]]:
    local = local_addresses(runner)
    if not raw_targets:
        return [validate_target("127.0.0.1")] + [validate_target(a, local) for a in local], local
    return [validate_target(t, local) for t in raw_targets], local


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def run_assessment(opts: ScanOptions, runner: Runner | None = None, progress=None, installs: list | None = None) -> Assessment:
    opts.validate()
    runner = runner or Runner()
    say = progress or (lambda msg: None)
    started, root = _now(), is_root()
    targets, _local = resolve_targets(opts.targets, runner)
    external = [t for t in targets if not t.is_self]
    if external and not opts.authorized:
        raise AuthorizationError("Bersagli non locali: serve autorizzazione esplicita (" + ", ".join(t.raw for t in external) + ").")
    scope = {
        "type": "locale" if not external else ("esterno" if len(external) == len(targets) else "misto"),
        "targets": [t.raw for t in targets],
        "authorization": {"required": bool(external), "declared": bool(external and opts.authorized),
                          "note": "Dichiarazione dell'operatore di essere autorizzato a scansionare i bersagli non locali." if external else "Solo sistema locale."},
    }
    findings: list[Finding] = []
    modules: list[ModuleResult] = []
    partial: list[str] = []

    say("Controlli nativi del sistema…")
    try:
        native = collect(opts.profile, deep=opts.mode != "quick", runner=runner)
        findings += native
        modules.append(ModuleResult("native", "ok", f"{len(native)} controlli"))
    except Exception as exc:  # pragma: no cover - collect isola già i singoli controlli
        modules.append(ModuleResult("native", "failed", f"{type(exc).__name__}: {exc}"))
        partial.append("controlli nativi falliti")

    if opts.integrity_enabled():
        say("Verifica integrità dei file di sistema (può richiedere un minuto)…")
        try:
            out = run_integrity(runner, root=root)
            findings += out.findings
            modules.append(ModuleResult("integrity", out.status, out.detail))
            if out.status != "ok":
                partial.append(f"Integrità file: {out.detail}")
        except Exception as exc:
            modules.append(ModuleResult("integrity", "failed", f"{type(exc).__name__}: {exc}"))
            partial.append("verifica integrità fallita")
    else:
        modules.append(ModuleResult("integrity", "skipped", "non previsto dalla modalità o disabilitato"))
        partial.append("integrità dei file di sistema non verificata")

    if opts.use_nmap:
        say("Scansione porte con Nmap…")
        try:
            out = run_nmap(runner, targets, mode=opts.mode, root=root)
            findings += out.findings
            modules.append(ModuleResult("nmap", out.status, out.detail))
            if out.status != "ok":
                partial.append(f"Nmap: {out.detail}")
        except Exception as exc:
            modules.append(ModuleResult("nmap", "failed", f"{type(exc).__name__}: {exc}"))
            partial.append("Nmap fallito")
    else:
        modules.append(ModuleResult("nmap", "skipped", "disabilitato dall'operatore"))
        partial.append("scansione Nmap disabilitata")

    if opts.trivy_enabled():
        say("Trivy: vulnerabilità e segreti su tutto il filesystem (può richiedere diversi minuti)…")
        try:
            out = run_trivy(runner, root=root, offline=opts.offline)
            findings += out.findings
            modules.append(ModuleResult("trivy", out.status, out.detail))
            if out.status != "ok":
                partial.append(f"Trivy: {out.detail}")
            elif not root:
                partial.append("Trivy eseguito senza root: file non leggibili esclusi")
        except Exception as exc:
            modules.append(ModuleResult("trivy", "failed", f"{type(exc).__name__}: {exc}"))
            partial.append("Trivy fallito")
    else:
        modules.append(ModuleResult("trivy", "skipped", "non previsto dalla modalità o disabilitato"))
        partial.append("scansione vulnerabilità (Trivy) non eseguita")

    lynis_index = None
    if opts.lynis_enabled():
        say("Audit Lynis in corso (può richiedere alcuni minuti)…")
        try:
            out = run_lynis(runner, root=root)
            findings += out.findings
            lynis_index = out.hardening_index
            modules.append(ModuleResult("lynis", out.status, out.detail))
            if out.status != "ok":
                partial.append(f"Lynis: {out.detail}")
            elif not root:
                partial.append("Lynis eseguito in modalità non privilegiata")
        except Exception as exc:
            modules.append(ModuleResult("lynis", "failed", f"{type(exc).__name__}: {exc}"))
            partial.append("Lynis fallito")
    else:
        modules.append(ModuleResult("lynis", "skipped", "non previsto dalla modalità o disabilitato"))
        partial.append("audit Lynis non eseguito")

    if not root:
        partial.append("eseguito senza privilegi root: shadow, sudoers, sshd -T, regole firewall e UDP non verificabili")
    if opts.mode != "full":
        partial.append(f"modalità {opts.mode}: copertura ridotta rispetto a full")

    seen_ids: dict[str, int] = {}
    for f in findings:                      # garanzia globale: ID sempre univoci
        n = seen_ids.get(f.id, 0) + 1
        seen_ids[f.id] = n
        if n > 1:
            f.id = f"{f.id}-dup{n}"

    say("Calcolo del risk assessment…")
    summary = assess(findings, partial, lynis_index)
    host = {"hostname": socket.gethostname(), "os": platform.platform(), "kernel": platform.release(), "arch": platform.machine(),
            "user": os.environ.get("USER") or os.environ.get("LOGNAME") or str(os.getuid() if hasattr(os, "getuid") else "")}
    return Assessment(str(uuid.uuid4()), started, _now(), opts, root, findings, modules, summary,
                      list(runner.executions), scope, host, list(installs or []))

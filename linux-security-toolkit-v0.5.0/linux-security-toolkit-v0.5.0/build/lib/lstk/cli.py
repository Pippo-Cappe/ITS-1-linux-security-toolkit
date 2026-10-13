from __future__ import annotations

import argparse
import json
import platform
import shlex
import sys
from pathlib import Path
from typing import List, Optional

import typer
from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from . import __version__
from .nmapscan import TargetError
from .report import ReportError, build_payload, verify_report, write_report
from .risk import LEVELS
from .runner import Runner, is_root
from .scan import MODE_TABLE, MODES, PROFILES, Assessment, AuthorizationError, ScanOptions, resolve_targets, run_assessment

app = typer.Typer(add_completion=False, no_args_is_help=False, help="Linux Security Toolkit")
console = Console()
STATE: dict = {"profile": "desktop", "assessment": None, "last_scan": None}

LOGO = r"""[bold cyan]
██╗     ███████╗████████╗██╗  ██╗
██║     ██╔════╝╚══██╔══╝██║ ██╔╝
██║     ███████╗   ██║   █████╔╝
██║     ╚════██║   ██║   ██╔═██╗
███████╗███████║   ██║   ██║  ██╗
╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝[/bold cyan]
[bold white]LINUX SECURITY TOOLKIT[/bold white]
[dim]Risk Assessment · Nmap · Lynis[/dim]"""

HELP = [
    ("/help", "Mostra i comandi disponibili"),
    ("/scan [quick|deep|full]", "Risk assessment completo: controlli + integrità + Nmap + Trivy + Lynis"),
    ("   --target IP|CIDR|host", "Scansiona anche bersagli non locali (richiede autorizzazione)"),
    ("   --no-nmap|--no-lynis|--no-trivy|--no-integrity", "Esclude un modulo (valutazione parziale)"),
    ("   --offline", "Trivy usa solo il database in cache (nessun download)"),
    ("/vuln [--offline]", "Solo Trivy: vulnerabilità dei pacchetti/librerie e segreti nei file"),
    ("/integrity", "Solo verifica integrità dei file installati (dpkg --verify / rpm -Va)"),
    ("/profile [desktop|server]", "Mostra o cambia profilo"),
    ("/risk", "Sintesi del rischio: voto, matrice 5x5, rischi principali"),
    ("/findings [filtro]", "issues (default), all, critical|high|medium|low, unverified"),
    ("/details ID", "Dettaglio di un finding"),
    ("/report [json|html|all]", "Esporta il rapporto (0600, hash SHA-256, HMAC opzionale)"),
    ("/verify FILE", "Verifica l'integrità di un rapporto"),
    ("/lynis", "Esegue solo Lynis (con conferma)"),
    ("/checks", "Elenca i controlli implementati"),
    ("/status", "Stato del programma e sistema"),
    ("/fix ID", "Stato delle correzioni (nessuna modifica automatica)"),
    ("/clear", "Pulisce il terminale"),
    ("/exit", "Esce dalla console"),
]

STYLE = {"critical": "bold white on red", "high": "bold red", "medium": "yellow", "low": "cyan",
         "none": "green", "unverified": "magenta", "info": "dim"}


def _e(x) -> str:
    return escape(str(x))


def banner():
    console.print(Panel(LOGO, border_style="cyan", box=box.DOUBLE, padding=(1, 3)))
    table = Table(box=None, show_header=False, padding=(0, 1))
    table.add_row("[dim]Sistema[/dim]", _e(platform.platform()))
    table.add_row("[dim]Privilegi[/dim]", "root" if is_root() else "utente (copertura ridotta: usare sudo per l'audit completo)")
    table.add_row("[dim]Profilo[/dim]", STATE["profile"])
    console.print(table)
    console.print("\n[bold]COMANDI DISPONIBILI[/bold]")
    for command, desc in HELP:
        console.print(f"  [cyan]{_e(command):<26}[/cyan] {_e(desc)}")
    console.print("\n[dim]Nessuna scansione parte automaticamente e nulla viene modificato sul sistema. /scan chiede conferma.[/dim]\n")


def print_help():
    table = Table(title="Guida LSTK", box=box.ROUNDED)
    table.add_column("Comando", style="cyan", no_wrap=True)
    table.add_column("Descrizione")
    for cmd, desc in HELP:
        table.add_row(_e(cmd), _e(desc))
    console.print(table)
    console.print("[dim]Esempi: /scan · /scan quick · /scan full --target 192.168.1.10 · /findings high · /report all[/dim]")


def show_findings(findings, title="Risultati"):
    if not findings:
        console.print("[yellow]Nessun risultato per questo filtro. Esegui /scan oppure cambia filtro.[/yellow]")
        return
    table = Table(title=f"{title} — {len(findings)}", box=box.ROUNDED, expand=True)
    for col in ("ID", "Rischio", "Esito", "Fonte", "Controllo"):
        table.add_column(col, no_wrap=(col in ("ID", "Rischio")))
    for f in findings:
        lvl = f.risk_level
        label = f"{lvl} ({f.risk_score})" if f.risk_score else lvl
        table.add_row(_e(f.id), f"[{STYLE.get(lvl, 'white')}]{_e(label)}[/]", _e(f.status), _e(f.source), _e(f.title))
    console.print(table)


def _sorted(findings):
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unverified": 4, "none": 5}
    return sorted(findings, key=lambda f: (order.get(f.risk_level, 9), -f.risk_score, f.id))


def filter_findings(findings, flt: str):
    flt = flt.lower()
    if flt == "all":
        return _sorted(findings)
    if flt == "unverified":
        return _sorted([f for f in findings if f.risk_level == "unverified"])
    if flt in LEVELS:
        return _sorted([f for f in findings if f.risk_level == flt])
    return _sorted([f for f in findings if f.risk_level in LEVELS])


def show_risk(a: Assessment):
    s = a.summary
    gcol = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}.get(s.grade, "white")
    lines = [f"Voto: [{gcol}]{s.grade}[/] · postura {s.posture_score}/100 · rischio complessivo: [{STYLE.get(s.overall_level, 'white')}]{s.overall_level}[/]",
             "Rischi: " + " · ".join(f"[{STYLE[l]}]{l}: {s.counts.get(l, 0)}[/]" for l in LEVELS),
             f"Copertura conclusiva {s.coverage_pct}% · non verificati {s.unverified} · superati {s.passed}"
             + (f" · indice Lynis {s.lynis_hardening_index}/100" if s.lynis_hardening_index is not None else "")]
    if s.partial:
        lines.append("[bold yellow]⚠ Valutazione PARZIALE[/bold yellow]: " + _e("; ".join(s.partial_reasons)))
    for n in s.grade_notes:
        lines.append(f"[dim]{_e(n)}[/dim]")
    console.print(Panel("\n".join(lines), title="Risk assessment", border_style="cyan"))
    m = Table(title="Matrice di rischio", box=box.SIMPLE_HEAVY)
    m.add_column("P\\I", justify="right")
    for i in range(1, 6):
        m.add_column(str(i), justify="center")
    for lik in range(5, 0, -1):
        cells = []
        for imp in range(1, 6):
            n, sc = s.matrix[lik - 1][imp - 1], lik * imp
            lvl = "critical" if sc >= 20 else "high" if sc >= 12 else "medium" if sc >= 8 else "low"
            cells.append(f"[{STYLE[lvl]}]{n if n else '·'}[/]")
        m.add_row(str(lik), *cells)
    console.print(m)
    top = [f for f in a.findings if f.id in s.top_risks]
    show_findings(_sorted(top), "Rischi principali")


def export_report(fmt="json"):
    a = STATE["assessment"]
    if a is None:
        console.print("[yellow]Nessun audit da esportare. Esegui /scan prima.[/yellow]")
        return
    payload = build_payload(a)
    try:
        for f in (("json", "html") if fmt == "all" else (fmt,)):
            path = write_report(payload, f)
            console.print(f"[green]Rapporto salvato:[/green] {_e(path)} [dim](0600, + .sha256)[/dim]")
    except ReportError as exc:
        console.print(f"[red]Errore:[/red] {_e(exc)}")


# --------------------------------------------------------------------------- /scan
class _ArgError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise _ArgError(message)


def parse_scan_args(args: list[str]) -> ScanOptions:
    p = _Parser(prog="/scan", add_help=False)
    p.add_argument("mode", nargs="?", default="full", choices=MODES)
    p.add_argument("--target", "-t", action="append", default=[])
    p.add_argument("--no-nmap", action="store_true")
    p.add_argument("--no-lynis", action="store_true")
    p.add_argument("--no-trivy", action="store_true")
    p.add_argument("--no-integrity", action="store_true")
    p.add_argument("--offline", action="store_true")
    ns = p.parse_args(args)
    return ScanOptions(profile=STATE["profile"], mode=ns.mode, targets=ns.target, use_nmap=not ns.no_nmap,
                       use_lynis=False if ns.no_lynis else None, use_trivy=False if ns.no_trivy else None,
                       use_integrity=False if ns.no_integrity else None, offline=ns.offline)


def describe_plan(opts: ScanOptions, runner: Runner, targets) -> str:
    lines = [f"Profilo: [cyan]{opts.profile}[/cyan] · modalità: [cyan]{opts.mode}[/cyan] — {_e(MODE_TABLE[opts.mode])}",
             f"Privilegi: {'root' if is_root() else 'utente non privilegiato (copertura ridotta, valutazione parziale)'}", "",
             "[bold]Verranno eseguiti[/bold] (solo lettura, nessuna modifica al sistema):",
             f"  • controlli nativi {'estesi' if opts.mode != 'quick' else 'base'}"]
    if opts.use_nmap:
        ok = runner.which("nmap")
        lines.append(f"  • Nmap su: {_e(', '.join(t.raw for t in targets))}" + ("" if ok else " [yellow](nmap non installato: verrà saltato)[/yellow]"))
        lines.append("    [dim]genera traffico di rete verso i bersagli[/dim]")
    if opts.integrity_enabled():
        ok = runner.which("dpkg") or runner.which("rpm")
        lines.append("  • Integrità dei file installati (dpkg --verify / rpm -Va)" + ("" if ok else " [yellow](dpkg/rpm assenti: verrà saltato)[/yellow]"))
    if opts.trivy_enabled():
        ok = runner.which("trivy")
        lines.append("  • Trivy: vulnerabilità e segreti su tutto il filesystem" + ("" if ok else " [yellow](trivy non installato: verrà saltato)[/yellow]")
                     + " [dim](può richiedere diversi minuti)[/dim]")
        lines.append("    [dim]" + ("database in cache locale, nessun download" if opts.offline else
                                     "scarica il database pubblico delle vulnerabilità; i file della macchina non vengono inviati; il contenuto dei segreti non viene riportato") + "[/dim]")
    if opts.lynis_enabled():
        ok = runner.which("lynis")
        lines.append("  • Lynis: audit system" + ("" if ok else " [yellow](lynis non installato: verrà saltato)[/yellow]") + " [dim](può richiedere alcuni minuti)[/dim]")
    return "\n".join(lines)


def do_scan(opts: ScanOptions) -> None:
    runner = Runner()
    try:
        opts.validate()
        targets, _ = resolve_targets(opts.targets, runner)
    except (TargetError, ValueError) as exc:
        console.print(f"[red]Errore:[/red] {_e(exc)}")
        return
    external = [t for t in targets if not t.is_self]
    console.print(Panel(describe_plan(opts, runner, targets), title="Piano di assessment", border_style="cyan"))
    if external:
        console.print(Panel("[bold red]ATTENZIONE: bersagli NON locali.[/bold red]\n"
                            f"{_e(', '.join(t.raw for t in external))}\n"
                            "Scansionare sistemi altrui senza autorizzazione scritta può essere illegale.",
                            border_style="red"))
        if Prompt.ask("Digita AUTORIZZO per confermare di essere autorizzato a scansionarli").strip() != "AUTORIZZO":
            console.print("Audit annullato.")
            return
        opts.authorized = True
    if not Confirm.ask("Avviare il risk assessment?", default=True):
        console.print("Audit annullato.")
        return
    try:
        with console.status("[cyan]Avvio…") as status:
            a = run_assessment(opts, runner, lambda m: status.update(f"[cyan]{_e(m)}"))
    except KeyboardInterrupt:
        console.print("\n[yellow]Audit interrotto dall'utente: nessun risultato salvato.[/yellow]")
        return
    except (AuthorizationError, TargetError, ValueError) as exc:
        console.print(f"[red]Errore:[/red] {_e(exc)}")
        return
    STATE["assessment"], STATE["last_scan"] = a, a.finished_at
    for m in a.modules:
        col = {"ok": "green", "skipped": "yellow", "partial": "yellow", "failed": "red"}.get(m.status, "white")
        console.print(f"  [{col}]{m.name}: {m.status}[/] [dim]{_e(m.detail)}[/dim]")
    show_risk(a)
    console.print("\n[dim]/findings per l'elenco, /details ID per il dettaglio, /report html|json|all per esportare.[/dim]")


def command(line: str) -> bool:
    try:
        parts = shlex.split(line.strip())
    except ValueError as exc:
        console.print(f"[red]Sintassi non valida:[/red] {_e(exc)}")
        return True
    if not parts:
        return True
    cmd, args = parts[0].lower(), parts[1:]
    a: Optional[Assessment] = STATE["assessment"]
    if cmd in ("/exit", "/quit", "exit", "quit"):
        return False
    if cmd in ("/help", "help"):
        print_help()
    elif cmd == "/clear":
        console.clear()
        banner()
    elif cmd == "/status":
        console.print(Panel(f"LSTK {__version__}\nSistema: {_e(platform.platform())}\nPrivilegi: {'root' if is_root() else 'utente'}\n"
                            f"Profilo: {STATE['profile']}\nUltimo audit: {STATE['last_scan'] or 'nessuno'}\n"
                            f"Finding in memoria: {len(a.findings) if a else 0}", title="Stato"))
    elif cmd == "/profile":
        if not args:
            console.print(f"Profilo corrente: [cyan]{STATE['profile']}[/cyan]. Uso: /profile desktop|server")
        elif args[0] in PROFILES:
            STATE["profile"] = args[0]
            console.print(f"[green]Profilo impostato:[/green] {STATE['profile']}")
        else:
            console.print("[red]Profilo non valido. Usa desktop oppure server.[/red]")
    elif cmd == "/scan":
        try:
            do_scan(parse_scan_args(args))
        except _ArgError as exc:
            console.print(f"[red]Argomenti non validi:[/red] {_e(exc)}. Uso: /scan [quick|deep|full] [--target T] [--no-nmap] [--no-lynis]")
    elif cmd == "/risk":
        show_risk(a) if a else console.print("[yellow]Nessun audit disponibile. Esegui /scan.[/yellow]")
    elif cmd == "/findings":
        if not a:
            console.print("[yellow]Nessun risultato disponibile. Esegui prima /scan.[/yellow]")
        else:
            flt = args[0] if args else "issues"
            if flt not in ("issues", "all", "unverified", *LEVELS):
                console.print("Uso: /findings [issues|all|critical|high|medium|low|unverified]")
            else:
                show_findings(filter_findings(a.findings, flt), f"Finding ({flt})")
    elif cmd == "/details":
        if not args:
            console.print("Uso: /details ID")
        else:
            m = next((f for f in (a.findings if a else []) if f.id.lower() == args[0].lower()), None)
            if not m:
                console.print("[yellow]Finding non trovato. Esegui /scan e controlla l'ID.[/yellow]")
            else:
                refs = ("\n\n[bold]Riferimenti[/bold]\n" + "\n".join(_e(r) for r in m.references)) if m.references else ""
                console.print(Panel(
                    f"[bold]{_e(m.title)}[/bold]\nID: {_e(m.id)} · Fonte: {_e(m.source)}\nGravità: {m.severity} · Esito: {m.status} · "
                    f"Rischio: {m.risk_level} (P{m.likelihood} × I{m.impact} = {m.risk_score}) · Confidenza: {m.confidence}\n"
                    f"Categoria: {_e(m.category)}\n\n[bold]Evidenza[/bold]\n{_e(m.evidence)}\n\n[bold]Raccomandazione[/bold]\n{_e(m.recommendation)}{refs}",
                    title="Dettaglio finding", expand=True))
    elif cmd == "/report":
        fmt = args[0] if args else "json"
        if fmt not in ("json", "html", "all"):
            console.print("Uso: /report [json|html|all]")
        else:
            export_report(fmt)
    elif cmd == "/verify":
        if not args:
            console.print("Uso: /verify FILE")
        else:
            res = verify_report(args[0])
            for ok, msg in res.checks:
                console.print(f"  {'[green]✔[/green]' if ok else '[yellow]–[/yellow]' if ok is None else '[red]✘[/red]'} {_e(msg)}")
            console.print("[green]Rapporto integro.[/green]" if res.ok else "[red]Verifica NON superata.[/red]")
    elif cmd == "/checks":
        table = Table(title="Controlli implementati", box=box.ROUNDED)
        table.add_column("Area", style="cyan")
        table.add_column("Copertura")
        for x, y in [
            ("sistema", "OS, kernel, contesto/privilegi, container, riavvio richiesto"),
            ("pacchetti", "gestore e aggiornamenti in sospeso (da cache locale, sola lettura)"),
            ("firewall", "servizi attivi e, come root, regole nft/iptables"),
            ("ssh", "configurazione effettiva (sshd -T come root) o file con Include; cifrari deboli"),
            ("account", "UID 0, password vuote, sudo NOPASSWD, scadenza password"),
            ("filesystem", "permessi file critici, mount /tmp, SUID e directory world-writable (deep/full)"),
            ("kernel", "parametri sysctl di hardening"),
            ("hardening", "SELinux/AppArmor, logging, auditd, NTP, cifratura disco"),
            ("servizi", "servizi abilitati e legacy (deep/full)"),
            ("integrità file", "file installati confrontati col database pacchetti (dpkg --verify / rpm -Va); file world-writable e orfani (deep/full)"),
            ("vulnerabilità (Trivy)", "CVE di pacchetti OS e librerie, segreti nei file (contenuto mai riportato), OS fuori supporto (full)"),
            ("rete (Nmap)", "porte TCP (UDP top-50 come root in full), servizi/versioni, esposizione loopback vs rete"),
            ("Lynis", "audit completo importato come finding (warning/suggerimenti, hardening index)"),
        ]:
            table.add_row(x, y)
        console.print(table)
    elif cmd in ("/vuln", "/integrity"):
        runner = Runner()
        offline = "--offline" in args
        tool = "trivy" if cmd == "/vuln" else ("dpkg" if runner.which("dpkg") else "rpm")
        if cmd == "/vuln" and not runner.which("trivy"):
            console.print("[yellow]Trivy non trovato. Installarlo da una fonte ufficiale verificando firma/checksum (https://trivy.dev).[/yellow]")
        elif cmd == "/integrity" and not (runner.which("dpkg") or runner.which("rpm")):
            console.print("[yellow]dpkg/rpm non disponibili: verifica non supportata su questo sistema.[/yellow]")
        elif Confirm.ask("Avviare " + ("la scansione Trivy (può richiedere diversi minuti)" if cmd == "/vuln" else "la verifica di integrità") + "? Sola lettura.", default=True):
            from .integrity import run_integrity
            from .trivy import run_trivy
            try:
                with console.status("[cyan]In corso…"):
                    out = (run_trivy(runner, root=is_root(), offline=offline) if cmd == "/vuln" else run_integrity(runner, root=is_root()))
            except KeyboardInterrupt:
                console.print("\n[yellow]Interrotto.[/yellow]")
                return True
            from .risk import score_finding
            for f in out.findings:
                score_finding(f)
            console.print(f"{tool}: {out.status} — {_e(out.detail)}")
            show_findings(_sorted([f for f in out.findings if f.status in ("fail", "warn", "unknown", "manual")]), "Risultati")
    elif cmd == "/lynis":
        runner = Runner()
        if not runner.which("lynis"):
            console.print("[yellow]Lynis non trovato. Installarlo dai repository ufficiali della distribuzione.[/yellow]")
        elif Confirm.ask("Avviare 'lynis audit system' (sola lettura, può richiedere minuti)?", default=False):
            from .lynis import run_lynis
            with console.status("[cyan]Lynis in corso…"):
                out = run_lynis(runner, root=is_root())
            console.print(f"Lynis: {out.status} — {_e(out.detail)}")
            show_findings(_sorted([f for f in out.findings if f.status in ("fail", "warn")]), "Finding Lynis")
    elif cmd == "/fix":
        if not args:
            console.print("[yellow]Le correzioni automatiche non sono implementate, per scelta di sicurezza.[/yellow]\n"
                          "Il modulo remediation offre primitive sicure (diff, backup, scrittura atomica) non ancora collegate ai finding.")
        else:
            console.print(f"[yellow]Nessuna correzione automatica per {_e(args[0])}.[/yellow] Consulta /details {_e(args[0])} e applica solo modifiche comprese e verificate.")
    else:
        console.print(f"[red]Comando sconosciuto:[/red] {_e(cmd)}. Digita /help.")
    return True


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """Avvia la console interattiva LSTK."""
    if ctx.invoked_subcommand is not None:
        return
    banner()
    while True:
        try:
            line = Prompt.ask("[bold cyan]lstk[/bold cyan]")
            if not command(line):
                break
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Uscita dalla console.[/dim]")
            break
    console.print("[dim]Linux Security Toolkit terminato.[/dim]")


@app.command()
def scan(profile: str = typer.Option("desktop", help="Profilo: desktop o server"),
         mode: str = typer.Option("full", "--mode", "-m", help="quick | deep | full"),
         target: Optional[List[str]] = typer.Option(None, "--target", "-t", help="Bersaglio Nmap non locale (ripetibile)"),
         authorized: bool = typer.Option(False, "--authorized", help="Dichiaro di essere autorizzato a scansionare i bersagli non locali"),
         no_nmap: bool = typer.Option(False, "--no-nmap"), no_lynis: bool = typer.Option(False, "--no-lynis"),
         no_trivy: bool = typer.Option(False, "--no-trivy"), no_integrity: bool = typer.Option(False, "--no-integrity"),
         offline: bool = typer.Option(False, "--offline", help="Trivy: usa solo la cache locale del database"),
         save: bool = typer.Option(False, "--save", help="Salva anche rapporti JSON+HTML in lstk-reports/"),
         fail_on: str = typer.Option("none", "--fail-on", help="Exit code 3 se il rischio complessivo è >= none|low|medium|high|critical"),
         deep: bool = typer.Option(False, "--deep", hidden=True)):
    """Risk assessment non interattivo: JSON su stdout, avanzamento su stderr."""
    if deep and mode == "full":
        mode = "deep"
    if profile not in PROFILES:
        raise typer.BadParameter("Usa desktop oppure server")
    if mode not in MODES:
        raise typer.BadParameter("Usa quick, deep o full")
    if fail_on not in ("none", *LEVELS[::-1]):
        raise typer.BadParameter("--fail-on: none|low|medium|high|critical")
    opts = ScanOptions(profile=profile, mode=mode, targets=list(target or []), authorized=authorized,
                       use_nmap=not no_nmap, use_lynis=False if no_lynis else None,
                       use_trivy=False if no_trivy else None, use_integrity=False if no_integrity else None, offline=offline)
    try:
        a = run_assessment(opts, Runner(), lambda m: typer.echo(f"[lstk] {m}", err=True))
    except AuthorizationError as exc:
        typer.echo(f"Errore: {exc} Usa --authorized solo se autorizzato.", err=True)
        raise typer.Exit(2)
    except (TargetError, ValueError) as exc:
        raise typer.BadParameter(str(exc))
    payload = build_payload(a)
    typer.echo(json.dumps(payload, indent=2, ensure_ascii=False))
    if save:
        try:
            for fmt in ("json", "html"):
                typer.echo(f"[lstk] salvato: {write_report(payload, fmt)}", err=True)
        except ReportError as exc:
            typer.echo(f"Errore: {exc}", err=True)
            raise typer.Exit(1)
    if fail_on != "none":
        order = ["low", "medium", "high", "critical"]
        if a.summary.overall_level in order and order.index(a.summary.overall_level) >= order.index(fail_on):
            raise typer.Exit(3)


@app.command()
def verify(file: Path = typer.Argument(..., help="Rapporto .json/.html da verificare")):
    """Verifica hash (e firma HMAC se presente) di un rapporto."""
    res = verify_report(file)
    for ok, msg in res.checks:
        typer.echo(f"{'OK ' if ok else '-- ' if ok is None else 'ERR'} {msg}")
    typer.echo("Rapporto integro." if res.ok else "Verifica NON superata.")
    raise typer.Exit(0 if res.ok else 1)


if __name__ == "__main__":
    app()

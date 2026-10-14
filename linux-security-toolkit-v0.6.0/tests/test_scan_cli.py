import pytest
from typer.testing import CliRunner
from lstk import cli
from lstk.runner import CmdResult
from lstk.scan import AuthorizationError, ScanOptions, run_assessment


def test_external_target_requires_authorization(fake):
    with pytest.raises(AuthorizationError):
        run_assessment(ScanOptions(targets=["203.0.113.5"]), fake())


def test_invalid_mode_rejected(fake):
    with pytest.raises(ValueError):
        run_assessment(ScanOptions(mode="everything"), fake())


def test_missing_tools_make_assessment_partial_never_clean(fake):
    a = run_assessment(ScanOptions(mode="full"), fake())
    assert a.summary.partial and a.summary.grade != "A"
    names = {m.name: m.status for m in a.modules}
    assert names["nmap"] == "skipped" and names["lynis"] == "skipped"
    assert any(f.id == "NMAP-000" for f in a.findings) and any(f.id == "LYN-000" for f in a.findings)


def test_quick_mode_does_not_run_lynis_and_disabled_nmap_is_partial(fake):
    r = fake(binaries=["lynis", "nmap"])
    a = run_assessment(ScanOptions(mode="quick", use_nmap=False), r)
    assert not any(c[0].endswith("lynis") for c in r.calls)
    assert a.summary.partial


def test_scan_never_runs_mutating_commands(fake):
    r = fake(binaries=["apt-get", "systemctl", "lynis", "nmap", "ufw"])
    run_assessment(ScanOptions(mode="full"), r)
    bad = {"rm", "chmod", "chown", "sed", "mv", "tee", "kill", "systemctl-start"}
    for c in r.calls:
        assert c[0].split("/")[-1] not in bad
        assert not (c[0].endswith("systemctl") and c[1] in ("start", "stop", "enable", "disable", "restart"))
        assert not (c[0].endswith("apt-get") and "-s" not in c)


def test_cli_scan_args_parse():
    o = cli.parse_scan_args(["quick", "--target", "10.0.0.1", "--no-lynis"])
    assert o.mode == "quick" and o.targets == ["10.0.0.1"] and o.use_lynis is False
    assert cli.parse_scan_args([]).mode == "full"
    with pytest.raises(cli._ArgError):
        cli.parse_scan_args(["bogus"])


def test_cli_noninteractive_requires_authorized_flag():
    res = CliRunner().invoke(cli.app, ["scan", "--target", "203.0.113.5", "--no-lynis", "--no-nmap"])
    assert res.exit_code == 2


def test_cli_rejects_option_injection_target():
    res = CliRunner().invoke(cli.app, ["scan", "--target", "-oX /tmp/x", "--authorized"])
    assert res.exit_code != 0


def test_cli_command_unknown_and_findings_without_scan(capsys):
    cli.STATE["assessment"] = None
    assert cli.command("/nope") is True
    assert cli.command("/findings") is True
    assert cli.command("/exit") is False


def test_rich_markup_in_evidence_is_not_interpreted():
    from lstk.models import Finding
    from lstk.scan import Assessment
    from lstk.risk import assess
    f = Finding("X-1", "[bold red]titolo[/]", "high", "fail", "c", "[link=http://evil]click[/link] \x1b[31m", "r")
    s = assess([f])
    cli.STATE["assessment"] = Assessment("id", "a", "b", ScanOptions(), False, [f], [], s, [], {}, {})
    cli.command("/details X-1")
    cli.command("/findings all")


def test_all_finding_ids_unique(fake):
    a = run_assessment(ScanOptions(mode="deep"), fake())
    ids = [f.id for f in a.findings]
    assert len(ids) == len(set(ids))


def test_modes_select_new_modules(fake):
    def modules(mode, **kw):
        a = run_assessment(ScanOptions(mode=mode, **kw), fake())
        return {m.name: m.status for m in a.modules}
    assert modules("quick")["integrity"] == "skipped" and modules("quick")["trivy"] == "skipped"
    assert modules("deep")["integrity"] == "skipped"        # dpkg/rpm assenti nel fake -> skipped, ma tentato
    assert modules("deep")["trivy"] == "skipped"
    full = run_assessment(ScanOptions(mode="full"), fake())
    ids = {f.id for f in full.findings}
    assert {"TRV-000", "INT-001", "NMAP-000", "LYN-000"} <= ids and full.summary.partial


def test_trivy_not_called_in_quick_and_no_trivy_flag(fake):
    r = fake(binaries=["trivy", "dpkg"])
    run_assessment(ScanOptions(mode="quick"), r)
    run_assessment(ScanOptions(mode="full", use_trivy=False), r)
    assert not any(c[0].endswith("trivy") for c in r.calls)


def test_cli_parse_new_flags():
    o = cli.parse_scan_args(["full", "--no-trivy", "--no-integrity", "--offline"])
    assert o.use_trivy is False and o.use_integrity is False and o.offline is True
    o = cli.parse_scan_args(["deep"])
    assert o.trivy_enabled() is False and o.integrity_enabled() is True


def test_ensure_tools_declined_installs_nothing(fake, monkeypatch):
    called = []
    monkeypatch.setattr(cli.installer, "run_install", lambda *a, **k: called.append(1) or [])
    monkeypatch.setattr(cli.Confirm, "ask", lambda *a, **k: False)
    assert cli.ensure_tools(fake(binaries=["apt-get"]), ["nmap"]) is False
    assert called == []


def test_ensure_tools_accepted_runs_installer_and_records(fake, monkeypatch):
    from lstk.installer import InstallResult
    monkeypatch.setattr(cli.installer, "run_install", lambda *a, **k: [InstallResult("nmap", True, "/usr/bin/nmap", "gestore pacchetti", "t")])
    monkeypatch.setattr(cli.Confirm, "ask", lambda *a, **k: True)
    cli.STATE["installs"] = []
    assert cli.ensure_tools(fake(binaries=["apt-get"]), ["nmap"]) is True
    assert cli.STATE["installs"][0]["tool"] == "nmap"


def test_ensure_tools_nothing_missing_does_nothing(fake, monkeypatch):
    monkeypatch.setattr(cli.Confirm, "ask", lambda *a, **k: pytest.fail("non deve chiedere nulla"))
    assert cli.ensure_tools(fake(binaries=["nmap", "lynis", "trivy", "ss"]), ["nmap", "lynis", "trivy", "iproute2"]) is False


def test_noninteractive_scan_never_installs_without_flag(monkeypatch):
    called = []
    monkeypatch.setattr(cli.installer, "run_install", lambda *a, **k: called.append(1) or [])
    CliRunner().invoke(cli.app, ["scan", "--mode", "quick", "--no-nmap"])
    assert called == []


def test_install_and_doctor_commands_exist():
    res = CliRunner().invoke(cli.app, ["doctor"])
    assert res.exit_code == 0 and "Strumenti" in res.output
    res = CliRunner().invoke(cli.app, ["install", "bogus", "--yes"])
    assert res.exit_code == 2


def test_report_includes_installs(fake):
    from lstk.report import build_payload, render_html
    a = run_assessment(ScanOptions(mode="quick", use_nmap=False), fake(), installs=[{"tool": "nmap", "ok": True, "method": "m", "detail": "d", "at": "t"}])
    p = build_payload(a)
    assert p["installs"][0]["tool"] == "nmap" and "Installazioni eseguite" in render_html(p)


def test_table_format_shows_probability_impact_columns(fake, monkeypatch):
    monkeypatch.setattr(cli, "Runner", lambda: fake())
    res = CliRunner().invoke(cli.app, ["scan", "--mode", "quick", "--no-nmap", "--format", "table"])
    assert res.exit_code == 0
    assert "P×I" in res.output and "Registro dei rischi" in res.output and '"findings"' not in res.output


def test_bad_format_rejected():
    assert CliRunner().invoke(cli.app, ["scan", "--format", "xml"]).exit_code == 2

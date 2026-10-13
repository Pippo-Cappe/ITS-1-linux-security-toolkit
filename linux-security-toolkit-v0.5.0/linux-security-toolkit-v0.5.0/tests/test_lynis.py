from lstk.lynis import parse_report, report_to_findings, run_lynis

REPORT = """# Lynis report
lynis_version=3.0.9
hardening_index=61
lynis_tests_done=250
warning[]=FIRE-4512|iptables module(s) loaded, but no rules active|-|-|
suggestion[]=SSH-7440|Consider hardening SSH configuration|PermitRootLogin|Set PermitRootLogin to no|
suggestion[]=SSH-7440|Consider hardening SSH configuration|PermitRootLogin|Set PermitRootLogin to no|
suggestion[]=AUTH-9286|Configure minimum password age\x1b[31m|-|-|
vulnerable_package[]=openssl
junk line without equals
"""


def test_parse_report():
    r = parse_report(REPORT)
    assert (r.hardening_index, r.tests_done, r.version) == (61, 250, "3.0.9")
    assert len(r.warnings) == 1 and len(r.suggestions) == 3 and r.vulnerable_packages == ["openssl"]


def test_findings_mapping_dedup_and_sanitize():
    fs = {f.id: f for f in report_to_findings(parse_report(REPORT))}
    assert fs["LYN-FIRE-4512"].severity == "high" and fs["LYN-FIRE-4512"].status == "fail" and fs["LYN-FIRE-4512"].category == "firewall"
    assert fs["LYN-SSH-7440"].status == "warn" and "no" in fs["LYN-SSH-7440"].recommendation
    assert "\x1b" not in fs["LYN-AUTH-9286"].title
    assert fs["LYN-INDEX"].status == "info" and "61" in fs["LYN-INDEX"].evidence
    assert fs["LYN-VULNPKG"].status == "fail"
    assert sum(1 for f in fs.values() if f.id == "LYN-SSH-7440") == 1


def test_missing_index_is_unknown():
    assert report_to_findings(parse_report("warning[]=A-1|x|-|-"))[0].status == "unknown"


def test_lynis_missing(fake):
    o = run_lynis(fake(), root=True)
    assert o.status == "skipped" and o.findings[0].status == "manual"


def test_lynis_cmd_uses_pentest_when_not_root_and_private_paths(fake):
    from lstk.runner import CmdResult
    r = fake({"lynis": CmdResult(1, "", "err")}, binaries=["lynis"])
    o = run_lynis(r, root=False)
    cmd = r.calls[0]
    assert "--pentest" in cmd and "--report-file" in cmd and o.status == "failed"
    run_lynis(fake({"lynis": CmdResult(1)}, binaries=["lynis"]), root=True)


def test_ids_unique_and_vulnpkg_not_double_counted():
    rep = parse_report("hardening_index=50\nwarning[]=PKGS-7392|vuln|-|-\nsuggestion[]=X-1|a|-|-\nwarning[]=X-1|b|-|-\nvulnerable_package[]=openssl\n")
    ids = [f.id for f in report_to_findings(rep)]
    assert len(ids) == len(set(ids))
    assert "LYN-PKGS-7392" not in ids and "LYN-VULNPKG" in ids

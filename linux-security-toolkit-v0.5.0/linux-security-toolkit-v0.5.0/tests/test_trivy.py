import json
from lstk.runner import CmdResult
from lstk.trivy import build_command, build_findings, parse_report, run_trivy

SECRET_VALUE = "ghp_SUPERSECRETVALUE1234567890abcdefghij"
REPORT = {
    "Trivy": {"Version": "0.75.0"},
    "Metadata": {"OS": {"Family": "debian", "Name": "9.13", "EOSL": True}},
    "Results": [
        {"Target": "host (debian 9.13)", "Class": "os-pkgs", "Type": "debian",
         "Packages": [{"Name": "openssl"}, {"Name": "bash"}, {"Name": "zlib"}],
         "Vulnerabilities": [
             {"VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl", "InstalledVersion": "1.1.0", "FixedVersion": "1.1.1",
              "Severity": "CRITICAL", "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-0001"},
             {"VulnerabilityID": "CVE-2024-0002", "PkgName": "openssl", "InstalledVersion": "1.1.0", "Severity": "LOW",
              "PrimaryURL": "javascript:alert(1)"},
             {"VulnerabilityID": "CVE-2024-0003", "PkgName": "bash", "InstalledVersion": "4.4", "Severity": "MEDIUM"}]},
        {"Target": "home/deploy.env", "Class": "secret",
         "Secrets": [{"RuleID": "github-pat", "Category": "GitHub", "Severity": "CRITICAL", "Title": "GitHub Personal Access Token",
                      "StartLine": 3, "EndLine": 3, "Match": "TOKEN=" + SECRET_VALUE, "Code": {"Lines": [{"Content": SECRET_VALUE}]}}]},
    ],
}


def by_id(fs):
    return {f.id: f for f in fs}


def test_grouping_severity_and_likelihood():
    fs = build_findings(parse_report(REPORT), scanners="vuln,secret", offline=False)
    pk = [f for f in fs if f.id.startswith("TRV-openssl")][0]
    assert pk.severity == "critical" and pk.status == "warn" and pk.likelihood == 4    # critico con fix disponibile
    assert "CVE-2024-0001" in pk.evidence and "2 vulnerabilità" in pk.title
    bash = [f for f in fs if f.id.startswith("TRV-bash")][0]
    assert bash.severity == "medium" and bash.likelihood == 2                          # nessun fix
    assert pk.references == ["https://avd.aquasec.com/nvd/cve-2024-0001"]            # URL non http(s) scartato


def test_secret_content_is_never_reported():
    fs = build_findings(parse_report(REPORT), scanners="vuln,secret", offline=False)
    blob = json.dumps([f.to_dict() for f in fs])
    assert SECRET_VALUE not in blob and "SUPERSECRET" not in blob
    sec = [f for f in fs if f.id.startswith("TRV-SEC")][0]
    assert "/home/deploy.env" in sec.evidence and "righe 3-3" in sec.evidence and sec.severity == "critical"


def test_eol_and_summary():
    fs = by_id(build_findings(parse_report(REPORT), scanners="vuln,secret", offline=False))
    assert fs["TRV-EOL"].status == "fail"
    assert fs["TRV-001"].status == "info" and "pacchetti analizzati: 3" in fs["TRV-001"].evidence


def test_clean_scan_is_pass_but_secret_only_is_never_pass():
    clean = build_findings(parse_report({"Results": []}), scanners="vuln,secret", offline=False)
    assert clean[0].status == "pass"
    sec_only = build_findings(parse_report({"Results": []}), scanners="secret", offline=True)
    assert sec_only[0].status == "info" and "NON valutate" in sec_only[0].evidence


def test_command_privacy_flags():
    cmd = build_command("/usr/bin/trivy", "/tmp/o.json", scanners="vuln,secret", offline=True, skip_dirs=["/proc", "/sys"])
    assert "--offline-scan" in cmd and "--skip-db-update" in cmd and "--skip-version-check" in cmd
    assert cmd.count("--skip-dirs") == 2 and cmd[-1] == "/" and "--scanners" in cmd
    online = build_command("/usr/bin/trivy", "/tmp/o.json", scanners="vuln", offline=False, skip_dirs=[])
    assert "--offline-scan" in online and "--skip-db-update" not in online


def writer(report):
    def h(args):
        out = args[args.index("--output") + 1]
        open(out, "w").write(json.dumps(report))
        return CmdResult(0)
    return h


def test_run_ok(fake):
    o = run_trivy(fake({"trivy": writer(REPORT)}, binaries=["trivy"]), root=True)
    assert o.status == "ok" and any(f.id == "TRV-EOL" for f in o.findings)


def test_missing_trivy_is_manual(fake):
    o = run_trivy(fake(), root=True)
    assert o.status == "skipped" and o.findings[0].status == "manual"


def test_db_failure_falls_back_to_secrets_and_flags_vulns_unknown(fake):
    calls = []

    def h(args):
        calls.append(args)
        if "vuln,secret" in args:
            return CmdResult(1, "", "FATAL init error: DB error: failed to download vulnerability DB")
        return writer({"Results": REPORT["Results"][1:]})(args)
    o = run_trivy(fake({"trivy": h}, binaries=["trivy"]), root=True)
    ids = by_id(o.findings)
    assert o.status == "partial" and len(calls) == 2
    assert ids["TRV-000"].status == "unknown" and ids["TRV-000"].severity == "high"     # vulnerabilità NON valutate != sicure
    assert any(i.startswith("TRV-SEC") for i in ids)


def test_other_failure_is_unknown_not_pass(fake):
    o = run_trivy(fake({"trivy": CmdResult(2, "", "segfault")}, binaries=["trivy"]), root=True)
    assert o.status == "failed" and o.findings[0].status == "unknown"


def test_timeout_is_unknown(fake):
    o = run_trivy(fake({"trivy": CmdResult(124, "", "", True)}, binaries=["trivy"]), root=True)
    assert o.status == "failed" and o.findings[0].status == "unknown"


def test_malformed_report_does_not_crash(fake):
    def h(args):
        open(args[args.index("--output") + 1], "w").write("{not json")
        return CmdResult(0)
    o = run_trivy(fake({"trivy": h}, binaries=["trivy"]), root=True)
    assert o.findings[0].status == "unknown"

import pytest
from lstk.nmapscan import (TargetError, build_command, build_findings, parse_xml, run_nmap, validate_target)

XML = """<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun version="7.94">
<host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="6379"><state state="open"/><service name="redis" product="Redis"/></port></ports></host>
<host><status state="up"/><address addr="192.168.1.5" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.2"/></port>
<port protocol="tcp" portid="3306"><state state="closed"/></port>
<port protocol="tcp" portid="9999"><state state="open"/><service name="x" product="[red]evil[/red]"/></port>
<port protocol="tcp" portid="21"><state state="open"/><service name="ftp"/><script id="ftp-anon" output="Anonymous FTP login allowed"/></port>
</ports></host><runstats><finished elapsed="3.2"/><hosts up="2" down="0" total="2"/></runstats></nmaprun>"""


@pytest.mark.parametrize("bad", ["", "-oX /etc/x", "--script=x", "a b", "10.0.0.0/8", "::1", "host;rm -rf", "$(id)", "a" * 300, "10.0.0.0/33"])
def test_invalid_targets_rejected(bad):
    with pytest.raises(TargetError):
        validate_target(bad)


def test_target_classification():
    assert validate_target("localhost").is_self
    assert validate_target("127.0.0.1").is_self
    assert validate_target("192.168.1.5", ["192.168.1.5"]).is_self
    assert not validate_target("192.168.1.5").is_self
    assert not validate_target("example.org").is_self
    assert validate_target("192.168.1.0/24").count == 256


def test_command_has_no_shell_and_expected_flags():
    t = [validate_target("127.0.0.1")]
    q = build_command("/usr/bin/nmap", t, mode="quick", root=False)
    assert "-sT" in q and "--top-ports" in q and "-p-" not in q and "-Pn" in q and q[-1] == "127.0.0.1"
    f = build_command("/usr/bin/nmap", t, mode="full", root=True)
    assert "-sS" in f and "-p-" in f and "default" in f and "vuln" not in " ".join(f)
    net = build_command("/usr/bin/nmap", [validate_target("10.0.0.0/24")], mode="quick", root=False)
    assert "-Pn" not in net


def test_parse_and_findings_exposure_logic():
    res = parse_xml(XML)
    assert {(p.host, p.port) for p in res.ports} == {("127.0.0.1", 6379), ("192.168.1.5", 23), ("192.168.1.5", 22), ("192.168.1.5", 9999), ("192.168.1.5", 21)}
    fs = {f.id: f for f in build_findings(res, self_scan=True, mode="full", targets_desc="x", udp_ran=False)}
    assert fs["NMAP-TCP-6379"].status == "info"                      # solo loopback -> non esposto
    assert fs["NMAP-TCP-23"].severity == "critical" and fs["NMAP-TCP-23"].status == "fail"
    assert fs["NMAP-TCP-22"].status == "info"
    assert fs["NMAP-TCP-9999"].status == "manual"                    # servizio non classificato
    assert fs["NMAP-TCP-21"].severity == "high" and "anonimo" in fs["NMAP-TCP-21"].evidence.lower()
    assert "[red]evil" in fs["NMAP-TCP-9999"].evidence


def test_xml_with_entities_rejected():
    with pytest.raises(ValueError):
        parse_xml('<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x "y">]><nmaprun/>')
    with pytest.raises(ValueError):
        parse_xml("not xml")


def test_nmap_missing_gives_manual_finding(fake):
    out = run_nmap(fake(), [validate_target("127.0.0.1")], mode="quick", root=False)
    assert out.status == "skipped" and out.findings[0].status == "manual"


def test_nmap_failure_is_unknown_not_pass(fake):
    from lstk.runner import CmdResult
    r = fake({"nmap": CmdResult(1, "", "boom")}, binaries=["nmap"])
    out = run_nmap(r, [validate_target("127.0.0.1")], mode="quick", root=False)
    assert out.status == "failed" and out.findings[0].status == "unknown"


def test_host_down_is_not_reported_as_safe(fake):
    from lstk.runner import CmdResult
    xml = '<?xml version="1.0"?><nmaprun version="7"><runstats><finished elapsed="1"/><hosts up="0" down="1" total="1"/></runstats></nmaprun>'
    r = fake({"nmap": CmdResult(0, xml)}, binaries=["nmap"])
    out = run_nmap(r, [validate_target("10.1.1.1")], mode="quick", root=False)
    assert out.findings[0].id == "NMAP-001" and out.findings[0].status == "unknown"

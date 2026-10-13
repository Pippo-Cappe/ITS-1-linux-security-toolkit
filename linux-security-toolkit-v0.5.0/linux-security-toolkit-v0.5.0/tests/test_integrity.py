from lstk.integrity import parse_verify, run_integrity
from lstk.runner import CmdResult

DPKG = """??5??????   /usr/bin/ls
??5?????? c /etc/ssh/sshd_config
missing     /usr/share/doc/foo/README
missing     /usr/sbin/cron
missing   c /etc/foo.conf
??5??????   /opt/app/bin/tool
.M.......   /usr/bin/passwd
garbage line
"""
RPM = """S.5....T.  c /etc/httpd/conf/httpd.conf
..5......    /usr/lib64/libssl.so.3
missing   d /usr/share/doc/x
"""


def test_parse_dpkg():
    mod, mis, benign = parse_verify(DPKG)
    assert mod == ["/usr/bin/ls"]            # solo contenuto diverso in percorsi critici
    assert mis == ["/usr/sbin/cron"]         # i mancanti in doc/config sono ignorati
    assert benign >= 2                       # config modificata + file fuori dai percorsi critici


def test_parse_rpm():
    mod, mis, benign = parse_verify(RPM)
    assert mod == ["/usr/lib64/libssl.so.3"] and mis == []


def test_run_fail_pass_and_unsupported(fake):
    o = run_integrity(fake({"dpkg": CmdResult(1, DPKG)}, binaries=["dpkg"]), root=True)
    assert [f.id for f in o.findings] == ["INT-001", "INT-002"] and o.findings[0].status == "fail"
    o = run_integrity(fake({"dpkg": CmdResult(0, "")}, binaries=["dpkg"]), root=True)
    assert o.findings[0].status == "pass"
    o = run_integrity(fake(), root=True)
    assert o.status == "skipped" and o.findings[0].status == "manual"


def test_rpm_used_when_no_dpkg(fake):
    r = fake({"rpm": CmdResult(1, RPM)}, binaries=["rpm"])
    o = run_integrity(r, root=False)
    assert r.calls[0] == ["rpm", "-Va"] and o.findings[0].status == "fail" and "senza root" in o.findings[0].evidence


def test_failed_tool_is_unknown(fake):
    o = run_integrity(fake({"dpkg": CmdResult(2, "", "boom")}, binaries=["dpkg"]), root=True)
    assert o.status == "failed" and o.findings[0].status == "unknown"

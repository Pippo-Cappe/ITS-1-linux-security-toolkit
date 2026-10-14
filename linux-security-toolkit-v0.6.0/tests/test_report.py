import json
import os
import stat
import pytest
from lstk.models import Finding
from lstk.report import ReportError, build_payload, render_html, reports_dir, verify_report, write_report
from lstk.risk import assess
from lstk.scan import Assessment, ScanOptions


def make_assessment():
    fs = [Finding("A-1", "<script>alert(1)</script>", "high", "fail", "c", "<img src=x onerror=alert(1)>", "r", "high"),
          Finding("B-1", "ok", "info", "pass", "c", "e", "r")]
    s = assess(fs, [])
    return Assessment("11111111-aaaa", "t0", "t1", ScanOptions(mode="full"), True, fs, [], s, [], {"type": "locale", "targets": ["127.0.0.1"], "authorization": {"note": "n"}},
                      {"hostname": "h", "os": "o", "kernel": "k", "arch": "a", "user": "u"})


def test_html_escapes_everything_and_has_csp():
    html = render_html(build_payload(make_assessment()))
    assert "<script>alert(1)" not in html and "<img src=x" not in html
    assert "&lt;script&gt;" in html and "Content-Security-Policy" in html


def test_write_permissions_and_verify(tmp_path):
    d = tmp_path / "r"
    d.mkdir(mode=0o700)
    p = build_payload(make_assessment())
    path = write_report(p, "json", d)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert verify_report(path).ok


def test_tampering_is_detected(tmp_path):
    d = tmp_path / "r"
    d.mkdir(mode=0o700)
    path = write_report(build_payload(make_assessment()), "json", d)
    data = json.loads(path.read_text())
    data["summary"]["grade"] = "A"
    path.write_text(json.dumps(data, indent=2))
    res = verify_report(path)
    assert not res.ok and any(c[0] is False for c in res.checks)


def test_internal_hash_detects_tamper_even_without_sidecar(tmp_path):
    d = tmp_path / "r"
    d.mkdir(mode=0o700)
    path = write_report(build_payload(make_assessment()), "json", d)
    os.unlink(str(path) + ".sha256")
    data = json.loads(path.read_text())
    data["findings"][0]["title"] = "changed"
    path.write_text(json.dumps(data))
    assert not verify_report(path).ok


def test_hmac_signature(tmp_path, monkeypatch):
    monkeypatch.setenv("LSTK_SIGNING_KEY", "a-very-long-secret-key-123")
    d = tmp_path / "r"
    d.mkdir(mode=0o700)
    path = write_report(build_payload(make_assessment()), "json", d)
    assert verify_report(path).ok
    monkeypatch.setenv("LSTK_SIGNING_KEY", "another-very-long-secret-key")
    assert not verify_report(path).ok
    monkeypatch.delenv("LSTK_SIGNING_KEY")
    assert not verify_report(path).ok


def test_no_overwrite_and_symlink_dir_refused(tmp_path, monkeypatch):
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(real)
    monkeypatch.setenv("LSTK_REPORT_DIR", str(link))
    with pytest.raises(ReportError):
        reports_dir()


def test_world_writable_dir_refused(tmp_path, monkeypatch):
    d = tmp_path / "w"
    d.mkdir()
    os.chmod(d, 0o777)
    monkeypatch.setenv("LSTK_REPORT_DIR", str(d))
    with pytest.raises(ReportError):
        reports_dir()

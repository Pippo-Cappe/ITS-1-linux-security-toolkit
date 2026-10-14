import os
from lstk.runner import Runner, SAFE_PATH


def test_missing_binary_is_reported_not_raised():
    r = Runner().run(["definitely-not-a-binary-xyz"])
    assert r.rc == 127 and not r.ok


def test_runs_without_shell_and_records_execution():
    r = Runner()
    res = r.run(["echo", "a;b && c"])
    assert res.out == "a;b && c" and r.executions and r.executions[0].returncode == 0


def test_timeout_kills_process():
    r = Runner()
    res = r.run(["sleep", "5"], timeout=1)
    assert res.timed_out and res.rc == 124 and r.executions[0].timed_out


def test_environment_is_minimal_and_path_is_fixed(monkeypatch):
    monkeypatch.setenv("PATH", "/tmp/evil")
    monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")
    env = Runner._env()
    assert env["PATH"] == SAFE_PATH and "LD_PRELOAD" not in env


def test_path_hijack_is_ignored(tmp_path, monkeypatch):
    evil = tmp_path / "ss"
    evil.write_text("#!/bin/sh\necho pwned\n")
    evil.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    assert Runner().which("ss") != str(evil)

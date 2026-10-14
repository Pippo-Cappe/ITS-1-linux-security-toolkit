import hashlib
import io
import os
import tarfile
import pytest
from lstk import installer
from lstk.installer import InstallError, plan_install, run_install


def build_tar(members) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mode = 0o755
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def sha_of(members) -> str:
    return hashlib.sha256(build_tar(members)).hexdigest()


def fetcher(members, lie_hash=None):
    blob = build_tar(members)          # costruito una sola volta: contenuto e hash deterministici

    def f(url, dest, max_bytes=0):
        assert url.startswith("https://github.com/aquasecurity/trivy/releases/download/v")
        open(dest, "wb").write(blob)
        return lie_hash or hashlib.sha256(blob).hexdigest()
    return f


class Spy:
    def __init__(self, rc=0):
        self.calls, self.rc = [], rc

    def __call__(self, argv, to_stderr=False):
        assert isinstance(argv, list)           # mai una stringa/shell
        self.calls.append(list(argv))
        return self.rc


def test_missing_tools_uses_runner(fake):
    r = fake(binaries=["nmap"])
    assert installer.missing_tools(r) == ["lynis", "iproute2", "trivy"]


def test_plan_apt_only_missing_packages(fake):
    steps = plan_install(fake(binaries=["apt-get"]), ["nmap", "lynis"])
    assert steps[0].argv == ["/usr/bin/apt-get", "update"] and steps[0].optional
    assert steps[1].argv == ["/usr/bin/apt-get", "install", "-y", "lynis", "nmap"]


def test_plan_other_managers_and_package_names(fake):
    assert plan_install(fake(binaries=["dnf"]), ["iproute2", "nmap"])[0].argv == ["/usr/bin/dnf", "install", "-y", "iproute", "nmap"]
    assert plan_install(fake(binaries=["pacman"]), ["nmap"])[0].argv[:4] == ["/usr/bin/pacman", "-S", "--noconfirm", "--needed"]
    assert plan_install(fake(binaries=["zypper"]), ["nmap"])[0].argv[1] == "--non-interactive"


def test_plan_errors(fake):
    with pytest.raises(InstallError):
        plan_install(fake(), ["nmap"])                 # nessun gestore pacchetti
    with pytest.raises(InstallError):
        plan_install(fake(binaries=["apt-get"]), ["nmap; rm -rf /"])   # nome non in whitelist
    assert plan_install(fake(), ["trivy"])[0].download  # trivy non richiede il gestore pacchetti


def test_user_gets_sudo_root_does_not(fake):
    steps = plan_install(fake(binaries=["apt-get", "sudo"]), ["nmap"])
    spy = Spy()
    run_install(fake(binaries=["apt-get", "sudo", "nmap"]), steps, root=False, log=lambda m: None, exec_fn=spy, names=["nmap"])
    assert all(c[:2] == ["/usr/bin/sudo", "--"] for c in spy.calls)
    spy = Spy()
    run_install(fake(binaries=["apt-get", "nmap"]), steps, root=True, log=lambda m: None, exec_fn=spy, names=["nmap"])
    assert all(c[0] == "/usr/bin/apt-get" for c in spy.calls)


def test_no_sudo_no_root_is_error_not_silent(fake):
    steps = plan_install(fake(binaries=["apt-get"]), ["nmap"])
    res = run_install(fake(binaries=["apt-get"]), steps, root=False, log=lambda m: None, exec_fn=Spy(), names=["nmap"])
    assert res and not res[0].ok and "sudo" in res[0].detail


def test_failure_stops_and_is_reported(fake):
    steps = plan_install(fake(binaries=["dnf"]), ["nmap"])
    res = run_install(fake(binaries=["dnf"]), steps, root=True, log=lambda m: None, exec_fn=Spy(rc=1), names=["nmap"])
    assert not res[0].ok and "codice 1" in res[0].detail


def test_apt_update_failure_is_not_fatal(fake):
    steps = plan_install(fake(binaries=["apt-get"]), ["nmap"])
    calls = []

    def ex(argv, to_stderr=False):
        calls.append(argv)
        return 100 if argv[1] == "update" else 0
    res = run_install(fake(binaries=["apt-get", "nmap"]), steps, root=True, log=lambda m: None, exec_fn=ex, names=["nmap"])
    assert len(calls) == 2 and res[-1].ok


def test_result_not_ok_if_binary_still_missing_after_install(fake):
    steps = plan_install(fake(binaries=["apt-get"]), ["nmap"])
    res = run_install(fake(binaries=["apt-get"]), steps, root=True, log=lambda m: None, exec_fn=Spy(), names=["nmap"])
    assert not res[-1].ok and "non trovato" in res[-1].detail


def test_trivy_verified_download_installs(fake, tmp_path, monkeypatch):
    members = {"trivy": b"#!/bin/sh\necho trivy\n", "LICENSE": b"x"}
    f = fetcher(members)
    monkeypatch.setitem(installer.TRIVY_SHA256, "64bit", hashlib.sha256(build_tar(members)).hexdigest())
    spy = Spy()
    target = installer.install_trivy(fake(binaries=["install"]), root=True, dest_dir="/usr/local/bin", machine="x86_64",
                                     fetch=f, exec_fn=spy)
    assert target == "/usr/local/bin/trivy"
    argv = spy.calls[0]
    assert argv[:3] == ["/usr/bin/install", "-m", "0755"] and argv[-1] == "/usr/local/bin/trivy"


def test_trivy_wrong_hash_installs_nothing(fake):
    spy = Spy()
    with pytest.raises(InstallError, match="NON coincide"):
        installer.install_trivy(fake(binaries=["install"]), root=True, machine="x86_64",
                                fetch=fetcher({"trivy": b"evil"}), exec_fn=spy)
    assert spy.calls == []


@pytest.mark.parametrize("members", [{"../../etc/cron.d/x": b"x"}, {"bin/trivy": b"x"}, {"README": b"x"}])
def test_trivy_archive_without_exact_member_rejected(fake, tmp_path, monkeypatch, members):
    monkeypatch.setitem(installer.TRIVY_SHA256, "64bit", sha_of(members))     # hash corretto, ma contenuto non conforme
    spy = Spy()
    with pytest.raises(InstallError) as exc:
        installer.install_trivy(fake(binaries=["install"]), root=True, machine="x86_64", fetch=fetcher(members), exec_fn=spy)
    assert "NON coincide" not in str(exc.value)       # deve fallire sul contenuto, non sull'hash
    assert spy.calls == []


def test_trivy_unsupported_arch_and_non_https(fake):
    with pytest.raises(InstallError, match="architettura"):
        installer.install_trivy(fake(binaries=["install"]), root=True, machine="riscv64", fetch=fetcher({}), exec_fn=Spy())
    with pytest.raises(InstallError, match="HTTPS"):
        installer.fetch_file("http://github.com/x", "/tmp/x")


def test_pinned_hashes_look_like_sha256():
    assert all(len(v) == 64 and int(v, 16) >= 0 for v in installer.TRIVY_SHA256.values())

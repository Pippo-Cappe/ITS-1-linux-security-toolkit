import pytest
from lstk.remediation import RemediationError, apply_file_change, preview_file_change

def test_preview_contains_diff(tmp_path):
    p = tmp_path / "sample.conf"
    p.write_text("old\n")
    diff = preview_file_change(str(p), "new\n")
    assert "-old" in diff and "+new" in diff

def test_requires_confirmation(tmp_path):
    p = tmp_path / "sample.conf"
    p.write_text("old\n")
    with pytest.raises(RemediationError):
        apply_file_change(str(p), "new\n", confirmed=False)
    assert p.read_text() == "old\n"

def test_backup_before_change(tmp_path):
    p = tmp_path / "sample.conf"
    p.write_text("old\n")
    backup_dir = tmp_path / "backups"
    backup = apply_file_change(str(p), "new\n", confirmed=True, backup_dir=str(backup_dir))
    assert p.read_text() == "new\n"
    assert backup.read_text() == "old\n"


def test_symlink_target_is_preserved(tmp_path):
    real = tmp_path / "real.conf"
    real.write_text("old\n")
    link = tmp_path / "link.conf"
    link.symlink_to(real)
    apply_file_change(str(link), "new\n", confirmed=True, backup_dir=str(tmp_path / "b"))
    assert link.is_symlink() and real.read_text() == "new\n"


def test_permissions_preserved(tmp_path):
    import os
    p = tmp_path / "s.conf"
    p.write_text("old\n")
    os.chmod(p, 0o600)
    apply_file_change(str(p), "new\n", confirmed=True, backup_dir=str(tmp_path / "b"))
    assert (p.stat().st_mode & 0o777) == 0o600

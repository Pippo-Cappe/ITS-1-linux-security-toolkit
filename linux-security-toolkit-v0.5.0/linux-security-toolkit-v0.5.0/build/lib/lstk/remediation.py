"""Safe, opt-in file remediation primitives. No system fixes are wired by default."""
from __future__ import annotations
import difflib
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path

class RemediationError(RuntimeError):
    pass

def preview_file_change(path: str, new_text: str) -> str:
    target = Path(path)
    try:
        old = target.read_text(errors="replace").splitlines(keepends=True)
    except OSError as exc:
        raise RemediationError(f"Impossibile leggere {target}: {exc}") from exc
    new = new_text.splitlines(keepends=True)
    return "".join(difflib.unified_diff(old, new, fromfile=str(target), tofile=f"{target} (proposta)"))

def apply_file_change(path: str, new_text: str, *, confirmed: bool = False, backup_dir: str | None = None) -> Path:
    """Apply only when caller explicitly confirms; creates a timestamped backup first."""
    if not confirmed:
        raise RemediationError("Modifica annullata: serve conferma esplicita.")
    target = Path(path).resolve()   # segue i link simbolici: si modifica il file reale, il link resta intatto
    if not target.is_file():
        raise RemediationError(f"Il file non esiste o non è regolare: {target}")
    try:
        original_stat = target.stat()
        backup_root = Path(backup_dir) if backup_dir else target.parent / ".lstk-backups"
        backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        backup = backup_root / f"{target.name}.{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}.bak"
        shutil.copy2(target, backup)
        fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.lstk-", dir=str(target.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(new_text)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_name, original_stat.st_mode)
            try:
                os.chown(temp_name, original_stat.st_uid, original_stat.st_gid)  # solo se permesso (root)
            except OSError:
                pass
            os.replace(temp_name, target)
            dir_fd = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
        return backup
    except OSError as exc:
        raise RemediationError(f"Modifica non completata: {exc}") from exc

"""Esecuzione controllata di comandi esterni.

- nessuna shell (argv come lista);
- binari risolti solo in directory di sistema (anti PATH-hijacking, importante se eseguito come root);
- ambiente minimo e stdin chiuso;
- timeout con terminazione dell'intero gruppo di processi;
- ogni esecuzione è registrata e finisce nel rapporto (trasparenza).
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime

SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
MAX_OUTPUT = 2_000_000


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


@dataclass
class CmdResult:
    rc: int
    out: str = ""
    err: str = ""
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.timed_out


@dataclass
class Execution:
    argv: list
    started_at: str
    duration_s: float
    returncode: int
    timed_out: bool

    def to_dict(self) -> dict:
        return asdict(self)


class Runner:
    def __init__(self) -> None:
        self.executions: list[Execution] = []

    def which(self, name: str) -> str | None:
        return shutil.which(name, path=SAFE_PATH)

    @staticmethod
    def _env() -> dict[str, str]:
        env = {"PATH": SAFE_PATH, "LC_ALL": "C", "LANG": "C", "TERM": "dumb"}
        for key in ("HOME", "USER", "LOGNAME"):
            if key in os.environ:
                env[key] = os.environ[key]
        return env

    @staticmethod
    def _kill(proc: subprocess.Popen) -> None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            try:
                proc.kill()
            except OSError:
                pass

    def run(self, args: list[str], timeout: int = 10) -> CmdResult:
        exe = args[0]
        if not os.path.isabs(exe):
            resolved = self.which(exe)
            if resolved is None:
                return CmdResult(127, "", f"comando non trovato: {exe}")
            args = [resolved, *args[1:]]
        started = datetime.now().astimezone().isoformat(timespec="seconds")
        t0 = time.monotonic()
        try:
            proc = subprocess.Popen(
                args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, errors="replace", env=self._env(), start_new_session=True,
            )
        except OSError as exc:
            return CmdResult(127, "", str(exc))
        timed_out = False
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._kill(proc)
            out, err = proc.communicate()
        except BaseException:
            self._kill(proc)
            proc.wait()
            raise
        rc = 124 if timed_out else proc.returncode
        self.executions.append(Execution(list(args), started, round(time.monotonic() - t0, 2), rc, timed_out))
        return CmdResult(rc, (out or "").strip()[:MAX_OUTPUT], (err or "").strip()[:MAX_OUTPUT], timed_out)

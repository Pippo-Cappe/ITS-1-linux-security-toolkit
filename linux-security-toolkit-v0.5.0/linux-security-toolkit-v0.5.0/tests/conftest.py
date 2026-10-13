import os
import pytest
from lstk.runner import CmdResult, Runner


class FakeRunner(Runner):
    """Runner deterministico: nessun comando reale viene eseguito."""

    def __init__(self, responses=None, binaries=()):
        super().__init__()
        self.responses = responses or {}
        self.binaries = set(binaries)
        self.calls = []

    def which(self, name):
        return f"/usr/bin/{name}" if name in self.binaries else None

    def run(self, args, timeout=10):
        self.calls.append(list(args))
        h = self.responses.get(os.path.basename(args[0]))
        if h is None:
            return CmdResult(127, "", "non trovato")
        return h(args) if callable(h) else h


@pytest.fixture
def fake():
    return FakeRunner

from lstk.models import Finding

def test_finding_serializes():
    f = Finding("X-1", "Test", "low", "pass", "test", "evidence", "recommendation")
    d = f.to_dict()
    assert d["id"] == "X-1"
    assert d["status"] == "pass"
    assert d["confidence"] == "medium"


import pytest


def test_finding_rejects_invalid_values():
    with pytest.raises(ValueError):
        Finding("X", "t", "urgent", "pass", "c", "e", "r")
    with pytest.raises(ValueError):
        Finding("X", "t", "low", "ok", "c", "e", "r")


def test_finding_sanitizes_terminal_escapes_and_bidi():
    f = Finding("X\x1b[2J", "t", "low", "pass", "c", "ev\x1b]0;pwn\x07il\u202etxt", "r")
    assert "\x1b" not in f.id and "\x1b" not in f.evidence and "\x07" not in f.evidence
    assert "\u202e" not in f.evidence

"""Modello dati dei finding, con sanificazione dei testi provenienti da fonti esterne."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")
STATUSES = ("pass", "fail", "warn", "manual", "unknown", "info")
CONFIDENCES = ("high", "medium", "low")

# Caratteri di controllo (ESC inclusi), C1 e override bidirezionali: possono essere
# iniettati da banner di servizi remoti o da file e ingannare terminale/report.
_CONTROL = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


def sanitize(value: object, limit: int = 20000) -> str:
    text = _CONTROL.sub("", str(value))
    if len(text) > limit:
        text = text[:limit] + "… [troncato]"
    return text


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    status: str
    category: str
    evidence: str
    recommendation: str
    confidence: str = "medium"
    source: str = "native"          # native | nmap | lynis
    likelihood: int = 0             # 1-5, 0 = da calcolare
    impact: int = 0                 # 1-5, 0 = da calcolare
    risk_score: int = 0             # likelihood * impact
    risk_level: str = "none"        # critical|high|medium|low|none|unverified
    references: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"severity non valida: {self.severity!r}")
        if self.status not in STATUSES:
            raise ValueError(f"status non valido: {self.status!r}")
        if self.confidence not in CONFIDENCES:
            raise ValueError(f"confidence non valida: {self.confidence!r}")
        for name in ("id", "title", "category", "evidence", "recommendation", "source"):
            setattr(self, name, sanitize(getattr(self, name)))
        self.references = [sanitize(r, 500) for r in self.references]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

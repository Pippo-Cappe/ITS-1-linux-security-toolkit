"""Risk assessment: probabilità x impatto (matrice 5x5), punteggio di postura e voto.

Metodologia completa in docs/METHODOLOGY.md. Il punteggio è indicativo e non una certificazione.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .models import Finding

IMPACT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
LEVELS = ("critical", "high", "medium", "low")
PENALTY_WEIGHT = {"critical": 20, "high": 8, "medium": 3, "low": 1}
PENALTY_CAP = {"critical": 100, "high": 45, "medium": 30, "low": 15}
SCORED = ("fail", "warn")
UNVERIFIED = ("manual", "unknown")
CONCLUSIVE = ("pass", "fail", "warn")
GRADES = "ABCDF"


def level_for(score: int) -> str:
    if score >= 20:
        return "critical"
    if score >= 12:
        return "high"
    if score >= 8:
        return "medium"
    if score >= 1:
        return "low"
    return "none"


def score_finding(f: Finding) -> Finding:
    """Calcola probabilità, impatto, punteggio e livello (modifica f in place)."""
    if f.status in SCORED:
        impact = f.impact or IMPACT[f.severity]
        if f.likelihood:
            lik = f.likelihood
        else:
            lik = 4 if f.status == "fail" else 3
            if f.status == "fail" and f.confidence == "high":
                lik = 5
            if f.confidence == "low":
                lik -= 1
        lik = max(1, min(5, lik))
        f.impact, f.likelihood = impact, lik
        f.risk_score = impact * lik
        f.risk_level = level_for(f.risk_score)
    elif f.status in UNVERIFIED:
        f.impact, f.likelihood, f.risk_score = f.impact or IMPACT[f.severity], 0, 0
        f.risk_level = "unverified"
    else:
        f.impact = f.likelihood = f.risk_score = 0
        f.risk_level = "none"
    return f


@dataclass
class RiskSummary:
    posture_score: int = 100
    grade: str = "A"
    overall_level: str = "none"
    counts: dict = field(default_factory=dict)
    unverified: int = 0
    passed: int = 0
    coverage_pct: int = 100
    partial: bool = False
    partial_reasons: list = field(default_factory=list)
    grade_notes: list = field(default_factory=list)
    matrix: list = field(default_factory=list)     # [likelihood-1][impact-1] -> conteggio
    top_risks: list = field(default_factory=list)
    lynis_hardening_index: int | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _worse(a: str, b: str) -> str:
    return a if GRADES.index(a) >= GRADES.index(b) else b


def assess(findings: list[Finding], partial_reasons: list[str] | None = None,
           lynis_index: int | None = None) -> RiskSummary:
    reasons = list(partial_reasons or [])
    for f in findings:
        score_finding(f)
    counts = {lvl: 0 for lvl in LEVELS}
    matrix = [[0] * 5 for _ in range(5)]
    for f in findings:
        if f.risk_level in counts:
            counts[f.risk_level] += 1
            matrix[f.likelihood - 1][f.impact - 1] += 1
    unverified = sum(1 for f in findings if f.status in UNVERIFIED)
    passed = sum(1 for f in findings if f.status == "pass")
    conclusive = sum(1 for f in findings if f.status in CONCLUSIVE)
    total = conclusive + unverified
    coverage = round(100 * conclusive / total) if total else 100
    if coverage < 70:
        reasons.append(f"copertura dei controlli conclusivi {coverage}% (< 70%)")

    penalty = sum(min(counts[l] * PENALTY_WEIGHT[l], PENALTY_CAP[l]) for l in LEVELS)
    posture = max(0, 100 - penalty)
    grade = "A" if posture >= 90 else "B" if posture >= 80 else "C" if posture >= 65 else "D" if posture >= 50 else "F"
    notes: list[str] = []
    if counts["critical"] >= 1 and grade in "AB":
        grade = _worse(grade, "C")
        notes.append("voto limitato a C: presente almeno un rischio critico")
    if reasons and grade == "A":
        grade = "B"
        notes.append("voto limitato a B: valutazione parziale, il livello A non è assegnabile")
    overall = next((l for l in LEVELS if counts[l]), "none")
    ranked = sorted((f for f in findings if f.risk_level in LEVELS),
                    key=lambda f: (-f.risk_score, LEVELS.index(f.risk_level), f.id))
    return RiskSummary(posture, grade, overall, counts, unverified, passed, coverage,
                       bool(reasons), reasons, notes, matrix, [f.id for f in ranked[:10]], lynis_index)

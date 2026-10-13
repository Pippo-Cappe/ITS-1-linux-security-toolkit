from lstk.models import Finding
from lstk.risk import assess, level_for, score_finding


def F(sev, status, conf="medium", **kw):
    return Finding("T", "t", sev, status, "c", "e", "r", conf, **kw)


def test_levels():
    assert [level_for(s) for s in (0, 4, 8, 12, 20)] == ["none", "low", "medium", "high", "critical"]


def test_fail_high_confidence_high_severity_is_critical():
    f = score_finding(F("high", "fail", "high"))
    assert (f.likelihood, f.impact, f.risk_score, f.risk_level) == (5, 4, 20, "critical")


def test_pass_info_are_not_scored_and_manual_is_unverified():
    assert score_finding(F("high", "pass")).risk_level == "none"
    f = score_finding(F("high", "manual"))
    assert f.risk_level == "unverified" and f.risk_score == 0


def test_explicit_likelihood_is_respected_and_clamped():
    assert score_finding(F("medium", "warn", likelihood=2)).risk_score == 6
    assert score_finding(F("critical", "fail", likelihood=9)).likelihood == 5


def test_clean_complete_assessment_is_A():
    s = assess([F("info", "pass"), F("high", "pass")])
    assert (s.grade, s.posture_score, s.partial) == ("A", 100, False)


def test_partial_assessment_cannot_get_A():
    s = assess([F("high", "pass")], ["Lynis non eseguito"])
    assert s.grade == "B" and s.partial


def test_critical_caps_grade_at_C():
    s = assess([F("critical", "fail", "high")])
    assert s.grade in ("C", "D", "F") and s.overall_level == "critical"


def test_penalty_caps_avoid_low_noise_domination():
    s = assess([F("low", "warn") for _ in range(200)])
    assert s.posture_score == 85


def test_unverified_counts_and_coverage():
    s = assess([F("low", "pass"), F("low", "unknown"), F("low", "manual"), F("low", "unknown")])
    assert s.unverified == 3 and s.coverage_pct == 25 and s.partial

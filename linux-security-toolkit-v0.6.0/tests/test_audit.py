from lstk.audit import collect

def test_collect_returns_findings():
    findings = collect("desktop", deep=False)
    assert findings
    assert any(f.id == "SYS-001" for f in findings)
    assert all(f.id and f.title and f.status for f in findings)

def test_deep_adds_service_check():
    quick = collect("desktop", deep=False)
    deep = collect("server", deep=True)
    assert len(deep) >= len(quick)
    assert any(f.id == "SRV-001" for f in deep)

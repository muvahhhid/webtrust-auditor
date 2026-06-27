from webtrust_auditor.scoring import calculate_score, count_findings_by_severity


def test_calculate_score_with_no_findings():
    result = calculate_score([])

    assert result["score"] == 100
    assert result["rating"] == "A"


def test_calculate_score_with_mixed_findings():
    findings = [
        {"severity": "High"},
        {"severity": "Medium"},
        {"severity": "Low"},
        {"severity": "Info"},
    ]

    result = calculate_score(findings)

    assert result["score"] == 60
    assert result["rating"] == "C"


def test_count_findings_by_severity():
    findings = [
        {"severity": "High"},
        {"severity": "High"},
        {"severity": "Medium"},
        {"severity": "Low"},
        {"severity": "Info"},
    ]

    counts = count_findings_by_severity(findings)

    assert counts["High"] == 2
    assert counts["Medium"] == 1
    assert counts["Low"] == 1
    assert counts["Info"] == 1
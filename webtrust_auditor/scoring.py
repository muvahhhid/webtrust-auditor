SEVERITY_PENALTIES = {
    "High": 25,
    "Medium": 10,
    "Low": 5,
    "Info": 0,
}


def calculate_score(findings: list[dict]) -> dict:
    """
    Calculates a score from 0 to 100 based on finding severities.

    Observations should not be passed here because they are not security findings.
    """
    score = 100
    severity_counts = get_severity_counts(findings)

    for severity, count in severity_counts.items():
        penalty = SEVERITY_PENALTIES.get(severity, 0)
        score -= penalty * count

    score = max(score, 0)

    return {
        "score": score,
        "rating": get_rating(score),
        "severity_counts": severity_counts,
    }


def get_severity_counts(findings: list[dict]) -> dict:
    """
    Counts findings by severity.
    """
    counts = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
    }

    for finding in findings:
        severity = finding.get("severity", "Info")

        if severity not in counts:
            severity = "Info"

        counts[severity] += 1

    return counts


def count_findings_by_severity(findings: list[dict]) -> dict:
    """
    Backward-compatible alias for older tests and older code.
    """
    return get_severity_counts(findings)


def get_rating(score: int) -> str:
    if score >= 90:
        return "A"

    if score >= 75:
        return "B"

    if score >= 60:
        return "C"

    if score >= 40:
        return "D"

    return "F"
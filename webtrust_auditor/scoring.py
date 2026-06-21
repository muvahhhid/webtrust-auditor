SEVERITY_PENALTIES = {
    "High": 25,
    "Medium": 10,
    "Low": 5,
    "Info": 0
}


def calculate_score(findings: list) -> dict:
    """
    Calculates a simple security readiness score based on findings.

    The score starts at 100.
    Each finding reduces the score depending on severity.
    """
    score = 100
    deductions = []

    for finding in findings:
        severity = finding.get("severity", "Info")
        penalty = SEVERITY_PENALTIES.get(severity, 0)

        score -= penalty

        deductions.append({
            "title": finding.get("title", "Unknown finding"),
            "severity": severity,
            "penalty": penalty
        })

    if score < 0:
        score = 0

    return {
        "score": score,
        "rating": get_rating(score),
        "total_penalty": 100 - score,
        "deductions": deductions
    }


def get_rating(score: int) -> str:
    """
    Converts a numeric score into a simple rating.
    """
    if score >= 90:
        return "A"

    if score >= 75:
        return "B"

    if score >= 60:
        return "C"

    if score >= 40:
        return "D"

    return "F"


def count_findings_by_severity(findings: list) -> dict:
    """
    Counts findings by severity level.
    """
    counts = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0
    }

    for finding in findings:
        severity = finding.get("severity", "Info")

        if severity not in counts:
            counts["Info"] += 1
        else:
            counts[severity] += 1

    return counts
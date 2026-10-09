
SEVERITY_WEIGHTS = {
    "INFO": 0,
    "LOW": 20,
    "MEDIUM": 40,
    "HIGH": 70,
    "CRITICAL": 90,
}


def score_findings(findings: list[dict]) -> dict:
    """
    Calculate a transparent, heuristic risk score from findings.

    This is a prioritization score, not a probability or CVSS score.
    Repeated findings of the same severity have diminishing impact.
    """

    normalized = []
    seen = set()

    for finding in findings:
        severity = str(
            finding.get("severity", "INFO")
        ).upper()

        if severity not in SEVERITY_WEIGHTS:
            severity = "INFO"

        # Avoid counting the same finding ID repeatedly.
        finding_id = finding.get("id") or finding.get("cve_id")

        identity = (
            finding.get("target"),
            finding_id,
            finding.get("port"),
        )

        if identity in seen:
            continue

        seen.add(identity)
        normalized.append({
            **finding,
            "severity": severity,
        })

    # Use the strongest finding as the base and add diminishing
    # contributions from additional findings.
    weights = sorted(
        (
            SEVERITY_WEIGHTS[item["severity"]]
            for item in normalized
        ),
        reverse=True,
    )

    score = 0.0

    for index, weight in enumerate(weights):
        score += weight * (0.5 ** index)

    score = min(round(score), 100)

    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "INFO"

    severity_counts = {
        severity: sum(
            1 for item in normalized
            if item["severity"] == severity
        )
        for severity in SEVERITY_WEIGHTS
    }

    return {
        "risk_score": score,
        "risk_level": level,
        "finding_count": len(normalized),
        "severity_counts": severity_counts,
        "scoring_method": "heuristic prioritization; not CVSS or probability",
        "findings": normalized,
    }

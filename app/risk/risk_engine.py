
SEVERITY_WEIGHTS = {
    "INFO": 0,
    "LOW": 20,
    "MEDIUM": 40,
    "HIGH": 70,
    "CRITICAL": 90,
}


def score_findings(findings: list[dict]) -> dict:
    """Prioritize security findings using a transparent heuristic."""

    unique_findings = []
    seen = set()

    for finding in findings:
        item = finding.copy()
        severity = str(item.get("severity", "INFO")).upper()

        if severity not in SEVERITY_WEIGHTS:
            severity = "INFO"

        item["severity"] = severity

        identity = (
            item.get("target", ""),
            item.get("id", item.get("cve_id", item.get("title", ""))),
            item.get("port"),
        )

        if identity in seen:
            continue

        seen.add(identity)
        unique_findings.append(item)

    ordered = sorted(
        unique_findings,
        key=lambda item: SEVERITY_WEIGHTS[item["severity"]],
        reverse=True,
    )

    score = 0.0

    for index, finding in enumerate(ordered):
        weight = SEVERITY_WEIGHTS[finding["severity"]]
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
            1 for item in unique_findings
            if item["severity"] == severity
        )
        for severity in SEVERITY_WEIGHTS
    }

    return {
        "risk_score": score,
        "risk_level": level,
        "finding_count": len(unique_findings),
        "severity_counts": severity_counts,
        "scoring_method": (
            "Heuristic prioritization; not CVSS or probability"
        ),
        "findings": unique_findings,
    }

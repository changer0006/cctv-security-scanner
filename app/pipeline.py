
import json
from pathlib import Path
from datetime import datetime, timezone

from app.fingerprint.fingerprint import fingerprint_device
from app.checks.security_assessment import assess_device
from app.vulnerability.cve_matcher import match_vulnerabilities
from app.risk.risk_engine import score_findings


def analyze_scan(scan_result: dict, database_path=None) -> dict:
    """Combine fingerprinting, security checks, CVE candidates, and risk."""

    fingerprint = fingerprint_device(scan_result)
    findings = assess_device(scan_result)

    cve_error = None

    try:
        if database_path is None:
            cve_candidates = match_vulnerabilities(scan_result)
        else:
            cve_candidates = match_vulnerabilities(
                scan_result, database_path=database_path
            )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        cve_candidates = []
        cve_error = str(error)

    # Give CVE candidates a consistent structure for risk scoring.
    risk_findings = list(findings)

    for candidate in cve_candidates:
        risk_item = candidate.copy()
        risk_item["id"] = candidate.get("cve_id") or "CVE-CANDIDATE"
        risk_item["title"] = (
            f"Potential match: {candidate.get('cve_id') or 'unidentified CVE'}"
        )
        risk_findings.append(risk_item)

    risk = score_findings(risk_findings)

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": scan_result.get("target", "unknown"),
        "scan_status": scan_result.get("status", "unknown"),
        "services": scan_result.get("ports", []),
        "fingerprint": fingerprint,
        "security_findings": findings,
        "cve_candidates": cve_candidates,
        "cve_database_error": cve_error,
        "risk": risk,
        "limitations": [
            "Device fingerprinting is heuristic, not a probability.",
            "Exposure findings do not prove exploitability.",
            "CVE matches are candidates and require validation.",
            "Only exact product/version matches are currently supported.",
            "An empty finding list does not prove the device is secure.",
        ],
    }


def save_report(result: dict, output_dir="reports") -> str:
    """Save a structured JSON report and return its path."""

    report_dir = Path(output_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    safe_target = "".join(
        char if char.isalnum() or char in ".-_" else "_"
        for char in result.get("target", "unknown")
    )
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = report_dir / f"scan_{safe_target}_{timestamp}.json"

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(result, file, indent=2, ensure_ascii=False)

    return str(report_path)

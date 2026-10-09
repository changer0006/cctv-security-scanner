
import json
from pathlib import Path
from datetime import datetime, timezone

from app.fingerprint.fingerprint import fingerprint_device
from app.checks.security_assessment import assess_device
from app.checks.http_checks import check_http_headers
from app.vulnerability.cve_matcher import match_vulnerabilities
from app.risk.risk_engine import score_findings


def analyze_scan(scan_result: dict, database_path=None) -> dict:
    """Combine device fingerprinting and security checks."""

    fingerprint = fingerprint_device(scan_result)
    findings = assess_device(scan_result)

    target = scan_result.get("target", "unknown")
    ports = scan_result.get("ports", [])

    # Check HTTP headers only on services identified as HTTP(S).
    http_checks = []
    http_findings = []
    checked_urls = set()

    for port_info in ports:
        if port_info.get("state") != "open":
            continue

        port = port_info.get("port")
        service = (port_info.get("service") or "").lower()
        product = (port_info.get("product") or "").lower()

        is_https = (
            port in (443, 8443)
            or "https" in service
            or "ssl/http" in service
            or "https" in product
        )

        is_http = (
            port in (80, 8080)
            or service == "http"
            or service.endswith("/http")
            or "http" in product
        )

        if not (is_http or is_https):
            continue

        scheme = "https" if is_https else "http"
        url = f"{scheme}://{target}:{port}/"

        if url in checked_urls:
            continue
        checked_urls.add(url)

        check_result = check_http_headers(url)
        http_checks.append(check_result)

        for finding in check_result.get("findings", []):
            item = finding.copy()
            item["target"] = target
            item["port"] = port
            item["url"] = url
            http_findings.append(item)

    # Match against the local CVE database.
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

    # Include preliminary findings, HTTP findings, and CVE candidates
    # in the risk engine.
    risk_findings = list(findings) + list(http_findings)

    for candidate in cve_candidates:
        risk_item = candidate.copy()
        risk_item["id"] = (
            candidate.get("cve_id") or "CVE-CANDIDATE"
        )
        risk_item["title"] = (
            f"Potential match: "
            f"{candidate.get('cve_id') or 'unidentified CVE'}"
        )
        risk_findings.append(risk_item)

    risk = score_findings(risk_findings)

    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "scan_status": scan_result.get("status", "unknown"),
        "services": ports,
        "fingerprint": fingerprint,
        "security_findings": findings,
        "http_checks": http_checks,
        "http_findings": http_findings,
        "cve_candidates": cve_candidates,
        "cve_database_error": cve_error,
        "risk": risk,
        "limitations": [
            "Device fingerprinting is heuristic, not a probability.",
            "Exposure findings do not prove exploitability.",
            "HTTP header checks inspect responses; missing headers "
            "do not by themselves prove exploitability.",
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
        char if char.isalnum() or char in ".-_"
        else "_"
        for char in result.get("target", "unknown")
    )

    timestamp = datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ"
    )
    report_path = report_dir / (
        f"scan_{safe_target}_{timestamp}.json"
    )

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(result, file, indent=2, ensure_ascii=False)

    return str(report_path)

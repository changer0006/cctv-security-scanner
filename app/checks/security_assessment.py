
from datetime import datetime, timezone


def assess_device(scan_result: dict) -> list[dict]:
    """
    Produce preliminary security findings from structured Nmap data.

    These checks identify exposure and configuration-review needs.
    They do not prove exploitability or confirm a CVE.
    """

    findings = []
    target = scan_result.get("target", "unknown")
    ports = scan_result.get("ports", [])

    def add_finding(
        finding_id,
        title,
        severity,
        evidence,
        description,
        remediation,
    ):
        findings.append({
            "id": finding_id,
            "target": target,
            "title": title,
            "severity": severity,
            "evidence": evidence,
            "description": description,
            "remediation": remediation,
            "confirmed_vulnerability": False,
            "observed_at": datetime.now(timezone.utc).isoformat(),
        })

    open_ports = [
        port for port in ports
        if port.get("state") == "open"
    ]

    # RTSP is common in video systems. Exposure alone is not a vulnerability.
    for port in open_ports:
        if port.get("port") == 554 or (
            (port.get("service") or "").lower() == "rtsp"
        ):
            add_finding(
                "CAM-RTSP-001",
                "RTSP service exposed",
                "MEDIUM",
                f"Port {port.get('port')}/{port.get('protocol', 'tcp')} "
                "is open and associated with RTSP.",
                "RTSP exposure may allow video-stream access depending "
                "on authentication, network reachability, and configuration. "
                "This scan has not tested authentication or stream access.",
                "Restrict RTSP access to trusted systems, review "
                "authentication settings, and disable RTSP if unnecessary.",
            )
            break

    # HTTP without HTTPS may expose management traffic to interception.
    http_ports = [
        port for port in open_ports
        if port.get("port") == 80
        or (port.get("service") or "").lower() == "http"
    ]

    https_ports = [
        port for port in open_ports
        if port.get("port") in (443, 8443)
        or (port.get("service") or "").lower() == "https"
    ]

    if http_ports and not https_ports:
        add_finding(
            "WEB-HTTP-001",
            "HTTP management service detected without detected HTTPS",
            "MEDIUM",
            "An HTTP service is open; no HTTPS service was identified "
            "in the supplied scan results.",
            "Unencrypted HTTP can expose management traffic if credentials "
            "or sensitive data are transmitted without encryption. "
            "The scan does not establish whether HTTPS is available "
            "on another port or through another interface.",
            "Verify the management interface configuration and prefer "
            "HTTPS with a valid certificate. Restrict management access "
            "to a trusted network.",
        )

    # Flag potentially unnecessary exposed services for human review.
    review_ports = {
        23: ("Telnet service exposed", "HIGH"),
        21: ("FTP service exposed", "MEDIUM"),
        2323: ("Alternative Telnet port exposed", "HIGH"),
    }

    for port in open_ports:
        port_number = port.get("port")

        if port_number in review_ports:
            title, severity = review_ports[port_number]

            add_finding(
                f"NET-PORT-{port_number}",
                title,
                severity,
                f"Port {port_number}/{port.get('protocol', 'tcp')} "
                "is open.",
                "This service may expose management or data traffic. "
                "Its actual risk depends on configuration and intended use.",
                "Confirm whether the service is required. Disable it if "
                "unnecessary, or restrict access and use secure alternatives.",
            )

    if not findings:
        add_finding(
            "GEN-REVIEW-001",
            "No configured exposure checks triggered",
            "INFO",
            f"Reviewed {len(open_ports)} open port(s) in the supplied results.",
            "No finding rules in this initial assessment matched. "
            "This does not mean the device is secure; coverage is limited.",
            "Continue with firmware verification, configuration review, "
            "and authenticated checks where explicitly authorized.",
        )

    return findings

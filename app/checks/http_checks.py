
import urllib.error
import urllib.request


SECURITY_HEADERS = {
    "strict-transport-security": (
        "HTTP-HDR-001",
        "Missing Strict-Transport-Security header",
        "LOW",
        "Review HTTPS and HSTS configuration where browser access is supported.",
    ),
    "content-security-policy": (
        "HTTP-HDR-002",
        "Missing Content-Security-Policy header",
        "INFO",
        "Consider a suitable Content Security Policy for browser-based interfaces.",
    ),
    "x-content-type-options": (
        "HTTP-HDR-003",
        "Missing X-Content-Type-Options header",
        "LOW",
        "Consider sending X-Content-Type-Options: nosniff.",
    ),
    "x-frame-options": (
        "HTTP-HDR-004",
        "Missing X-Frame-Options header",
        "INFO",
        "Consider frame restrictions using X-Frame-Options or CSP frame-ancestors.",
    ),
}


def check_http_headers(url: str, timeout: int = 5) -> dict:
    """
    Inspect response headers from an authorized HTTP(S) endpoint.

    Sends a normal GET request; does not submit credentials or alter settings.
    Redirects are followed by urllib's default redirect handler.
    """

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "CCTV-Security-Scanner/0.1"},
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = response.status
            final_url = response.geturl()
            headers = {
                key.lower(): value
                for key, value in response.headers.items()
            }

    except (urllib.error.URLError, TimeoutError, ValueError) as error:
        return {
            "url": url,
            "reachable": False,
            "error": str(error),
            "findings": [],
        }

    findings = []

    for header, details in SECURITY_HEADERS.items():
        if header not in headers:
            finding_id, title, severity, remediation = details
            findings.append({
                "id": finding_id,
                "title": title,
                "severity": severity,
                "evidence": f"Response did not include {header}.",
                "remediation": remediation,
                "confirmed_vulnerability": False,
            })

    return {
        "url": url,
        "final_url": final_url,
        "status_code": status,
        "reachable": True,
        "headers": headers,
        "findings": findings,
    }

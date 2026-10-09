def fingerprint_device(scan_result: dict) -> dict:
    """Classify a device using evidence from structured Nmap results."""

    ports = scan_result.get("ports", [])
    evidence = []
    services = []
    vendor = "Unknown"
    score = 0

    def add_evidence(points: int, message: str):
        nonlocal score
        if message not in evidence:
            evidence.append(message)
            score += points

    for item in ports:
        port = item.get("port")
        service = (item.get("service") or "").lower()
        product = (item.get("product") or "").lower()
        version = item.get("version")
        signature = f"{service} {product} {version or ''}".lower()

        services.append({
            "port": port,
            "protocol": item.get("protocol", "tcp"),
            "state": item.get("state", "unknown"),
            "service": service or "unknown",
            "product": item.get("product"),
            "version": version,
        })

        # Vendor identification requires an explicit signature.
        if "hikvision" in signature:
            vendor = "Hikvision"
            add_evidence(35, "Hikvision signature detected")

        elif "dahua" in signature:
            vendor = "Dahua"
            add_evidence(35, "Dahua signature detected")

        elif "axis" in signature:
            vendor = "Axis"
            add_evidence(35, "Axis signature detected")

        # RTSP is useful evidence, but is not proof by itself.
        if port == 554 or "rtsp" in service:
            add_evidence(20, "RTSP service indicator detected")

        # Common camera-associated control service.
        if port == 8000 and (
            "ipcam" in signature or "hikvision" in signature
        ):
            add_evidence(25, "Camera-associated control service detected")

        # Camera-related HTTP banners.
        if port in (80, 443, 8080, 8443) and any(
            term in signature
            for term in ("camera", "ipcam", "hikvision", "dahua", "onvif")
        ):
            add_evidence(10, "Camera-associated HTTP service detected")

        if "onvif" in signature:
            add_evidence(20, "ONVIF indicator detected")

    # This is a heuristic score, not a calibrated probability.
    confidence = min(score, 100)

    if confidence >= 60:
        device_type = "Likely CCTV/NVR"
    elif confidence >= 30:
        device_type = "Possible CCTV/NVR"
    else:
        device_type = "Unknown"

    return {
        "target": scan_result.get("target", "Unknown"),
        "status": scan_result.get("status", "unknown"),
        "device_type": device_type,
        "vendor": vendor,
        "confidence": confidence,
        "confidence_type": "heuristic score, not probability",
        "evidence": evidence,
        "services": services,
    }


from app.discovery.network_discovery import discover_hosts
from app.discovery.nmap_scanner import scan_host
from app.fingerprint.fingerprint import fingerprint_device


def main():
    network = input(
        "Enter authorized network (example 192.168.1.0/24): "
    ).strip()

    print("\nDiscovering hosts...\n")

    hosts = discover_hosts(network)

    if not hosts:
        print("No active hosts found.")
        return

    print("=" * 60)
    print("DISCOVERED DEVICES")
    print("=" * 60)

    for index, host in enumerate(hosts, start=1):
        print(
            f"{index}. IP: {host['ip']} | "
            f"MAC: {host.get('mac') or 'Unknown'} | "
            f"Vendor: {host.get('vendor') or 'Unknown'}"
        )

    target_input = input(
        "\nEnter device index number or IP address to scan: "
    ).strip()

    if target_input.isdigit():
        index = int(target_input) - 1

        if index < 0 or index >= len(hosts):
            print("Invalid device index.")
            return

        target = hosts[index]["ip"]
    else:
        target = target_input

    if not target:
        print("No target selected.")
        return

    print(f"\nScanning {target}...\n")

    try:
        result = scan_host(target)
    except (RuntimeError, OSError) as error:
        print(f"Scan failed: {error}")
        return

    fingerprint = fingerprint_device(result)

    print("=" * 60)
    print("SCAN RESULTS")
    print("=" * 60)
    print(f"Target: {result['target']}")
    print(f"Status: {result['status']}")

    print("\nDetected Services:")

    for port in result.get("ports", []):
        print(
            f"{port['port']}/{port['protocol']}: "
            f"{port['state']} - {port.get('service') or 'unknown'} "
            f"{port.get('product') or ''} "
            f"{port.get('version') or ''}"
        )

    print("\nDEVICE FINGERPRINT")
    print("-" * 60)
    print(f"Device Type: {fingerprint['device_type']}")
    print(f"Vendor: {fingerprint['vendor']}")
    print(
        f"Heuristic Score: {fingerprint['confidence']}/100 "
        "(not a probability)"
    )

    print("\nEvidence:")

    if fingerprint["evidence"]:
        for item in fingerprint["evidence"]:
            print(f"- {item}")
    else:
        print("- No CCTV-specific indicators identified.")

    print("\nFingerprinting complete.")


if __name__ == "__main__":
    main()



import ipaddress
from app.database.db import save_scan
from app.discovery.network_discovery import discover_hosts
from app.discovery.nmap_scanner import scan_host
from app.pipeline import analyze_scan, save_report


def main():
    network = input(
        "Enter authorized network (example 192.168.1.0/24): "
    ).strip()

    # Validate the network input before invoking Nmap.
    try:
        ipaddress.ip_network(network, strict=False)
    except ValueError:
        print("Invalid network format.")
        return

    print("\nDiscovering hosts...\n")

    try:
        hosts = discover_hosts(network)
    except (RuntimeError, OSError) as error:
        print(f"Discovery failed: {error}")
        return

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
        "\nEnter device index or IP from the list: "
    ).strip()

    if target_input.isdigit():
        index = int(target_input) - 1
        if index < 0 or index >= len(hosts):
            print("Invalid device index.")
            return
        target = hosts[index]["ip"]
    else:
        try:
            target = str(ipaddress.ip_address(target_input))
        except ValueError:
            print("Invalid IP address.")
            return

        # Only scan a host returned by discovery.
        discovered_ips = {host["ip"] for host in hosts}
        if target not in discovered_ips:
            print("Target was not in the discovered-host list.")
            return

    print(f"\nScanning {target}...\n")

    try:
        scan_result = scan_host(target)
    except (RuntimeError, OSError) as error:
        print(f"Scan failed: {error}")
        return

    print("Analyzing scan results...")
    report = analyze_scan(scan_result)

    fingerprint = report["fingerprint"]
    risk = report["risk"]

    print("\n" + "=" * 60)
    print("CCTV SECURITY ASSESSMENT")
    print("=" * 60)
    print(f"Target: {report['target']}")
    print(f"Scan status: {report['scan_status']}")
    print(f"Device type: {fingerprint['device_type']}")
    print(f"Vendor: {fingerprint['vendor']}")
    print(f"Fingerprint heuristic score: {fingerprint['confidence']}/100")
    print(f"Risk score: {risk['risk_score']}/100")
    print(f"Risk level: {risk['risk_level']}")
    print(f"Unique findings: {risk['finding_count']}")

    print("\nSECURITY FINDINGS")
    for finding in report["security_findings"]:
        print(
            f"- [{finding['severity']}] {finding['title']}: "
            f"{finding['evidence']}"
        )

    print("\nLOCAL CVE CANDIDATES")
    if report["cve_candidates"]:
        for candidate in report["cve_candidates"]:
            print(
                f"- {candidate.get('cve_id', 'Unknown ID')} "
                f"[{candidate['severity']}] — "
                f"requires validation: "
                f"{candidate['requires_manual_validation']}"
            )
    else:
        print("No exact product/version candidates found.")

    if report["cve_database_error"]:
        print(
            "\nWarning: local CVE database could not be used: "
            f"{report['cve_database_error']}"
        )

    try:
        report_path = save_report(report)
        print(f"\nJSON report saved to: {report_path}")
    except OSError as error:
        print(f"\nCould not save report: {error}")


if __name__ == "__main__":
    main()

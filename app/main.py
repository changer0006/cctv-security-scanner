import sys
from app.discovery.network_discovery import discover_hosts
from app.discovery.nmap_scanner import scan_host


def main():
    try:
        network = input(
            "Enter authorized network (example 192.168.1.0/24): "
        ).strip()

        if not network:
            print("No network target specified. Exiting.")
            return

        print("\nDiscovering hosts...\n")

        hosts = discover_hosts(network)

        if not hosts:
            print("No active hosts found.")
            return

        print("=" * 60)
        print("DISCOVERED DEVICES")
        print("=" * 60)

        for index, host in enumerate(hosts, start=1):
            print(f"\nDevice {index}")
            print(f"IP Address : {host['ip']}")
            print(f"MAC Address: {host['mac'] or 'Unknown'}")
            print(f"Vendor     : {host['vendor'] or 'Unknown'}")

        print("\n" + "=" * 60)
        choice = input("\nDo you want to run a detailed scan on a discovered device? (y/N): ").strip().lower()

        if choice == 'y':
            target_input = input("Enter device index number or IP address to scan: ").strip()

            target_ip = None
            if target_input.isdigit():
                idx = int(target_input) - 1
                if 0 <= idx < len(hosts):
                    target_ip = hosts[idx]['ip']
                else:
                    print("Invalid device number.")
                    return
            else:
                target_ip = target_input

            if not target_ip:
                print("Invalid target.")
                return

            print(f"\nScanning host {target_ip} (service/version scan)...")
            scan_result = scan_host(target_ip)

            print("\n" + "=" * 60)
            print(f"SCAN RESULTS FOR {scan_result['target']} (Status: {scan_result['status']})")
            print("=" * 60)

            ports = scan_result.get("ports", [])
            if not ports:
                print("No open ports found.")
            else:
                for p in ports:
                    svc = p.get('service') or 'unknown'
                    prod = p.get('product') or ''
                    ver = p.get('version') or ''
                    details = f"{prod} {ver}".strip()
                    details_str = f" ({details})" if details else ""
                    print(f"Port {p['port']}/{p['protocol']}: {p['state']} - {svc}{details_str}")

    except KeyboardInterrupt:
        print("\nScan cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
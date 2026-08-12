from app.discovery.nmap_scanner import scan_host


def main():
    target = input("Enter authorized target IP: ").strip()

    print("\nStarting scan...\n")

    result = scan_host(target)

    print("\nScan Result")
    print("=" * 50)

    print(f"Target: {result['target']}")
    print(f"Status: {result['status']}")

    print("\nPorts:")

    for port in result["ports"]:
        print(
            f"{port['port']}/{port['protocol']} "
            f"{port['state']} "
            f"{port['service']} "
            f"{port['product'] or ''} "
            f"{port['version'] or ''}"
        )


if __name__ == "__main__":
    main()
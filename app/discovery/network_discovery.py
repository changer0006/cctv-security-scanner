import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET


def discover_hosts(network: str) -> list[dict]:
    """
    Discover live hosts on an authorized network.
    Example: 192.168.1.0/24
    """

    with tempfile.TemporaryDirectory() as temp_dir:
        xml_path = os.path.join(temp_dir, "discovery.xml")

        command = [
            "nmap",
            "-sn",
            "-oX",
            xml_path,
            network
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False
            )
        except FileNotFoundError:
            raise RuntimeError("Nmap executable not found. Please ensure nmap is installed and added to PATH.")

        if result.returncode != 0:
            error_msg = result.stderr.strip() or result.stdout.strip() or f"Nmap exited with code {result.returncode}"
            raise RuntimeError(error_msg)

        tree = ET.parse(xml_path)
        root = tree.getroot()

        hosts = []

        for host in root.findall("host"):

            status = host.find("status")

            if status is None or status.get("state") != "up":
                continue

            addresses = host.findall("address")

            ip_address = None
            mac_address = None
            vendor = None

            for address in addresses:

                address_type = address.get("addrtype")

                if address_type == "ipv4":
                    ip_address = address.get("addr")

                elif address_type == "mac":
                    mac_address = address.get("addr")
                    vendor = address.get("vendor")

            hosts.append({
                "ip": ip_address,
                "mac": mac_address,
                "vendor": vendor
            })

        return hosts
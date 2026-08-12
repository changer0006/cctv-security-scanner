import subprocess
import tempfile
import xml.etree.ElementTree as ET


def scan_host(target: str) -> dict:
    """
    Run an Nmap service/version scan against an authorized target
    and return structured information.
    """

    with tempfile.NamedTemporaryFile(suffix=".xml") as temp_file:

        command = [
            "nmap",
            "-sV",
            "-oX",
            temp_file.name,
            target
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode != 0:
            raise RuntimeError(result.stderr)

        tree = ET.parse(temp_file.name)
        root = tree.getroot()

        host = root.find("host")

        if host is None:
            return {
                "target": target,
                "status": "down",
                "ports": []
            }

        status = host.find("status")

        host_state = (
            status.get("state")
            if status is not None
            else "unknown"
        )

        ports = []

        ports_element = host.find("ports")

        if ports_element is not None:

            for port in ports_element.findall("port"):

                port_number = int(port.get("portid"))

                protocol = port.get("protocol")

                state_element = port.find("state")

                state = (
                    state_element.get("state")
                    if state_element is not None
                    else "unknown"
                )

                service_element = port.find("service")

                service = None
                product = None
                version = None

                if service_element is not None:
                    service = service_element.get("name")
                    product = service_element.get("product")
                    version = service_element.get("version")

                ports.append({
                    "port": port_number,
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                    "product": product,
                    "version": version
                })

        return {
            "target": target,
            "status": host_state,
            "ports": ports
        }
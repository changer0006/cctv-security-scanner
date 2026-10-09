# CCTV Security Scanner
### Offline AI-Assisted Vulnerability Assessment and Security Audit Framework for CCTV Cameras and DVR/NVR Systems

**CCTV Security Scanner** is a Python-based cybersecurity project designed to discover network-connected devices, identify CCTV cameras and DVR/NVR systems, assess exposed services, and support security vulnerability analysis.

The long-term goal is to develop an extensible security auditing framework with local vulnerability intelligence, explainable risk scoring, offline AI-assisted analysis, and automated security reports.

> **Project status:** Under active development. Network discovery and structured Nmap scanning have been implemented. CCTV fingerprinting, vulnerability assessment, offline AI, and reporting are planned or under development.

## Key Objectives

- Discover active devices on an authorized local network.
- Identify exposed ports and network services.
- Fingerprint potential CCTV cameras and DVR/NVR systems.
- Detect potentially risky service exposure and configuration issues.
- Match device and firmware information against known CVEs.
- Calculate explainable risk scores.
- Generate actionable remediation recommendations.
- Support offline AI-assisted security analysis.
- Produce security assessment reports.

## Planned Architecture

```text
Authorized Network
        |
        v
 Network Discovery
        |
        v
 Nmap Service Scanning
        |
        v
 CCTV/DVR Fingerprinting
        |
        v
 Security Assessment
        |
        v
 Local CVE Intelligence
        |
        v
 Risk Scoring Engine
        |
        v
 SQLite Database
        |
        v
 Dashboard and Reports
        |
        v
 Optional Offline AI Analysis
```

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application and assessment logic |
| Nmap | Network discovery and service/version scanning |
| Linux / WSL2 | Development and execution environment |
| Git and GitHub | Version control |
| SQLite | Planned local storage |
| Streamlit | Planned interactive dashboard |
| Ollama | Planned local AI inference |
| NVD/CVE data | Planned vulnerability intelligence |

## Current Features

- **Network discovery:** identifies active hosts on a specified network using Nmap.
- **Structured scan results:** parses Nmap XML output into Python dictionaries.
- **Service detection:** collects port state, protocol, service name, product, and version where available.
- **Modular architecture:** separates discovery, fingerprinting, risk analysis, AI, and reporting components.

## Roadmap

- [x] Initial project structure and Git repository
- [x] Network host discovery
- [x] Structured Nmap service/version scanner
- [ ] CCTV/DVR device fingerprinting
- [ ] HTTP, HTTPS, RTSP, and ONVIF security checks
- [ ] Device and firmware identification
- [ ] Local CVE matching
- [ ] CVSS-based severity analysis
- [ ] Explainable risk scoring
- [ ] SQLite scan history
- [ ] Streamlit security dashboard
- [ ] HTML/PDF report generation
- [ ] Offline AI-assisted finding explanations
- [ ] Testing, evaluation, and documentation

## Getting Started

### Prerequisites

- Linux or WSL2 with Ubuntu
- Python 3
- Git
- Nmap

Install the required system packages on Ubuntu:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git nmap
```

### Clone the repository

```bash
git clone https://github.com/changer0006/cctv-security-scanner.git
cd cctv-security-scanner
```

### Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Run the application

From the project root:

```bash
python3 -m app.main
```

Follow the prompts to discover devices or scan a specific IP address, depending on the functionality available in the current version.

## Example Workflow

Discover active hosts on your authorized network:

```bash
nmap -sn 192.168.1.0/24
```

Scan a specific authorized device for service/version information:

```bash
nmap -sV 192.168.1.20
```

Replace the example addresses with addresses from your own lab or a network you have explicit permission to assess.

## Security and Responsible Use

This project is intended for **authorized defensive security assessment and educational use**.

- Only scan networks and devices you own or have explicit permission to test.
- Start with non-destructive discovery and service detection.
- Do not perform intrusive tests against production devices without written authorization.
- Keep scan reports, device addresses, credentials, and other sensitive information private.
- Verify vendor advisories and vulnerability evidence before declaring a device vulnerable.

An exposed port or service banner alone does not prove that a vulnerability exists. Accurate CVE matching requires sufficiently reliable vendor, model, firmware, and affected-version information.

## Project Limitations

The project is under active development. Planned functionality should not be interpreted as already implemented. Device fingerprinting may produce false positives, and service/version detection can be incomplete or inaccurate. Risk scores and AI-generated explanations will require validation against supporting evidence.

## Future Scope

The framework aims to support offline security audits, local vulnerability databases, explainable risk prioritization, remediation guidance, and automated reporting for CCTV and DVR/NVR deployments.

## Author

**Sree Ram Kumar**  
B.Tech Computer Science and Engineering — Cybersecurity

GitHub: [@changer0006](https://github.com/changer0006)

## License

No license has been selected yet. Until a license is added, all rights are reserved by the copyright holder by default. Add an appropriate open-source license if you intend to permit reuse or redistribution.

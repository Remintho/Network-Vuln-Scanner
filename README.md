# Network Vulnerability Scanner

## Overview
The **Network Vulnerability Scanner** is a Python-based tool designed for security professionals, network administrators, and ethical hackers. It automates scanning a network to identify open ports, grab service banners, and check for potential vulnerabilities based on known exploits.

This tool leverages:
- **Nmap** for port scanning
- **Socket** for banner grabbing
- **Exploit-DB queries** for known vulnerabilities
- **Local vulnerability keyword matching** (optional)

## Features
- **Port Scanning:** Automatically scans the target for open ports within a specified range.
- **Banner Grabbing:** Retrieves service banners to identify versions and service types.
- **Vulnerability Checking:** Queries Exploit-DB and matches against a local vulnerability file.
- **JSON Output:** Saves results in an easy-to-analyze JSON format.

---

## Installation

### 1. Install Python
Ensure you have Python 3.x installed. You can download it from [python.org](https://www.python.org/downloads/).

### 2. Install Nmap
This tool requires Nmap for port scanning.

- **Linux (Ubuntu/Debian):**
  ```bash
  sudo apt update && sudo apt install nmap
  ```
- **MacOS (via Homebrew):**
  ```bash
  brew install nmap
  ```
- **Windows:**
  Download and install Nmap from [nmap.org](https://nmap.org/download.html).

### 3. Install Required Python Modules
Run the following command to install dependencies:
```bash
pip install python-nmap requests beautifulsoup4 IPy
```

### 4. Clone the Repository
```bash
git clone https://github.com/yourusername/network-vuln-scanner.git
cd network-vuln-scanner
```

---

## Usage

### Basic Command
To scan a target:
```bash
python network_vuln_scanner.py TARGET_IP_OR_HOSTNAME
```
Example:
```bash
python network_vuln_scanner.py 192.168.1.100
```

### Scan with Custom Port Range
```bash
python network_vuln_scanner.py 192.168.1.100 -p 20-8080
```

### Save Results to a File
```bash
python network_vuln_scanner.py 192.168.1.100 -o results.json
```

### Use a Local Vulnerability File
Create a text file with vulnerable service keywords (e.g., `vuln_keywords.txt`):
```text
Apache/2.2.14
OpenSSH 5.3p1
```
Run the scanner with:
```bash
python network_vuln_scanner.py 192.168.1.100 -v vuln_keywords.txt
```

---

## Output
The scanner outputs results in JSON format, including:
```json
{
    "target": "192.168.1.100",
    "open_ports": [
        {
            "port": 22,
            "banner": "OpenSSH 7.9p1 Ubuntu 10ubuntu2.3",
            "vulnerabilities_remote": [
                {"exploit_id": "12345", "description": "OpenSSH 7.9p1 remote exploit"}
            ],
            "vulnerabilities_local": []
        }
    ]
}
```

---

## Future Enhancements
- **Integration with real Exploit-DB API**
- **Asynchronous scanning for better performance**
- **More advanced banner parsing**
- **GUI or Web-based interface for easier use**

---

## Disclaimer
This tool is intended for **educational and ethical** penetration testing only. **Do not** use it on networks you do not have permission to scan. Unauthorized use of this tool may violate local laws.

---

## License
MIT License. See `LICENSE` for details.


## Author
Developed by Remintho.


#!/usr/bin/env python3
import nmap
import socket
import json
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from IPy import IP

# --- Helper: Validate or resolve target IP ---
def check_ip(target):
    try:
        IP(target)
        return target
    except ValueError:
        return socket.gethostbyname(target)

# --- 1. Port Scanning using nmap ---
def port_scan(target, port_range="1-1024"):
    nm = nmap.PortScanner()
    print(f"[+] Scanning {target} for ports {port_range} ...")
    nm.scan(target, port_range)
    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                if nm[host][proto][port]['state'] == 'open':
                    open_ports.append(port)
    return open_ports

# --- 2. Banner Grabbing using socket ---
def get_banner(target, port, timeout=2):
    try:
        target_ip = check_ip(target)
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((target_ip, port))
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return banner
    except Exception:
        return ""

# --- 3. Vulnerability Lookup via Exploit-DB (Simulated) ---
def query_exploit_db(service_banner):
    url = "https://www.exploit-db.com/search"
    params = {"q": service_banner}
    try:
        response = requests.get(url, params=params, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            exploits = []
            # Simplified parser; may need tailoring for production use
            for row in soup.find_all("tr"):
                cols = row.find_all("td")
                if cols and len(cols) >= 2:
                    exploit_id = cols[0].text.strip()
                    description = cols[1].text.strip()
                    if exploit_id and description:
                        exploits.append({"exploit_id": exploit_id, "description": description})
            return exploits
        else:
            return []
    except Exception:
        return []

# --- 4. Process Each Open Port ---
def process_port(target, port, vuln_keywords=None):
    banner = get_banner(target, port)
    vulns_remote = []
    vulns_local = []
    if banner:
        print(f"[+] Port {port} is open; Banner: {banner}")
        vulns_remote = query_exploit_db(banner)
        if vuln_keywords:
            for keyword in vuln_keywords:
                if keyword.lower() in banner.lower():
                    vulns_local.append(keyword)
    else:
        print(f"[-] Port {port} is open but no banner received.")
    return {
        "port": port,
        "banner": banner,
        "vulnerabilities_remote": vulns_remote,
        "vulnerabilities_local": vulns_local
    }

# --- 5. Main Scanner Function ---
def scan_target(target, port_range="1-1024", vuln_keywords=None):
    results = {"target": target, "open_ports": []}
    open_ports = port_scan(target, port_range)
    if not open_ports:
        print("[-] No open ports found.")
        return results
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(process_port, target, port, vuln_keywords): port 
            for port in open_ports
        }
        for future in futures:
            port_result = future.result()
            results["open_ports"].append(port_result)
    return results

# --- 6. Command-Line Interface ---
def main():
    import argparse
    parser = argparse.ArgumentParser(description="Python Network Vulnerability Scanner")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range to scan (default: 1-1024)")
    parser.add_argument("-o", "--output", default="scan_results.json", help="Output JSON file")
    parser.add_argument("-v", "--vuln_file", default=None, help="Path to file with vulnerable service keywords")
    args = parser.parse_args()

    target = args.target
    port_range = args.ports
    output_file = args.output
    vuln_keywords = None

    # --- Load local vulnerability keywords (friend's idea) ---
    if args.vuln_file:
        try:
            with open(args.vuln_file, "r") as vf:
                vuln_keywords = [line.strip() for line in vf if line.strip()]
            print(f"[+] Loaded {len(vuln_keywords)} vulnerable service keywords from {args.vuln_file}")
        except Exception as e:
            print(f"Error reading vulnerability file: {e}")

    results = scan_target(target, port_range, vuln_keywords)
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)
    print(f"\n[+] Scan complete. Results saved to {output_file}")

if __name__ == "__main__":
    main()

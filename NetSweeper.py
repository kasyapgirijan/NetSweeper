import argparse
import os
import subprocess
import threading
import time
import json
from pathlib import Path
import pandas as pd  # Requires installation: pip install pandas openpyxl
import math
from art import text2art

# Global Constants
PING_PATH = None
TMP_PATH = None
TCP_PATH = None
UDP_PATH = None
VERBOSE = False

# Display Banner
banner = text2art("NetSweeper", font='standard')
print(banner)
print("v1.1 by Kasyap Girijan\n")

# Initialization Functions
def init_directories(output_dir):
    """Initialize required directories."""
    global PING_PATH, TMP_PATH, TCP_PATH, UDP_PATH
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    PING_PATH = output_dir / "ping_sweep"
    TCP_PATH = output_dir / "TCP"
    UDP_PATH = output_dir / "UDP"
    TMP_PATH = output_dir / "tmp"

    for path in [PING_PATH, TCP_PATH, UDP_PATH, TMP_PATH]:
        path.mkdir(parents=True, exist_ok=True)


def run_command(command, log_file):
    """Run shell commands in the background and log output."""
    with open(log_file, "a") as log:
        subprocess.Popen(command, shell=True, stdout=log, stderr=log, preexec_fn=os.setpgrp)


def validate_interface(interface):
    """Validate if the provided network interface is available."""
    try:
        interfaces = subprocess.check_output(["ip", "-o", "link", "show"]).decode()
        available_interfaces = [line.split()[1].strip(':') for line in interfaces.split("\n") if line]
        if interface not in available_interfaces:
            raise ValueError(f"Invalid interface '{interface}'! Available: {', '.join(available_interfaces)}")
    except Exception as e:
        raise RuntimeError(f"Failed to fetch interfaces: {e}")
    return interface


def validate_scope(scope_file):
    """Validate if the scope file exists."""
    path = Path(scope_file)
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"Scope file '{scope_file}' not found!")
    return path

# Report Generation
def generate_html_report(results, output_file):
    """Generate an HTML report from scan results."""
    html_content = """
    <html>
    <head><title>NetSweeper Scan Report</title></head>
    <body>
        <h1>NetSweeper Scan Report</h1>
        <table border='1'>
            <tr>
                <th>Host</th>
                <th>Port</th>
                <th>State</th>
                <th>Service</th>
            </tr>
    """
    for host in results:
        for port in host.get("ports", []):
            html_content += f"""
            <tr>
                <td>{host['host']}</td>
                <td>{port['port']}</td>
                <td>{port['state']}</td>
                <td>{port['service']}</td>
            </tr>
            """
    html_content += """
        </table>
    </body>
    </html>
    """
    with open(output_file, "w") as f:
        f.write(html_content)
    print(f"HTML Report generated: {output_file}")

# Scanning Functions
def ping_sweep(interface, scope_file, extensive=False):
    """Perform a ping sweep to identify active hosts."""
    print("Executing Ping Sweep...")
    log_file = PING_PATH / "ping_sweep.log"
    base_cmd = f"nmap -T3 -e {interface} -iL {scope_file} -sn -n"
    commands = [base_cmd + " --disable-arp-ping"]
    
    if extensive:
        SCTP_PORTS = "7,9,20-22,80,443,1021,1022,1720,1812,2049,2905,4502,5060,5215,5868,6701-6706,7701,8282,8471,9082,14001,36412"
        TCP_PORTS = "7,9,13,21-23,25,53,79-81,88,110,135,139,143,443,445,587,631,873,990,993,995,1025,1433,1720,2049,2717,3306,3389,5432,5800,5900,7070,8000,8080,8443,8888,9100"
        UDP_PORTS = "53,67,123,135,137-138,161,445,631,1434"
        
        commands += [
            base_cmd + f" -PS{TCP_PORTS}",
            base_cmd + f" -PU{UDP_PORTS}",
            base_cmd + f" -PY{SCTP_PORTS}",
        ]
    
    threads = [threading.Thread(target=run_command, args=(cmd, log_file)) for cmd in commands]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    merge_ping_sweep()


def merge_ping_sweep():
    """Merge alive machine results from different scans."""
    print("Merging Ping Sweep Results...")
    alive_file = PING_PATH / "alive_machines.txt"
    with open(alive_file, "w") as outfile:
        for file in PING_PATH.glob("ping_sweep_*.txt"):
            with open(file, "r") as infile:
                for line in infile:
                    if "Nmap scan report for" in line:
                        outfile.write(line.split()[-1] + "\n")
    return alive_file

# Main Function
def main():
    parser = argparse.ArgumentParser(description="NetSweeper: Network Recon Tool")
    parser.add_argument("-o", "--output", required=True, help="Output directory")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("-s", "--scope", required=True, help="Scope file path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
    parser.add_argument("--extensive", action="store_true", help="Enable extensive ping sweep (SCTP, TCP, and UDP ports)")
    args = parser.parse_args()
    global VERBOSE
    VERBOSE = args.verbose
    init_directories(args.output)
    ping_sweep(validate_interface(args.interface), validate_scope(args.scope), args.extensive)
    
    results = []  # Placeholder for parsed scan results
    html_report_path = Path(args.output) / "scan_report.html"
    generate_html_report(results, html_report_path)
    
    print("Scan started in the background. Logs are being saved.")

if __name__ == "__main__":
    main()

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
import os
import sys

# Global Constants
PING_PATH = None
TMP_PATH = None
TCP_PATH = None
UDP_PATH = None
VERBOSE = False

banner = text2art("NetSweeper  .v1.1", font='standard')  # You can try other fonts like 'standard', 'slant'
print(banner)
print (" by Kasyap Girijan")
print(" ")

# Initialization Functions
def init_directories(output_dir):
    global PING_PATH, TMP_PATH, TCP_PATH, UDP_PATH

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    PING_PATH = output_dir / "ping_sweep"
    TCP_PATH = output_dir / "TCP"
    UDP_PATH = output_dir / "UDP"
    TMP_PATH = output_dir / "tmp"

    for path in [PING_PATH, TCP_PATH, UDP_PATH, TMP_PATH]:
        path.mkdir(parents=True, exist_ok=True)


def validate_interface(eth):
    interfaces = subprocess.check_output(["ifconfig"]).decode()
    available_interfaces = [line.split(":")[0] for line in interfaces.split("\n") if ":" in line]

    if eth not in available_interfaces:
        raise ValueError(f"Network Interface '{eth}' is invalid! Available interfaces: {', '.join(available_interfaces)}")
    return eth


def validate_scope(scope):
    if not os.path.exists(scope):
        raise FileNotFoundError(f"Scope file '{scope}' does not exist!")
    return scope


# Helper Functions
def run_command(command, suppress_output=True):
    if VERBOSE:
        print(f"Executing: {command}")
    try:
        if suppress_output:
            subprocess.run(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(command, shell=True)
    except subprocess.SubprocessError as e:
        print(f"Error running command: {command}\n{e}")


def split_machines(alive_machines_file, num_splits=4):
    with open(alive_machines_file, "r") as file:
        machines = file.read().splitlines()

    num_per_split = max(1, len(machines) // num_splits)
    split_files = []
    for i in range(0, len(machines), num_per_split):
        split_file = TMP_PATH / f"list_{i // num_per_split}"
        with open(split_file, "w") as split:
            split.write("\n".join(machines[i:i+num_per_split]))
        split_files.append(split_file)

    return split_files


# Export Results
def parse_nmap_output(nmap_output_file):
    results = []
    with open(nmap_output_file, "r") as file:
        lines = file.readlines()

    current_host = None
    for line in lines:
        line = line.strip()
        if line.startswith("Nmap scan report for"):
            current_host = {"host": line.split(" ")[-1], "ports": []}
            results.append(current_host)
        elif line.startswith("PORT"):
            continue
        elif current_host and line:
            parts = line.split()
            if len(parts) >= 3:
                current_host["ports"].append({
                    "port": parts[0],
                    "state": parts[1],
                    "service": parts[2],
                })
    return results


def export_to_json(results, output_file):
    with open(output_file, "w") as file:
        json.dump(results, file, indent=4)
    print(f"Results exported to JSON: {output_file}")


def export_to_excel(results, output_file):
    data = []
    for host in results:
        for port in host["ports"]:
            data.append({
                "Host": host["host"],
                "Port": port["port"],
                "State": port["state"],
                "Service": port["service"],
            })
    df = pd.DataFrame(data)
    df.to_excel(output_file, index=False)
    print(f"Results exported to Excel: {output_file}")


# ETA Calculation
def calculate_eta(start_time, current_count, total_count):
    elapsed_time = time.time() - start_time
    avg_time_per_item = elapsed_time / current_count if current_count else 0
    remaining_time = avg_time_per_item * (total_count - current_count)
    return remaining_time


def verbose_log(message, start_time=None, current=None, total=None):
    if VERBOSE:
        eta = ""
        if start_time is not None and current is not None and total is not None:
            eta_seconds = calculate_eta(start_time, current, total)
            eta = f" | ETA: {math.ceil(eta_seconds)} seconds"
        print(f"{message}{eta}")


# Scanning Functions
def ping_sweep(eth, scope_file, extensive=False):
    """
    Performs a ping sweep on the target network.

    Args:
        eth (str): Network interface to use.
        scope_file (str): Path to the file containing the target IPs or subnets.
        extensive (bool): Whether to perform an extensive scan.
    """
    print("Executing Ping Sweep...")
    
    commands = []

    if extensive:
        # Define ports for SCTP, TCP, and UDP scans
        SCTP_PORTS = "7,9,20-22,80,179,443,1021,1022,1167,1720,1812,1813,2049,2225,2427,2904,2905,2944,2945,3097,3565,3863-3868,4195,4333,4502,4711,4739,4740,5060,5061,5090,5091,5215,5445,5060,5672,5675,5868,5910-5912,5913,6701-6706,6970,7626,7701,7728,8282,8471,9082,9084,9899-9902,11997-11999,14001,20049,25471,29118,29168,29169,30100,36412,36422-36424,36443,36444,36462,38412,38422,38462,38472"
        TCP_PORTS = "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157"
        UDP_PORTS = "53,67,123,135,137-138,161,445,631,1434"

        commands = [
            f"nmap -T4 -e {eth} -iL {scope_file} -oN {PING_PATH}/ping_sweep_tcp.txt -sn -n -PS{TCP_PORTS}",
            f"nmap -T4 -e {eth} -iL {scope_file} -oN {PING_PATH}/ping_sweep_udp.txt -sn -n -PU{UDP_PORTS}",
            f"nmap -T4 -e {eth} -iL {scope_file} -oN {PING_PATH}/ping_sweep_sctp.txt -sn -n -PY{SCTP_PORTS}",
        ]
    else:
        # Simple ping sweep using ICMP probes
        commands = [
            f"nmap -T4 -e {eth} -iL {scope_file} -oN {PING_PATH}/ping_sweep_n.txt -sn -n --disable-arp-ping",
            f"nmap -T4 -e {eth} -iL {scope_file} -oN {PING_PATH}/ping_sweep_s.txt -sn -n -PS80 --disable-arp-ping",
            f"nmap -T4 -e {eth} -iL {scope_file} -oN {PING_PATH}/ping_sweep_u.txt -sn -n -PU53 --disable-arp-ping",
    ]

    # Execute the commands in parallel
    threads = [threading.Thread(target=run_command, args=(cmd,)) for cmd in commands]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    merge_ping_sweep()


def merge_ping_sweep():
    print("Merging Ping Sweep Results...")
    alive_file = PING_PATH / "alivemachines.txt"
    with open(alive_file, "w") as outfile:
        for file in PING_PATH.glob("ping_sweep_*.txt"):
            with open(file, "r") as infile:
                for line in infile:
                    if "Nmap scan report for" in line:
                        ip = line.split(" ")[-1]
                        outfile.write(ip + "\n")
    return alive_file

def udp_scan(ip, eth):
    """Performs a UDP scan on the given IP address."""
    udp_command = f"nmap -p- -Pn -n -sUV -T4 -e {eth} {ip} -oA {UDP_PATH}/udp_scan_{ip}"
    verbose_log(f"Running UDP scan for {ip}")
    run_command(udp_command, suppress_output=False)

    udp_output = UDP_PATH / f"udp_scan_{ip}.nmap"
    if udp_output.exists():
        return parse_nmap_output(udp_output)
    return []

def tcp_scan(ip, eth):
    """Performs a TCP scan on the given IP address."""
    tcp_command = f"nmap -p- -Pn -n -sSV -A -T4 -e {eth} {ip} -oA {TCP_PATH}/tcp_scan_{ip}"
    verbose_log(f"Running TCP scan for {ip}")
    run_command(tcp_command, suppress_output=False)

    tcp_output = TCP_PATH / f"tcp_scan_{ip}.nmap"
    if tcp_output.exists():
        return parse_nmap_output(tcp_output)
    return []


# def perform_scans(alive_machines_file, eth):
#     """Executes both TCP and UDP scans for all alive machines."""
#     print("Executing TCP and UDP Scans...")
#     split_files = split_machines(alive_machines_file)
#     total_ips = sum(len(open(file).readlines()) for file in split_files)
#     start_time = time.time()

#     count = 0  # For tracking progress
#     all_results = []

#     for split_file in split_files:
#         with open(split_file, "r") as file:
#             ips = file.read().splitlines()

#         for ip in ips:
#             # Run UDP scan and collect results
#             udp_results = udp_scan(ip, eth)
#             all_results.extend(udp_results)

#             # Run TCP scan and collect results
#             tcp_results = tcp_scan(ip, eth)
#             all_results.extend(tcp_results)

#             # Update progress
#             count += 1
#             verbose_log(f"Completed scans for {ip}", start_time, count, total_ips)

#     return all_results



def export_to_html(results, output_file):
    """Exports scan results to an interactive HTML report with critical ports highlighted."""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Scan Results</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.0/dist/css/bootstrap.min.css">
        <style>
            body { padding: 20px; }
            h1 { color: #333; }
            .table { margin-top: 20px; }
            .critical-port { color: red; }
        </style>
    </head>
    <body>
        <h1>Network Scan Results</h1>
        <table class="table table-bordered">
            <thead class="table-dark">
                <tr>
                    <th>Host</th>
                    <th>Port</th>
                    <th>State</th>
                    <th>Service</th>
                </tr>
            </thead>
            <tbody>
    """
    critical_ports = {20, 21, 22, 23, 25, 53, 80, 110, 123, 143, 161, 162, 389, 443, 587, 636, 990, 1433, 3306, 1521, 5432, 3268, 3269, 3389, 5900}
    for host in results:
        for port in host["ports"]:
            port_num = int(port['port'].split('/')[0])  # Assuming port format is '80/tcp'
            row_class = 'critical-port' if port_num in critical_ports else ''
            html_content += f"""
                <tr class="{row_class}">
                    <td>{host['host']}</td>
                    <td>{port['port']}</td>
                    <td>{port['state']}</td>
                    <td>{port['service']}</td>
                </tr>
            """
    
    html_content += """
            </tbody>
        </table>
    </body>
    </html>
    """
    
    with open(output_file, "w") as file:
        file.write(html_content)
    print(f"Results exported to HTML: {output_file}")

def perform_scans(alive_machines_file, eth, scan_tcp=True, scan_udp=True):
    """Executes TCP and/or UDP scans for all alive machines based on the flags."""
    print(f"Executing {'TCP' if scan_tcp else ''}{' and ' if scan_tcp and scan_udp else ''}{'UDP' if scan_udp else ''} scans...")
    all_results = []

    for ip in open(alive_machines_file).read().splitlines():
        if scan_tcp:
            tcp_results = tcp_scan(ip, eth)
            all_results.extend(tcp_results)
        if scan_udp:
            udp_results = udp_scan(ip, eth)
            all_results.extend(udp_results)

    return all_results

# Main Function
def main():
    parser = argparse.ArgumentParser(description="NetSweeper: Network Recon Tool")
    parser.add_argument("-o", "--output", required=True, help="Output directory for results")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to use")
    parser.add_argument("-s", "--scope", required=True, help="Path to the scope file")
    parser.add_argument("--tcp", action="store_true", help="Perform only TCP scans")
    parser.add_argument("--udp", action="store_true", help="Perform only UDP scans")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
    parser.add_argument("--html", action="store_true", help="Export results to HTML file")

    args = parser.parse_args()
    global VERBOSE
    VERBOSE = args.verbose

    if os.geteuid() != 0:
        print("WARNING! This script needs to be run as root!")
        return

    try:
        init_directories(args.output)
        eth = validate_interface(args.interface)
        scope = validate_scope(args.scope)

        ping_sweep(eth, scope, extensive=False)
        alive_file = PING_PATH / "alivemachines.txt"

        # Determine scan type based on user flags
        scan_tcp = args.tcp or not args.udp  # Default to TCP if no flag is provided
        scan_udp = args.udp or not args.tcp  # Default to UDP if no flag is provided

        scan_results = perform_scans(alive_file, eth, scan_tcp=scan_tcp, scan_udp=scan_udp)

        # Export results
        export_to_json(scan_results, PING_PATH / "scan_results.json")
        export_to_excel(scan_results, PING_PATH / "scan_results.xlsx")
        if args.html:
            export_to_html(scan_results, PING_PATH / "scan_results.html")

        print("Scans completed successfully!")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()

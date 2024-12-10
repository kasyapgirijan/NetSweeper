
# **NetSweeper**

NetSweeper is a Python-based network scanning and reconnaissance tool designed for efficient host discovery, port scanning, and reporting. Originally built for network segmentation validation, it is particularly useful in environments requiring strict access controls, such as the Cardholder Data Environment (CDE) in compliance with PCI DSS standards.

---

## **Features**
- **Ping Sweep**: Identify live hosts in a network using simple ICMP probes or extensive port-based sweeps.
- **Extensive Scan Mode**: Use SCTP, TCP, and UDP port probes for detailed live host discovery with the `--extensive` flag.
- **TCP/UDP Scanning**: Scan for open ports and detect services and protocols.
- **Custom Scope**: Define a target list of IPs or ranges for scanning.
- **Output Flexibility**: Export results in JSON and Excel formats.
- **Verbose Mode**: Get detailed logs for ongoing scans.
- **PCI DSS Support**: Helps validate network segmentation in the CDE.

---

## **How It Helps with PCI DSS Compliance**
NetSweeper can be used to validate network segmentation, which is crucial for PCI DSS compliance. It assists by:
1. **Host Discovery**: Identifying all active devices in the Cardholder Data Environment (CDE).
2. **Port and Protocol Validation**: Ensuring only authorized ports and services are accessible within the CDE.
3. **Scope Definition**: Verifying that only in-scope systems are included in scans.
4. **Adjacency Testing**: Scanning adjacent networks to ensure proper segmentation and isolation.
5. **Audit-Friendly Reporting**: Generating JSON/Excel outputs for documentation during PCI audits.

### **Recommendations for PCI DSS Use**
- Restrict access to this script to authorized personnel.
- Use this script to validate segmentation periodically and after major network changes.
- Integrate with firewall rules to ensure alignment with the segmentation strategy.
- Log all scans and results for audit trails.

---

## **Requirements**

### **System Requirements**
- Python 3.6 or higher
- `nmap` installed on the system (`sudo apt install nmap` on Debian/Ubuntu systems)

---

## **Installation**

### **Clone the repository:**

```bash
git clone https://github.com/yourusername/NetSweeper.git
cd NetSweeper
```

### **Install dependencies:**

```bash
pip install -r requirements.txt
```

### **Ensure `nmap` is installed:**

```bash
sudo apt install nmap
```

---

## **Usage**
Run the script using the following command:

```bash
python NetSweeper.py -o <output_directory> -i <network_interface> -s <scope_file> [--extensive] [-v]
```

### **Arguments**
| Flag                | Description                                         | Example                     |
|---------------------|-----------------------------------------------------|-----------------------------|
| `-o, --output`      | Directory where results will be saved               | `-o /path/to/output`        |
| `-i, --interface`   | Network interface to use for scanning               | `-i eth0`                  |
| `-s, --scope`       | File containing target IPs or ranges to scan        | `-s /path/to/scope.txt`     |
| `--extensive`       | Perform extensive host discovery using SCTP, TCP, and UDP ports | `--extensive`             |
| `-v, --verbose`     | Enable verbose mode for detailed logs (optional)    | `-v`                       |

---

### **Example Commands**

#### Simple Ping Sweep:
```bash
python NetSweeper.py -o /output/directory -i eth0 -s /path/to/scope.txt -v
```

#### Extensive Scan:
```bash
python NetSweeper.py -o /output/directory -i eth0 -s /path/to/scope.txt --extensive -v
```

---

## **Output Files**
### **Ping Sweep Results:**
- Live hosts saved in `results/ping_sweep/alivemachines.txt`.

### **Scan Results:**
- JSON: `results/ping_sweep/scan_results.json`
- Excel: `results/ping_sweep/scan_results.xlsx`

### **Temporary Files:** 
Intermediate results stored in `results/tmp`.

---

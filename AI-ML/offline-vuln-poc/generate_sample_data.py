#!/usr/bin/env python3
"""
Sample Data Generator for Vulnerability Management System
Creates sample vulnerability data and scan files for testing
"""
import json
import csv
import random
from datetime import datetime, timedelta
import os

def generate_sample_vulnerabilities():
    """Generate sample vulnerability data"""
    
    # Sample data based on common vulnerabilities
    sample_software = [
        "Apache HTTP Server", "Microsoft IIS", "Nginx", "MySQL", "PostgreSQL",
        "MongoDB", "Redis", "Elasticsearch", "Docker", "Kubernetes",
        "OpenSSH", "ProFTPD", "vsftpd", "Postfix", "Sendmail",
        "Adobe Acrobat", "Microsoft Office", "Java Runtime", "Flash Player",
        "WordPress", "Joomla", "Drupal", "phpMyAdmin", "Jenkins"
    ]
    
    sample_hosts = [
        "web-server-01", "db-server-01", "mail-server-01", "app-server-01",
        "cont-jonavolcot", "cont-sndirpc2", "cont-manas-dev", "prod-web-01",
        "staging-app-01", "backup-server-01", "fileserver-01", "proxy-01"
    ]
    
    sample_ports = ["22", "23", "25", "53", "80", "110", "143", "443", "993", "995", "3306", "5432", "6379", "9200", "8080", "8443"]
    
    sample_cves = [
        "CVE-2023-44487", "CVE-2023-4911", "CVE-2023-38545", "CVE-2023-32681",
        "CVE-2023-28879", "CVE-2023-27536", "CVE-2023-23397", "CVE-2023-21716",
        "CVE-2022-47939", "CVE-2022-41040", "CVE-2022-37969", "CVE-2022-30190"
    ]
    
    vulnerabilities = []
    
    for i in range(50):
        severity_weights = [0.2, 0.4, 0.3, 0.1]  # Low, Medium, High, Critical
        severity = random.choices(["Low", "Medium", "High", "Critical"], weights=severity_weights)[0]
        
        software = random.choice(sample_software)
        host = random.choice(sample_hosts)
        port = random.choice(sample_ports)
        cve = random.choice(sample_cves) if random.random() > 0.3 else "N/A"
        
        # Generate version
        major = random.randint(1, 10)
        minor = random.randint(0, 20)
        patch = random.randint(0, 50)
        version = f"{major}.{minor}.{patch}"
        
        # Generate IP addresses
        ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 254)}"
        
        # Generate timestamps
        discovered_date = datetime.now() - timedelta(days=random.randint(1, 365))
        last_seen = discovered_date + timedelta(days=random.randint(0, 30))
        
        # Generate CVSS scores based on severity
        cvss_ranges = {
            "Low": (0.1, 3.9),
            "Medium": (4.0, 6.9),
            "High": (7.0, 8.9),
            "Critical": (9.0, 10.0)
        }
        cvss_min, cvss_max = cvss_ranges[severity]
        cvss_score = round(random.uniform(cvss_min, cvss_max), 1)
        
        # Generate vulnerability descriptions
        vuln_types = [
            "Buffer Overflow", "SQL Injection", "Cross-Site Scripting", "Remote Code Execution",
            "Privilege Escalation", "Information Disclosure", "Denial of Service", "Authentication Bypass",
            "Directory Traversal", "Command Injection", "XML External Entity", "Deserialization Vulnerability"
        ]
        
        vuln_type = random.choice(vuln_types)
        description = f"{vuln_type} vulnerability in {software} version {version}"
        
        vulnerability = {
            "id": f"VULN-{str(i+1).zfill(4)}",
            "title": f"{software} {vuln_type}",
            "description": description,
            "severity": severity,
            "cvss_score": cvss_score,
            "cve_id": cve,
            "software": software,
            "version": version,
            "host": host,
            "ip_address": ip,
            "port": port,
            "discovered_date": discovered_date.strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": last_seen.strftime("%Y-%m-%d %H:%M:%S"),
            "status": random.choice(["Open", "In Progress", "Resolved", "False Positive"]),
            "scanner": random.choice(["Nessus", "OpenVAS", "Qualys", "Rapid7", "Nmap"]),
            "remediation": f"Update {software} to the latest version or apply security patches"
        }
        
        vulnerabilities.append(vulnerability)
    
    return vulnerabilities

def generate_nessus_file(vulnerabilities):
    """Generate a Nessus-style CSV file"""
    
    nessus_data = []
    for vuln in vulnerabilities:
        nessus_row = {
            "Plugin ID": random.randint(10000, 99999),
            "CVE": vuln["cve_id"],
            "CVSS": vuln["cvss_score"],
            "Risk": vuln["severity"],
            "Host": vuln["ip_address"],
            "Protocol": "tcp",
            "Port": vuln["port"],
            "Name": vuln["title"],
            "Synopsis": vuln["description"][:100] + "...",
            "Description": vuln["description"],
            "Solution": vuln["remediation"],
            "Plugin Output": f"Version detected: {vuln['version']}"
        }
        nessus_data.append(nessus_row)
    
    return nessus_data

def generate_openvas_file(vulnerabilities):
    """Generate an OpenVAS-style CSV file"""
    
    openvas_data = []
    for vuln in vulnerabilities:
        openvas_row = {
            "IP": vuln["ip_address"],
            "Hostname": vuln["host"],
            "Port": vuln["port"],
            "Port Protocol": "tcp",
            "CVSS": vuln["cvss_score"],
            "Severity": vuln["severity"],
            "QoD": random.randint(70, 100),
            "NVT Name": vuln["title"],
            "Summary": vuln["description"],
            "Specific Result": f"Detected version: {vuln['version']}",
            "NVT OID": f"1.3.6.1.4.1.25623.1.0.{random.randint(100000, 999999)}",
            "CVEs": vuln["cve_id"],
            "Task Name": "Full and fast",
            "Timestamp": vuln["discovered_date"]
        }
        openvas_data.append(openvas_row)
    
    return openvas_data

def generate_qualys_file(vulnerabilities):
    """Generate a Qualys-style CSV file"""
    
    qualys_data = []
    for vuln in vulnerabilities:
        qualys_row = {
            "QID": random.randint(10000, 99999),
            "IP": vuln["ip_address"],
            "Detection ID": f"DET-{random.randint(1000, 9999)}",
            "Title": vuln["title"],
            "Vuln Status": vuln["status"].upper(),
            "Type": "Vuln",
            "Severity": {"Low": 2, "Medium": 3, "High": 4, "Critical": 5}[vuln["severity"]],
            "Port": vuln["port"],
            "Protocol": "TCP",
            "FQDN": f"{vuln['host']}.example.com",
            "OS": random.choice(["Linux", "Windows Server 2019", "Ubuntu 20.04", "CentOS 7"]),
            "First Detected": vuln["discovered_date"],
            "Last Detected": vuln["last_seen"],
            "Times Detected": random.randint(1, 10),
            "CVE ID": vuln["cve_id"],
            "Vendor Reference": f"https://vendor.com/advisory/{random.randint(1000, 9999)}",
            "Bugtraq ID": random.randint(10000, 99999) if random.random() > 0.5 else "",
            "Threat": random.choice(["Remote", "Local", "Adjacent Network"]),
            "Impact": random.choice(["Server", "General", "Database"]),
            "Solution": vuln["remediation"],
            "Exploitability": random.choice(["Unproven", "Proof of Concept", "Functional", "High"]),
            "Associated Malware": random.choice(["None", "Trojan.Generic", "Backdoor.Remote"]) if random.random() > 0.8 else "None"
        }
        qualys_data.append(qualys_row)
    
    return qualys_data

def save_to_json(data, filename):
    """Save data to JSON file"""
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"Saved JSON data to {filename}")

def save_to_csv(data, filename):
    """Save data to CSV file"""
    if not data:
        print(f"No data to save to {filename}")
        return
    
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        fieldnames = data[0].keys()
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)
    print(f"Saved CSV data to {filename} ({len(data)} records)")

def create_output_directory():
    """Create output directory if it doesn't exist"""
    output_dir = "sample_vulnerability_data"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    return output_dir

def main():
    """Main function to generate all sample data"""
    
    print("Generating sample vulnerability data...")
    
    # Create output directory
    output_dir = create_output_directory()
    
    # Generate vulnerability data
    vulnerabilities = generate_sample_vulnerabilities()
    
    # Save master vulnerability data
    save_to_json(vulnerabilities, os.path.join(output_dir, "vulnerabilities.json"))
    save_to_csv(vulnerabilities, os.path.join(output_dir, "vulnerabilities.csv"))
    
    # Generate scanner-specific files
    print("\nGenerating scanner-specific files...")
    
    # Nessus format
    nessus_data = generate_nessus_file(vulnerabilities)
    save_to_csv(nessus_data, os.path.join(output_dir, "nessus_scan.csv"))
    
    # OpenVAS format
    openvas_data = generate_openvas_file(vulnerabilities)
    save_to_csv(openvas_data, os.path.join(output_dir, "openvas_scan.csv"))
    
    # Qualys format
    qualys_data = generate_qualys_file(vulnerabilities)
    save_to_csv(qualys_data, os.path.join(output_dir, "qualys_scan.csv"))
    
    # Generate summary statistics
    print("\n" + "="*50)
    print("VULNERABILITY SUMMARY")
    print("="*50)
    
    severity_counts = {}
    status_counts = {}
    scanner_counts = {}
    
    for vuln in vulnerabilities:
        severity_counts[vuln['severity']] = severity_counts.get(vuln['severity'], 0) + 1
        status_counts[vuln['status']] = status_counts.get(vuln['status'], 0) + 1
        scanner_counts[vuln['scanner']] = scanner_counts.get(vuln['scanner'], 0) + 1
    
    print(f"Total vulnerabilities generated: {len(vulnerabilities)}")
    print(f"\nBy Severity:")
    for severity, count in sorted(severity_counts.items()):
        print(f"  {severity}: {count}")
    
    print(f"\nBy Status:")
    for status, count in sorted(status_counts.items()):
        print(f"  {status}: {count}")
    
    print(f"\nBy Scanner:")
    for scanner, count in sorted(scanner_counts.items()):
        print(f"  {scanner}: {count}")
    
    print(f"\nFiles generated in '{output_dir}' directory:")
    print(f"  - vulnerabilities.json (master data)")
    print(f"  - vulnerabilities.csv (master data)")
    print(f"  - nessus_scan.csv (Nessus format)")
    print(f"  - openvas_scan.csv (OpenVAS format)")
    print(f"  - qualys_scan.csv (Qualys format)")
    
    print("\nSample data generation completed successfully!")

if __name__ == "__main__":
    main()
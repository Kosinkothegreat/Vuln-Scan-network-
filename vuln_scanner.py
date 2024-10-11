#!/usr/bin/env python3

import nmap
import sys
import time
import json

# Define a simple vulnerability database
VULN_DB = {
    "22": {"service": "ssh", "vulnerabilities": ["CVE-2018-15473: OpenSSH User Enumeration"]},
    "80": {"service": "http", "vulnerabilities": ["CVE-2019-6340: Drupal Remote Code Execution"]},
    "443": {"service": "https", "vulnerabilities": ["CVE-2020-0601: Windows CryptoAPI Spoofing"]},
    "3306": {"service": "mysql", "vulnerabilities": ["CVE-2012-2122: MySQL Information Disclosure"]},
    "3389": {"service": "ms-wbt-server", "vulnerabilities": ["CVE-2019-0708: BlueKeep RDP Vulnerability"]},
    # Add more ports and vulnerabilities as needed
}

def scan_host(target_ip):
    scanner = nmap.PortScanner()
    print(f"Starting scan on {target_ip}...")
    
    try:
        # Perform a TCP SYN scan on common ports
        scanner.scan(target_ip, arguments='-sS -T4')
    except Exception as e:
        print(f"Error scanning {target_ip}: {e}")
        sys.exit(1)
    
    print("Scan complete.\n")
    return scanner

def analyze_scan(scanner, target_ip):
    report = {}
    if target_ip in scanner.all_hosts():
        print(f"Host: {target_ip} ({scanner[target_ip].hostname()})")
        print(f"State: {scanner[target_ip].state()}\n")
        
        for proto in scanner[target_ip].all_protocols():
            print(f"Protocol: {proto}")
            ports = scanner[target_ip][proto].keys()
            for port in sorted(ports):
                state = scanner[target_ip][proto][port]['state']
                service = scanner[target_ip][proto][port]['name']
                print(f"Port: {port}\tState: {state}\tService: {service}")
                
                # Check for vulnerabilities
                if str(port) in VULN_DB:
                    vulnerabilities = VULN_DB[str(port)]["vulnerabilities"]
                    print(f"\tVulnerabilities:")
                    for vuln in vulnerabilities:
                        print(f"\t - {vuln}")
                    
                    # Add to report
                    report[port] = {
                        "service": service,
                        "vulnerabilities": vulnerabilities
                    }
            print("\n")
    else:
        print(f"No information available for host: {target_ip}")
    
    return report

def save_report(report, target_ip):
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    report_filename = f"vuln_report_{target_ip}_{timestamp}.json"
    
    try:
        with open(report_filename, 'w') as report_file:
            json.dump(report, report_file, indent=4)
        print(f"Report saved to {report_filename}")
    except Exception as e:
        print(f"Error saving report: {e}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 vuln_scanner.py <target_ip>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    scanner = scan_host(target_ip)
    report = analyze_scan(scanner, target_ip)
    
    if report:
        save_report(report, target_ip)
    else:
        print("No vulnerabilities found.")

if __name__ == "__main__":
    main()

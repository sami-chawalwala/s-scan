#!/usr/bin/env python3

import socket
import ipaddress
import subprocess
import threading
import time
import argparse
import sys
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import re
import requests
import json

class NetworkScanner:
    def __init__(self, target, timeout=1, threads=100):
        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.active_hosts = []
        self.open_ports = {}
        self.os_info = {}
        self.start_time = datetime.now()
        self.vulnerabilities = {}
        
        self.common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
            27017: "MongoDB",
            62078: "iPhone Sync", 7000: "AirPlay", 5353: "mDNS"
        }
        
        self.vendors = {
            "00:1A:2B": "Apple", "00:1D:4F": "Apple", "00:1E:52": "Apple",
            "00:1C:B3": "Apple", "00:19:E3": "Apple", "A4:D1:D2": "Apple",
            "B4:8F:80": "Apple", "E4:CE:8F": "Apple", "F8:1E:DF": "Apple",
            "10:1C:0C": "Apple", "00:23:DF": "Apple", "00:25:BC": "Apple",
            "00:1F:F3": "Apple", "00:16:CB": "Apple", "00:1E:C2": "Apple",
            "B8:31:B5": "Apple", "C8:69:CD": "Apple", "D4:23:DE": "Apple",
            "EC:35:86": "Apple", "F0:18:98": "Apple", "34:12:98": "Samsung",
            "00:23:D4": "Samsung", "40:16:7E": "Samsung", "38:AA:3C": "Samsung",
            "84:38:38": "Samsung", "BC:20:A4": "Samsung", "DC:A4:CA": "Samsung",
            "E0:AC:CB": "Samsung", "FC:DB:B3": "Samsung", "00:0A:F5": "Google",
            "00:1C:DF": "Google", "A4:77:33": "Google", "BC:6A:29": "Google",
            "D0:82:90": "Google", "E4:0F:7A": "Google", "F4:F5:24": "Google",
            "00:22:68": "OnePlus", "00:24:98": "OnePlus", "A4:70:D6": "OnePlus",
            "B4:75:0E": "OnePlus", "7C:2A:31": "Xiaomi", "B4:6D:83": "Xiaomi",
            "D4:3B:04": "Xiaomi", "E8:5B:5B": "Xiaomi", "08:32:19": "Huawei",
            "28:2C:B2": "Huawei", "4C:32:75": "Huawei", "5C:E2:7C": "Huawei"
        }
        
        self.port_vulnerabilities = {
            21: ["Anonymous login", "Weak password", "Version disclosure"],
            22: ["Weak SSH keys", "Password brute-force possible", "Old OpenSSH versions"],
            23: ["Telnet is insecure", "Credentials in clear text", "No encryption"],
            25: ["Open relay possible", "SPF/DKIM missing"],
            53: ["DNS zone transfer possible", "Cache poisoning risk"],
            80: ["HTTP without TLS", "Directory listing possible", "SQL injection risk"],
            110: ["POP3 without TLS", "Credentials in clear text"],
            111: ["RPC exposed", "Portmapper abuse"],
            135: ["RPC exposed", "NetBIOS vulnerability"],
            139: ["NetBIOS exposed", "SMB vulnerability"],
            143: ["IMAP without TLS", "Credentials in clear text"],
            443: ["SSL/TLS vulnerabilities", "Weak ciphers", "Heartbleed if OpenSSL 1.0.1"],
            445: ["SMB vulnerability", "EternalBlue possible if unpatched"],
            993: ["SSL/TLS vulnerabilities on IMAPS"],
            995: ["SSL/TLS vulnerabilities on POP3S"],
            1723: ["PPTP is insecure", "MS-CHAPv2 can be cracked"],
            3306: ["Default credentials", "Weak root password", "Remote access allowed"],
            3389: ["RDP vulnerability", "BlueKeep if unpatched", "Weak credentials"],
            5432: ["Default credentials", "Weak password", "Remote access allowed"],
            5900: ["VNC without password", "Weak VNC auth", "Remote access"],
            6379: ["Redis without auth", "Remote code execution"],
            8080: ["HTTP without TLS", "Directory listing possible", "Default credentials"],
            8443: ["SSL/TLS vulnerabilities", "Weak ciphers"],
            27017: ["MongoDB without auth", "Remote access", "Default credentials"]
        }
    
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def get_network_range(self, ip, subnet_mask="255.255.255.0"):
        network = ipaddress.IPv4Network(f"{ip}/{subnet_mask}", strict=False)
        return network
    
    def ping_host(self, ip):
        try:
            if sys.platform.startswith('win'):
                result = subprocess.run(['ping', '-n', '1', '-w', str(self.timeout*1000), ip], 
                                      capture_output=True, text=True, timeout=self.timeout+1)
                if "Reply from" in result.stdout or "TTL=" in result.stdout:
                    return ip
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', str(self.timeout), ip],
                                      capture_output=True, text=True, timeout=self.timeout+1)
                if result.returncode == 0:
                    return ip
            return None
        except:
            return None
    
    def arp_ping(self, ip):
        try:
            if sys.platform.startswith('win'):
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=2)
                if "No ARP entries found" not in result.stdout and ip in result.stdout:
                    return ip
            else:
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=2)
                if "incomplete" not in result.stdout.lower() and ip in result.stdout:
                    return ip
            return None
        except:
            return None
    
    def tcp_ping(self, ip):
        ports = [80, 443, 22, 21, 25, 53, 445, 3389, 8080, 8443]
        try:
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    if result == 0:
                        return ip
                except:
                    pass
            return None
        except:
            return None
    
    def scan_network(self, network):
        print(f"\n[+] SCANNING NETWORK: {network}")
        print(f"[+] Total IPs to scan: {network.num_addresses}")
        print(f"[+] Methods: ICMP Ping + ARP Ping + TCP SYN Ping")
        print(f"[+] Starting scan...")
        
        ip_list = [str(ip) for ip in network.hosts()]
        active_set = set()
        
        print(f"[+] Phase 1: ICMP Ping Sweep...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = list(executor.map(self.ping_host, ip_list))
            for ip in results:
                if ip:
                    active_set.add(ip)
        
        print(f"[+] Phase 2: ARP Ping Sweep...")
        remaining = [ip for ip in ip_list if ip not in active_set]
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = list(executor.map(self.arp_ping, remaining))
            for ip in results:
                if ip:
                    active_set.add(ip)
        
        print(f"[+] Phase 3: TCP SYN Ping Sweep...")
        remaining = [ip for ip in ip_list if ip not in active_set]
        if remaining:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                results = list(executor.map(self.tcp_ping, remaining))
                for ip in results:
                    if ip:
                        active_set.add(ip)
        
        self.active_hosts = sorted(list(active_set))
        return self.active_hosts
    
    def get_mac_address(self, ip):
        try:
            if sys.platform.startswith('win'):
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True)
                match = re.search(r'([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}', result.stdout)
                if match:
                    return match.group(0)
            else:
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
                match = re.search(r'([0-9A-Fa-f]{2}[:]){5}[0-9A-Fa-f]{2}', result.stdout)
                if match:
                    return match.group(0)
            return "N/A"
        except:
            return "N/A"
    
    def get_hostname(self, ip):
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "N/A"
    
    def get_vendor_from_mac(self, mac):
        if mac == "N/A":
            return "Unknown"
        mac_prefix = mac.upper()[:8]
        for prefix, vendor in self.vendors.items():
            if mac_prefix.startswith(prefix):
                return vendor
        return "Unknown"
    
    def detect_os_enhanced(self, ip, open_ports):
        os_info = {
            "guess": "Unknown",
            "confidence": "Low",
            "ttl": None,
            "device_type": "Unknown",
            "vendor": "Unknown"
        }
        
        mac = self.get_mac_address(ip)
        vendor = self.get_vendor_from_mac(mac)
        os_info["vendor"] = vendor
        
        if vendor and vendor != "Unknown":
            if vendor == "Apple":
                os_info["guess"] = "Apple iOS/macOS"
                os_info["device_type"] = "Apple Device"
                os_info["confidence"] = "High"
            elif vendor == "Samsung":
                os_info["guess"] = "Android (Samsung)"
                os_info["device_type"] = "Android Phone"
                os_info["confidence"] = "High"
            elif vendor == "Google":
                os_info["guess"] = "Android/Google Device"
                os_info["device_type"] = "Google Device"
                os_info["confidence"] = "High"
            elif vendor == "OnePlus":
                os_info["guess"] = "Android (OnePlus)"
                os_info["device_type"] = "Android Phone"
                os_info["confidence"] = "High"
            elif vendor == "Xiaomi":
                os_info["guess"] = "Android (Xiaomi)"
                os_info["device_type"] = "Android Phone"
                os_info["confidence"] = "High"
        
        try:
            if sys.platform.startswith('win'):
                result = subprocess.run(['ping', '-n', '1', ip], capture_output=True, text=True, timeout=3)
            else:
                result = subprocess.run(['ping', '-c', '1', ip], capture_output=True, text=True, timeout=3)
            
            ttl_match = re.search(r'ttl[=:](\d+)', result.stdout, re.IGNORECASE)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                os_info["ttl"] = ttl
                
                if ttl <= 64:
                    if vendor == "Apple":
                        os_info["guess"] = "Apple iOS/macOS"
                        os_info["device_type"] = "Apple Device"
                    else:
                        os_info["guess"] = "Linux/Unix/Android"
                        os_info["device_type"] = "Linux/Android Device"
                    os_info["confidence"] = "High"
                elif ttl <= 128:
                    if vendor == "Apple":
                        os_info["guess"] = "Apple iOS/macOS (Windows TTL)"
                        os_info["device_type"] = "Apple Device"
                    else:
                        os_info["guess"] = "Windows"
                        os_info["device_type"] = "Windows Device"
                    os_info["confidence"] = "Medium"
                elif ttl <= 255:
                    os_info["guess"] = "Network Device"
                    os_info["device_type"] = "Network Device"
                    os_info["confidence"] = "Medium"
        except:
            pass
        
        if open_ports:
            if 62078 in open_ports:
                os_info["guess"] = "Apple iOS (iPhone/iPad)"
                os_info["device_type"] = "iPhone/iPad"
                os_info["confidence"] = "High"
            elif 7000 in open_ports:
                os_info["guess"] = "Apple iOS/macOS (AirPlay)"
                os_info["device_type"] = "Apple Device with AirPlay"
                os_info["confidence"] = "High"
            elif 5353 in open_ports and vendor == "Apple":
                os_info["guess"] = "Apple iOS/macOS (mDNS)"
                os_info["device_type"] = "Apple Device"
                os_info["confidence"] = "High"
        
        self.os_info[ip] = os_info
        return os_info
    
    def extract_version_from_banner(self, banner, port):
        patterns = {
            21: r'(\d+\.\d+\.\d+)',
            22: r'OpenSSH[-_]?(\d+\.\d+\.?\d*)',
            80: r'(?:Apache|nginx|Tomcat)/(\d+\.\d+\.?\d*)',
            443: r'(?:Apache|nginx|Tomcat)/(\d+\.\d+\.?\d*)',
            3306: r'(\d+\.\d+\.\d+)',
            5432: r'(\d+\.\d+\.\d+)',
            5900: r'(\d+\.\d+\.\d+)',
            3389: r'(\d+\.\d+\.\d+)',
            8080: r'(?:Apache|nginx|Tomcat)/(\d+\.\d+\.?\d*)',
            8443: r'(?:Apache|nginx|Tomcat)/(\d+\.\d+\.?\d*)',
        }
        
        if port in patterns:
            match = re.search(patterns[port], banner, re.IGNORECASE)
            if match:
                return match.group(1)
        
        match = re.search(r'v?(\d+\.\d+\.?\d*)', banner, re.IGNORECASE)
        if match:
            return match.group(1)
        return 'Unknown'
    
    def get_service_banner(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            if port in [21, 25, 110, 143]:
                data = sock.recv(1024).decode('utf-8', errors='ignore')
            elif port in [80, 443, 8080, 8443]:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                data = sock.recv(1024).decode('utf-8', errors='ignore')
            elif port in [22, 23]:
                data = sock.recv(1024).decode('utf-8', errors='ignore')
            else:
                sock.send(b'\n')
                data = sock.recv(1024).decode('utf-8', errors='ignore')
            
            sock.close()
            return data.strip()[:300] if data else 'No banner'
        except:
            return 'No banner'
    
    def check_cves_nvd(self, service, version):
        if not version or version == 'Unknown':
            return []
        
        cvss_list = []
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service}%20{version}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for vuln in data.get('vulnerabilities', [])[:5]:
                    cve = vuln.get('cve', {})
                    cve_id = cve.get('id', 'Unknown')
                    metrics = cve.get('metrics', {})
                    cvss_v3 = metrics.get('cvssMetricV31', [])
                    score = cvss_v3[0].get('cvssData', {}).get('baseScore', 0) if cvss_v3 else 0
                    desc = cve.get('descriptions', [{}])[0].get('value', '')[:200]
                    
                    cvss_list.append({
                        'id': cve_id,
                        'score': score,
                        'severity': self.get_severity(score),
                        'description': desc
                    })
        except:
            pass
        return cvss_list
    
    def get_severity(self, score):
        if score >= 9.0:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        elif score > 0:
            return 'LOW'
        return 'N/A'
    
    def nmap_style_vuln_scan(self, ip, open_ports):
        print(f"\n" + "-"*0)
        print(f"                    DEEP VULNERABILITY SCAN")
        print(f"~"*70)
        print(f"\n[+] TARGET: {ip}")
        print(f"[+] Mode: Version Detection + CVE Lookup")
        print(f"[+] This is equivalent to: nmap -sV --script vuln\n")
        
        if not open_ports:
            print(f"[+] No open ports found on {ip}")
            return
        
        os_info = self.detect_os_enhanced(ip, open_ports)
        
        print(f"[+] OS DETECTION")
        print(f"    Device: {os_info['device_type']} ({os_info['guess']})")
        print(f"    Vendor: {os_info['vendor']}")
        if os_info['ttl']:
            print(f"    TTL: {os_info['ttl']}")
        print(f"    Confidence: {os_info['confidence']}\n")
        
        print(f"[+] Detecting service versions on {len(open_ports)} open ports...\n")
        print(f"    {'PORT':<10} {'SERVICE':<15} {'VERSION':<25} {'CVES'}")
        print(f"    {'-'*75}")
        
        total_cves = 0
        vuln_details = {}
        
        for port in sorted(open_ports):
            service = self.common_ports.get(port, 'Unknown')
            banner = self.get_service_banner(ip, port)
            version = self.extract_version_from_banner(banner, port)
            cves = self.check_cves_nvd(service, version) if version != 'Unknown' else []
            cve_count = len(cves)
            total_cves += cve_count
            
            version_display = version if version != 'Unknown' else 'N/A'
            cve_display = f"{cve_count} found" if cve_count > 0 else "None"
            print(f"    {port:<10} {service:<15} {version_display:<25} {cve_display}")
            
            if cve_count > 0:
                vuln_details[port] = {
                    'service': service,
                    'version': version,
                    'banner': banner,
                    'cves': cves
                }
                print(f"    {' ' * 10}{' ' * 15}{' ' * 25} └─ Detailed CVEs:")
                for cve in cves[:3]:
                    print(f"    {' ' * 10}{' ' * 15}{' ' * 25}    ├─ {cve['id']} ({cve['severity']})")
                    print(f"    {' ' * 10}{' ' * 15}{' ' * 25}    │  Score: {cve['score']}")
                    print(f"    {' ' * 10}{' ' * 15}{' ' * 25}    │  {cve['description'][:80]}...")
                if len(cves) > 3:
                    print(f"    {' ' * 10}{' ' * 15}{' ' * 25}    └─ ... and {len(cves) - 3} more")
                else:
                    print(f"    {' ' * 10}{' ' * 15}{' ' * 25}    └─")
        
        print(f"\n[+] VULNERABILITY SUMMARY FOR {ip}")
        print(f"    Device: {os_info['device_type']} ({os_info['guess']})")
        print(f"    Total Open Ports: {len(open_ports)}")
        print(f"    Total CVEs Found: {total_cves}")
        print(f"    Risk Level: {self.get_risk_level(total_cves)}")
        
        if total_cves == 0:
            print(f"    ✅ No known vulnerabilities found on this host.")
        else:
            print(f"    ⚠  Host has {total_cves} known vulnerabilities. Review details above.")
        
        print(f"\n[+] DETAILED VULNERABILITY INFORMATION:")
        for port, details in vuln_details.items():
            print(f"\n    PORT {port} ({details['service']})")
            print(f"    Version: {details['version']}")
            if details['banner'] and details['banner'] != 'No banner':
                print(f"    Banner: {details['banner'][:100]}")
            print(f"    CVEs:")
            for cve in details['cves']:
                print(f"      - {cve['id']} ({cve['severity']}) - Score: {cve['score']}")
                print(f"        {cve['description']}")
                print(f"        References: https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve['id']}")
        
        print(f"\n" + "="*0)
        print(f"                    SCAN COMPLETE")
        print(f"."*60)
    
    def get_risk_level(self, cve_count):
        if cve_count == 0:
            return "LOW (No CVEs found)"
        elif cve_count <= 2:
            return "MEDIUM (Minor vulnerabilities)"
        elif cve_count <= 5:
            return "HIGH (Multiple vulnerabilities)"
        else:
            return "CRITICAL (Heavily vulnerable)"
    
    def scan_all_ports(self, ip):
        open_ports = []
        print(f"[+] Scanning all 65535 ports on {ip} (aggressive mode)...")
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return port
            except:
                pass
            return None
        
        batch_size = 1000
        for start in range(1, 65536, batch_size):
            end = min(start + batch_size, 65536)
            ports = list(range(start, end))
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                results = list(executor.map(scan_port, ports))
                batch_open = [p for p in results if p]
                open_ports.extend(batch_open)
            
            if batch_open:
                print(f"[+] Found {len(batch_open)} open ports in range {start}-{end}")
        
        self.open_ports[ip] = open_ports
        return open_ports
    
    def scan_common_ports(self, ip):
        ports = list(self.common_ports.keys())
        open_ports = []
        print(f"[+] Scanning common ports on {ip}...")
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return port
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = list(executor.map(scan_port, ports))
            open_ports = [p for p in results if p]
        
        self.open_ports[ip] = open_ports
        return open_ports
    
    def get_os_guess(self, ip, open_ports):
        os_guess = "Unknown"
        
        if 22 in open_ports and 80 in open_ports:
            os_guess = "Linux/Unix (likely)"
        elif 22 in open_ports and 3389 in open_ports:
            os_guess = "Windows (likely)"
        elif 80 in open_ports and 443 in open_ports:
            os_guess = "Web Server (Linux/Windows)"
        elif 139 in open_ports and 445 in open_ports:
            os_guess = "Windows (SMB)"
        elif 22 in open_ports and 3306 in open_ports:
            os_guess = "Linux (MySQL)"
        
        try:
            if sys.platform.startswith('win'):
                result = subprocess.run(['ping', '-n', '1', ip], capture_output=True, text=True)
            else:
                result = subprocess.run(['ping', '-c', '1', ip], capture_output=True, text=True)
            
            ttl_match = re.search(r'ttl[=:](\d+)', result.stdout, re.IGNORECASE)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                if ttl <= 64:
                    os_guess = f"Linux/Unix (TTL: {ttl})"
                elif ttl <= 128:
                    os_guess = f"Windows (TTL: {ttl})"
                elif ttl <= 255:
                    os_guess = f"Network Device/Cisco (TTL: {ttl})"
        except:
            pass
        
        return os_guess
    
    def aggressive_scan(self, ip):
        os_guess = self.get_os_guess(ip, self.open_ports.get(ip, []))
        open_ports = self.open_ports.get(ip, [])
        
        print(f"\n" + "-"*0)
        print(f"                    AGGRESSIVE SCAN ON {ip}")
        print(f"~"*80)
        
        print(f"\n[+] STEP 1: OS Detection")
        print(f"-"*40)
        print(f"    OS: {os_guess}")
        
        print(f"\n[+] STEP 2: Open Ports")
        print(f"-"*40)
        if open_ports:
            print(f"    Found {len(open_ports)} open ports:")
            for port in sorted(open_ports):
                service = self.common_ports.get(port, "Unknown")
                print(f"    - {port}/tcp  ({service})")
        else:
            print(f"    No open ports found")
        
        print(f"\n[+] STEP 3: Vulnerability Assessment")
        print(f"-"*40)
        vulns = self.check_vulnerabilities(ip, open_ports)
        if vulns:
            for port, vuln_list in vulns.items():
                service = self.common_ports.get(port, "Unknown")
                print(f"    Port {port} ({service}):")
                for vuln in vuln_list:
                    print(f"      - {vuln}")
        else:
            print(f"    No known vulnerabilities found")
        
        print(f"\n[+] STEP 4: Service Analysis")
        print(f"-"*40)
        for port in sorted(open_ports):
            service = self.common_ports.get(port, "Unknown")
            if port in [21, 22, 23, 3389]:
                print(f"    - {port}/tcp ({service}): Check for default/weak credentials")
            elif port in [80, 443, 8080, 8443]:
                print(f"    - {port}/tcp ({service}): Check for web vulnerabilities")
            elif port in [3306, 5432, 27017, 6379]:
                print(f"    - {port}/tcp ({service}): Check for default credentials")
            elif port in [139, 445]:
                print(f"    - {port}/tcp ({service}): Check for SMB vulnerabilities")
            else:
                print(f"    - {port}/tcp ({service}): Further investigation recommended")
        
        print(f"\n" + "-"*0)
        print(f"                    SCAN COMPLETE")
        print(f"\n" + "^"*60)
    
    def display_active_hosts(self):
        print(f"\n" + "-"*80)
        print(f"                    ACTIVE HOSTS ON NETWORK")
        print(f"="*80)
        print(f"{'NO.':<6} {'IP Address':<20} {'Hostname':<30} {'MAC Address':<20}")
        print(f"-"*80)
        
        for idx, ip in enumerate(sorted(self.active_hosts), 1):
            hostname = self.get_hostname(ip)
            mac = self.get_mac_address(ip)
            print(f"{idx:<6} {ip:<20} {hostname:<30} {mac:<20}")
        
        print(f"\n[+] Total Active Hosts: {len(self.active_hosts)}")
        print(f"="*0)
    
    def check_vulnerabilities(self, ip, open_ports):
        vulns = {}
        for port in open_ports:
            if port in self.port_vulnerabilities:
                vulns[port] = self.port_vulnerabilities[port]
        return vulns
    
    def parse_target_input(self, user_input):
        parts = user_input.strip().split()
        
        if len(parts) == 1:
            return parts[0], False
        elif len(parts) == 2 and parts[1].lower() == '-s':
            return parts[0], True
        else:
            return user_input, False
    
    def run(self):
        print(f"\n[+] NETWORK SCANNER TOOL")
        print(f"[+] Developed by: SAMI CHAWALWALA")
        print(f"[+] Starting at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if self.target == "auto":
            local_ip = self.get_local_ip()
            print(f"\n[+] Local IP Detected: {local_ip}")
            network = self.get_network_range(local_ip)
            self.target = str(network)
            print(f"[+] Network Range: {self.target}")
        else:
            try:
                network = ipaddress.IPv4Network(self.target, strict=False)
                print(f"[+] Network Range: {self.target}")
            except:
                print(f"\n[-] Invalid network format!")
                print(f"[+] Use: 192.168.1.0/24 or auto")
                return
        
        active = self.scan_network(network)
        
        if not active:
            print(f"\n[-] No active hosts found!")
            return
        
        print(f"\n[+] Found {len(active)} active hosts")
        
        self.display_active_hosts()
        
        while True:
            print(f"\n" + "-"*80)
            print(f"                    SELECT TARGET FOR PORT SCAN")
            print(f"="*80)
            print(f"\n[+] Enter the IP address from the list above to perform:")
            print(f"    - Port scanning")
            print(f"    - OS detection")
            print(f"    - Vulnerability assessment")
            print(f"    - Service analysis")
            print(f"\n[+]  Activate sin~sam scan, use: <IP> -s")
            print(f"\n[-] Or type 'all' to scan all active hosts")
            print(f"[-] Or type 'quick' for fast common port scan")
            print(f"[-] Or type 'exit' to quit")
            
            choice = input(f"\n[?] Enter target IP: ").strip()
            
            if choice.lower() == 'exit':
                print(f"\n[+] Exiting...")
                sys.exit(0)
            
            if choice.lower() == 'all':
                for ip in sorted(self.active_hosts):
                    print(f"\n[+] Scanning {ip}...")
                    open_ports = self.scan_all_ports(ip)
                    self.aggressive_scan(ip)
                continue
            
            if choice.lower() == 'quick':
                for ip in sorted(self.active_hosts):
                    print(f"\n[+] Quick scanning {ip}...")
                    open_ports = self.scan_common_ports(ip)
                    self.aggressive_scan(ip)
                continue
            
            target_ip, deep_vuln = self.parse_target_input(choice)
            
            if target_ip in self.active_hosts:
                print(f"\n[+] Scanning {target_ip}...")
                open_ports = self.scan_all_ports(target_ip)
                
                if deep_vuln:
                    print(f"\n[+] DEEP VULNERABILITY MODE ACTIVATED (-s)")
                    self.nmap_style_vuln_scan(target_ip, open_ports)
                else:
                    self.aggressive_scan(target_ip)
                
                continue
            else:
                print(f"\n[-] Invalid IP. Please enter a valid IP from the list or 'all'/'quick'/'exit'")
                continue

def main():
    parser = argparse.ArgumentParser(
        description="Network Scanner Tool",
        epilog="USE IT, ABUSE IT, WHO CARE"
    )
    
    parser.add_argument('-t', '--target', default='auto', 
                       help='Target network (e.g., 192.168.1.0/24) or "auto" for local network')
    parser.add_argument('--timeout', type=float, default=1, help='Timeout in seconds (default: 1)')
    parser.add_argument('--threads', type=int, default=100, help='Number of threads (default: 100)')
    
    args = parser.parse_args()
    
    scanner = NetworkScanner(args.target, args.timeout, args.threads)
    scanner.run()

if __name__ == '__main__':
    main()


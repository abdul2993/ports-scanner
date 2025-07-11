#!/usr/bin/env python3
import socket
import sys
import argparse
import time
import concurrent.futures
import ipaddress
from typing import List, Optional, Tuple

class PortScanner:
    def __init__(self):
        self.timeout = 1.0
        self.max_threads = 100
        self.verbose = False
        self.scan_results = []
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
            443, 445, 587, 993, 995, 1723, 3306, 3389,
            5900, 8080, 8443, 27017, 27018
        ]
        self.banner = r"""
==============================
       Port Scanner Tool
==============================
"""

    def validate_ip(self, ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def resolve_hostname(self, hostname: str) -> Optional[str]:
        try:
            ip = socket.gethostbyname(hostname)
            if self.validate_ip(ip):
                return ip
            return None
        except (socket.gaierror, socket.error):
            return None

    def scan_port(self, target_ip: str, port: int) -> Optional[Tuple[int, str]]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((target_ip, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except OSError:
                        service = "unknown"
                    if self.verbose:
                        print(f"[+] Port {port}/tcp open - {service}")
                    return (port, service)
        except (socket.timeout, socket.error) as e:
            if self.verbose:
                print(f"[-] Port {port}/tcp error: {str(e)}")
        return None

    def scan_ports(self, target_ip: str, ports: List[int]) -> List[Tuple[int, str]]:
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.scan_port, target_ip, port): port for port in ports}
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    result = future.result()
                    if result:
                        open_ports.append(result)
                except Exception as e:
                    if self.verbose:
                        print(f"Error scanning port {port}: {e}")
        return sorted(open_ports, key=lambda x: x[0])

    def parse_ports(self, ports_arg: str) -> List[int]:
        if ports_arg.lower() == 'common':
            return self.common_ports
        elif ',' in ports_arg:
            return [int(p.strip()) for p in ports_arg.split(',') if p.strip().isdigit()]
        elif '-' in ports_arg:
            try:
                start, end = map(int, ports_arg.split('-'))
                return list(range(start, end + 1))
            except ValueError:
                raise ValueError("Invalid port range format. Use 'start-end'")
        elif ports_arg.isdigit():
            return [int(ports_arg)]
        else:
            raise ValueError("Invalid ports specification")

    def print_results(self, target: str, open_ports: List[Tuple[int, str]], scan_time: float):
        print("\nScan Results:")
        print("-" * 50)
        print(f"Target: {target}")
        print(f"Scanned ports: {len(self.scan_results)}")
        print(f"Open ports: {len(open_ports)}")
        print(f"Scan duration: {scan_time:.2f} seconds\n")

        if open_ports:
            for port, service in open_ports:
                print(f"Port {port}/tcp is open - Service: {service}")
        else:
            print("No open ports found.")
        print("-" * 50)

    def run(self, args):
        print(self.banner)
        print("[*] Starting Port Scanner...")

        target_ip = self.resolve_hostname(args.target)
        if not target_ip:
            print(f"[!] Invalid IP or hostname: {args.target}")
            sys.exit(1)

        try:
            ports_to_scan = self.parse_ports(args.ports)
        except ValueError as ve:
            print(f"[!] Error: {ve}")
            sys.exit(1)

        self.verbose = args.verbose
        self.timeout = args.timeout
        self.max_threads = args.threads

        start_time = time.time()
        self.scan_results = self.scan_ports(target_ip, ports_to_scan)
        duration = time.time() - start_time

        self.print_results(args.target, self.scan_results, duration)

def main():
    parser = argparse.ArgumentParser(description="Python Multi-threaded Port Scanner")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="common", help="Ports to scan (e.g., 22,80,443 or 1-1024 or 'common')")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()
    scanner = PortScanner()
    scanner.run(args)

if __name__ == "__main__":
    main()

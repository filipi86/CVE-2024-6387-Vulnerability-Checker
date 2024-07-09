#!/usr/bin/env python3

import socket
import argparse
import ipaddress

# Define color codes
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
ORANGE = "\033[33m"
ENDC = "\033[0m"

# Define known vulnerable and patched versions
vulnerable_versions = {
    'SSH-2.0-OpenSSH_1', 'SSH-2.0-OpenSSH_2', 'SSH-2.0-OpenSSH_3', 'SSH-2.0-OpenSSH_4.0',
    'SSH-2.0-OpenSSH_4.1', 'SSH-2.0-OpenSSH_4.2', 'SSH-2.0-OpenSSH_4.3', 'SSH-2.0-OpenSSH_4.4',
    'SSH-2.0-OpenSSH_8.5', 'SSH-2.0-OpenSSH_8.6', 'SSH-2.0-OpenSSH_8.7', 'SSH-2.0-OpenSSH_8.8',
    'SSH-2.0-OpenSSH_8.9', 'SSH-2.0-OpenSSH_9.0', 'SSH-2.0-OpenSSH_9.1', 'SSH-2.0-OpenSSH_9.2',
    'SSH-2.0-OpenSSH_9.3', 'SSH-2.0-OpenSSH_9.4', 'SSH-2.0-OpenSSH_9.5', 'SSH-2.0-OpenSSH_9.6',
    'SSH-2.0-OpenSSH_9.7'
}

patched_versions = {
    'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10', 'SSH-2.0-OpenSSH_9.3p1 Ubuntu-3ubuntu3.6',
    'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.3', 'SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.6',
    'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3', 'SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3',
    'SSH-2.0-OpenSSH_9.7p1 Debian-7'
}

def display_banner():
    banner = f"""
{GREEN}
  +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ 
  + CVE-2024-6387 Vulnerability Checker                       +
  + Created by senhasegura Identity Threat Labs               +
  + Filipi Pires - Threat Researcher & Cybersecurity Advocate +
  + @senhasegura / @filipipires                               +
  +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
{ENDC}
"""
    print(banner)

def resolve_hostname(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

def get_ssh_banner(ip, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except socket.error:
        return None

def check_vulnerability(address, port, timeout):
    ip = resolve_hostname(address) if not address.replace(".", "").isdigit() else address
    if not ip:
        return ip, port, 'ERROR', " WE COULDN'T CONNECT OR RETRIEVE BANNER"

    banner = get_ssh_banner(ip, port, timeout)
    if not banner:
        return ip, port, 'ERROR', " WE COULDN'T CONNECT OR RETRIEVE BANNER"

    if "SSH-2.0-OpenSSH" in banner:
        if banner in vulnerable_versions and banner not in patched_versions:
            return ip, port, 'VULNERABLE', f"-> Running {banner}"
        else:
            return ip, port, 'SAFE', f"-> Running {banner}"
    else:
        return ip, port, 'UNKNOWN', f"-> SSH version {banner}"

def main():
    display_banner()

    parser = argparse.ArgumentParser(description="Check for CVE-2024-6387 vulnerability on a list of servers.")
    parser.add_argument("addresses", nargs='*', help="IP addresses, URLs, or CIDR ranges of the servers to check.")
    parser.add_argument("-f", "--file", help="File containing a list of IP addresses or CIDR ranges to check.")
    parser.add_argument("-p", "--ports", type=str, default="22", help="Comma-separated list of port numbers for SSH (default: 22).")
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="Connection timeout in seconds (default: 5.0).")

    args = parser.parse_args()

    results = {'SAFE': [], 'VULNERABLE': [], 'UNKNOWN': [], 'ERROR': []}
    ports = [int(p) for p in args.ports.split(',')]
    addresses = list(args.addresses)

    # Read addresses from file if provided
    if args.file:
        try:
            with open(args.file, 'r') as f:
                file_addresses = [line.strip() for line in f if line.strip()]
                addresses.extend(file_addresses)
        except IOError:
            print(f"{YELLOW}Could not read file: {args.file}{ENDC}")

    # Resolve CIDR ranges and expand them into IP addresses
    expanded_addresses = []
    for addr in addresses:
        if '/' in addr:
            try:
                network = ipaddress.ip_network(addr, strict=False)
                expanded_addresses.extend([str(ip) for ip in network.hosts()])
            except ValueError:
                print(f"{YELLOW}Invalid CIDR notation: {addr}{ENDC}")
        else:
            expanded_addresses.append(addr)

    # Check all combinations of addresses and ports
    for address in expanded_addresses:
        for port in ports:
            ip, port, status, message = check_vulnerability(address, port, args.timeout)
            results[status].append((ip, port, message))

    # Display results

    if len(results['SAFE']) > 0:
        print(f"\n{GREEN}SERVER NOT VULNERABLE: {len(results['SAFE'])}{ENDC}")
        for ip, port, msg in results['SAFE']:
            print(f"{GREEN}[SAFE] -> {ip}:{port}{msg}{ENDC}")

    if len(results['VULNERABLE']) > 0:
        print(f"\n{RED}SERVER VULNERABLE: {len(results['VULNERABLE'])}{ENDC}")
        for ip, port, msg in results['VULNERABLE']:
            print(f"{RED}[VULNERABLE] -> {ip}:{port} {msg}{ENDC}")

    if len(results['UNKNOWN']) > 0:
        print(f"\n{ORANGE}SERVER UNKNOWN SSH VERSION: {len(results['UNKNOWN'])}{ENDC}")
        for ip, port, msg in results['UNKNOWN']:
            print(f"{ORANGE}[UNKNOWN] -> {ip}:{port}{msg}{ENDC}")

    if len(results['ERROR']) > 0:
        print(f"\n{YELLOW}WE COULDN'T CONNECT OR RETRIEVE BANNER: {len(results['ERROR'])}{ENDC}")
        for ip, port, msg in results['ERROR']:
            print(f"{YELLOW}[ERROR] -> {ip}:{port}{msg}{ENDC}")

if __name__ == "__main__":
    main()

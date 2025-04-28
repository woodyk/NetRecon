#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_ssh.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-27 20:50:53
# Modified: 2025-04-27 21:06:06

import socket
import argparse
import re
import paramiko
import json

# Known vulnerable OpenSSH versions and CVEs
VULNERABLE_OPENSSH_VERSIONS = {
    "8.5": ["CVE-2024-6387 (regreSSHion)"],
    "8.6": ["CVE-2024-6387 (regreSSHion)"],
    "8.7": ["CVE-2024-6387 (regreSSHion)"],
    "8.8": ["CVE-2024-6387 (regreSSHion)"],
    "8.9": ["CVE-2024-6387 (regreSSHion)"],
    "9.0": ["CVE-2024-6387 (regreSSHion)"],
    "9.1": ["CVE-2024-6387 (regreSSHion)"],
    "9.2": ["CVE-2024-6387 (regreSSHion)"],
    "9.3": ["CVE-2024-6387 (regreSSHion)"],
    "9.4": ["CVE-2024-6387 (regreSSHion)"],
    "9.5": ["CVE-2023-48795 (Terrapin)"],
}

WEAK_KEY_TYPES = [
    "ssh-dss",            # DSA (deprecated)
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
]

def parse_banner(banner: str, findings: list):
    if banner.startswith("SSH-1."):
        findings.append("Insecure SSH protocol detected: SSHv1 (obsolete and insecure)")

    openssh_match = re.search(r"OpenSSH[_-](\d+\.\d+)", banner)
    if openssh_match:
        version = openssh_match.group(1)
        findings.append(f"Detected OpenSSH version {version}")

        if version in VULNERABLE_OPENSSH_VERSIONS:
            cves = VULNERABLE_OPENSSH_VERSIONS[version]
            findings.append(f"Known vulnerabilities for OpenSSH {version}: {', '.join(cves)}")
    else:
        findings.append("Non-standard SSH server detected.")

def enumerate_auth_methods(ip: str, port: int, findings: list, timeout=5):
    try:
        transport = paramiko.Transport((ip, port))
        transport.start_client(timeout=timeout)
        transport.auth_password(username='', password='')
    except paramiko.ssh_exception.BadAuthenticationType as e:
        supported = e.allowed_types
        if 'password' in supported:
            findings.append("Password authentication is enabled (may allow brute-force attacks).")
        else:
            findings.append(f"Supported authentication methods: {', '.join(supported)}")
    except Exception as e:
        findings.append(f"Authentication methods enumeration failed: {str(e)}")
    finally:
        try:
            transport.close()
        except:
            pass

def detect_host_key_weakness(ip: str, port: int, findings: list, timeout=5):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, port=port, username='invalid', password='invalid', timeout=timeout, allow_agent=False, look_for_keys=False)
    except paramiko.ssh_exception.SSHException:
        # Expected due to bad credentials
        pass
    except Exception as e:
        findings.append(f"Host key retrieval failed: {str(e)}")
        return

    host_keys = client.get_host_keys()
    for hostname in host_keys:
        for key_type in host_keys[hostname].keys():
            if key_type in WEAK_KEY_TYPES:
                findings.append(f"Weak host key algorithm detected: {key_type}")
            else:
                findings.append(f"Host key algorithm detected: {key_type}")

    try:
        client.close()
    except:
        pass

def scan_ssh(ip: str, port: int = 22, timeout: int = 5) -> dict:
    """Remote SSH network vulnerability scan."""
    banner = None
    findings = []

    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            banner = sock.recv(1024).decode(errors='ignore').strip()

        if banner:
            parse_banner(banner, findings)
            enumerate_auth_methods(ip, port, findings, timeout)
            detect_host_key_weakness(ip, port, findings, timeout)
        else:
            findings.append("No SSH banner retrieved.")

    except (socket.timeout, ConnectionRefusedError) as e:
        findings.append(f"Connection error: {str(e)}")
    except Exception as e:
        findings.append(f"Unexpected error: {str(e)}")

    return {
        "ip": ip,
        "port": port,
        "banner": banner,
        "findings": findings
    }

def main():
    parser = argparse.ArgumentParser(description="SSH Network Vulnerability Scanner")
    parser.add_argument("--ip", required=True, help="Target IP address or hostname")
    parser.add_argument("--port", type=int, default=22, help="Target port (default 22)")
    args = parser.parse_args()

    result = scan_ssh(ip=args.ip, port=args.port)

    # Pretty print results
    print(json.dumps(result, indent=4))

if __name__ == "__main__":
    main()


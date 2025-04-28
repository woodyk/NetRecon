#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_ssh.py
# Author: Wadih Khairallah
# Description: SSH Vulnerability Scanner for NetRecon
# Updated: 2025-04-28

import socket
import re
import paramiko
import json
import sys
from datetime import datetime, timezone

# Constants
TIMEOUT = 5
DEFAULT_PORT = 22

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

def is_ip(address):
    ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$|^([a-fA-F0-9:]+:+)+[a-fA-F0-9]+$")
    return bool(ip_pattern.match(address))

def parse_target(target):
    parts = target.strip().lower().split(':')
    host = parts[0]
    port = int(parts[1]) if len(parts) == 2 and parts[1].isdigit() else None
    return host, port

def check_port_open(host, port):
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return True
    except Exception:
        return False

def grab_banner(host, port):
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            banner = sock.recv(1024).decode(errors='ignore').strip()
            if banner:
                return {"status": "info", "detail": f"SSH Banner: {banner}"}
    except Exception as e:
        return {"status": "error", "detail": f"Failed to grab SSH banner: {str(e)}"}
    return {"status": "error", "detail": "No SSH banner retrieved."}

def check_openssh_version(banner):
    try:
        openssh_match = re.search(r"OpenSSH[_-](\d+\.\d+)", banner)
        if openssh_match:
            version = openssh_match.group(1)
            if version in VULNERABLE_OPENSSH_VERSIONS:
                cves = VULNERABLE_OPENSSH_VERSIONS[version]
                return {"status": "fail", "detail": f"OpenSSH {version} vulnerable: {', '.join(cves)}"}
            else:
                return {"status": "pass", "detail": f"OpenSSH {version} detected, no known critical vulnerabilities."}
        return {"status": "info", "detail": "Non-standard SSH server banner, OpenSSH version not detected."}
    except Exception as e:
        return {"status": "error", "detail": f"OpenSSH version check failed: {str(e)}"}

def check_authentication_methods(host, port):
    try:
        transport = paramiko.Transport((host, port))
        transport.start_client(timeout=TIMEOUT)
        transport.auth_password(username='', password='')
    except paramiko.ssh_exception.BadAuthenticationType as e:
        supported = e.allowed_types
        if 'password' in supported:
            return {"status": "fail", "detail": "Password authentication is enabled (may allow brute-force attacks)."}
        else:
            return {"status": "pass", "detail": f"Authentication methods: {', '.join(supported)}"}
    except Exception as e:
        return {"status": "error", "detail": f"Authentication methods enumeration failed: {str(e)}"}
    finally:
        try:
            transport.close()
        except:
            pass

def check_host_key_strength(host, port):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username='invalid', password='invalid', timeout=TIMEOUT, allow_agent=False, look_for_keys=False)
    except paramiko.ssh_exception.SSHException:
        pass
    except Exception as e:
        return {"status": "error", "detail": f"Host key retrieval failed: {str(e)}"}

    try:
        host_keys = client.get_host_keys()
        for hostname in host_keys:
            for key_type in host_keys[hostname].keys():
                if key_type in WEAK_KEY_TYPES:
                    return {"status": "fail", "detail": f"Weak host key algorithm detected: {key_type}"}
                else:
                    return {"status": "pass", "detail": f"Host key algorithm used: {key_type}"}
        return {"status": "error", "detail": "No host key information retrieved."}
    finally:
        try:
            client.close()
        except:
            pass

def collect(target: str):
    host, port = parse_target(target)
    port = port if port else DEFAULT_PORT
    open_ports = []
    vulnerabilities = {}
    summary = []

    if check_port_open(host, port):
        open_ports.append(port)
    else:
        return {
            "target": host,
            "port": [port],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "open": False,
            "vulnerabilities": {},
            "summary": ["SSH port not reachable."]
        }

    banner_info = grab_banner(host, port)
    vulnerabilities["ssh_banner"] = banner_info

    if banner_info["status"] in ["info", "pass"]:
        banner_text = banner_info["detail"]
        vulnerabilities["openssh_version_check"] = check_openssh_version(banner_text)
    else:
        vulnerabilities["openssh_version_check"] = {"status": "error", "detail": "OpenSSH version could not be determined."}

    vulnerabilities["auth_methods_check"] = check_authentication_methods(host, port)
    vulnerabilities["host_key_strength_check"] = check_host_key_strength(host, port)

    return {
        "target": host,
        "port": open_ports,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "open": True,
        "vulnerabilities": vulnerabilities,
        "summary": summary
    }

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 check_ssh.py <target> or <target:port>")
        sys.exit(1)

    target = sys.argv[1]
    result = collect(target)

    print(json.dumps(result, indent=4))


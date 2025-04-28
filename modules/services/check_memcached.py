#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_memcached.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-27 22:07:36

import argparse
import json
import socket

# Constants
DEFAULT_PORT = 11211
TIMEOUT = 3


def send_memcached_command(sock, command: str) -> str:
    try:
        sock.sendall((command + "\r\n").encode())
        response = sock.recv(4096)
        return response.decode(errors="ignore")
    except Exception:
        return ""


def check_open_access(target, port, findings):
    try:
        sock = socket.create_connection((target, port), timeout=TIMEOUT)
        sock.close()
        findings.append("Memcached server accepted TCP connection (potentially open access).")
    except Exception as e:
        findings.append(f"Open access check failed: {str(e)}")


def check_version_info(target, port, findings):
    try:
        sock = socket.create_connection((target, port), timeout=TIMEOUT)
        response = send_memcached_command(sock, "version")
        if response.startswith("VERSION"):
            version = response.strip().split(" ")[1]
            findings.append(f"Memcached version detected: {version}.")
        else:
            findings.append("Could not determine Memcached version.")
        sock.close()
    except Exception as e:
        findings.append(f"Version info check failed: {str(e)}")


def check_stats_access(target, port, findings):
    try:
        sock = socket.create_connection((target, port), timeout=TIMEOUT)
        response = send_memcached_command(sock, "stats")
        if "STAT" in response:
            findings.append("Memcached server statistics accessible without authentication (critical).")
        else:
            findings.append("Server statistics not accessible or protected.")
        sock.close()
    except Exception as e:
        findings.append(f"Stats access check failed: {str(e)}")


def check_amplification_risk(target, port, findings):
    try:
        sock = socket.create_connection((target, port), timeout=TIMEOUT)
        response = send_memcached_command(sock, "stats items")
        if "STAT items" in response:
            findings.append("Memcached server vulnerable to potential amplification (stats items exposed).")
        else:
            findings.append("No obvious amplification risk detected.")
        sock.close()
    except Exception as e:
        findings.append(f"Amplification risk check failed: {str(e)}")


def scan_memcached(target: str, port: int = DEFAULT_PORT) -> dict:
    """Remote Memcached vulnerability scan."""
    findings = []

    check_open_access(target, port, findings)
    check_version_info(target, port, findings)
    check_stats_access(target, port, findings)
    check_amplification_risk(target, port, findings)

    return {
        "ip": target,
        "port": port,
        "findings": findings
    }


def main():
    parser = argparse.ArgumentParser(description="Memcached Server Vulnerability Scanner")
    parser.add_argument("--ip", required=True, help="Target Memcached server IP address")
    parser.add_argument("--port", type=int, default=11211, help="Target Memcached server port (default 11211)")
    args = parser.parse_args()

    result = scan_memcached(target=args.ip, port=args.port)

    print(json.dumps(result, indent=4))


if __name__ == "__main__":
    main()


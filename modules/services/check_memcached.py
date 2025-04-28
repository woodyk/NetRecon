#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_memcached.py
# Author: Wadih Khairallah
# Description: Memcached Vulnerability Scanner for NetRecon
# Updated: 2025-04-28

import json
import socket
import sys
import re
from datetime import datetime, timezone

# Constants
DEFAULT_PORT = 11211
TIMEOUT = 3

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
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        sock.close()
        return True
    except Exception:
        return False

def send_memcached_command(sock, command: str) -> str:
    try:
        sock.sendall((command + "\r\n").encode())
        response = sock.recv(4096)
        return response.decode(errors="ignore")
    except Exception:
        return ""

def check_open_access(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        sock.close()
        return {"status": "fail", "detail": "Memcached server accepted TCP connection (potentially open access)."}
    except Exception as e:
        return {"status": "error", "detail": f"Open access check failed: {str(e)}"}

def check_version_info(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        response = send_memcached_command(sock, "version")
        sock.close()
        if response.startswith("VERSION"):
            version = response.strip().split(" ")[1]
            return {"status": "info", "detail": f"Memcached version detected: {version}."}
        return {"status": "fail", "detail": "Could not determine Memcached version."}
    except Exception as e:
        return {"status": "error", "detail": f"Version info check failed: {str(e)}"}

def check_stats_access(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        response = send_memcached_command(sock, "stats")
        sock.close()
        if "STAT" in response:
            return {"status": "fail", "detail": "Memcached server statistics accessible without authentication (critical)."}
        return {"status": "pass", "detail": "Server statistics not accessible or protected."}
    except Exception as e:
        return {"status": "error", "detail": f"Stats access check failed: {str(e)}"}

def check_amplification_risk(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        response = send_memcached_command(sock, "stats items")
        sock.close()
        if "STAT items" in response:
            return {"status": "fail", "detail": "Memcached server vulnerable to amplification (stats items exposed)."}
        return {"status": "pass", "detail": "No obvious amplification risk detected."}
    except Exception as e:
        return {"status": "error", "detail": f"Amplification risk check failed: {str(e)}"}

def collect(target: str):
    host, port = parse_target(target)
    port = port if port else DEFAULT_PORT
    vulnerabilities = {}
    summary = []

    if not check_port_open(host, port):
        return {
            "target": host,
            "port": [port],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "open": False,
            "vulnerabilities": {},
            "summary": ["Memcached port not reachable."]
        }

    vulnerabilities["memcached_open_access"] = check_open_access(host, port)
    vulnerabilities["memcached_version_info"] = check_version_info(host, port)
    vulnerabilities["memcached_stats_access"] = check_stats_access(host, port)
    vulnerabilities["memcached_amplification_risk"] = check_amplification_risk(host, port)

    return {
        "target": host,
        "port": [port],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "open": True,
        "vulnerabilities": vulnerabilities,
        "summary": summary
    }

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 check_memcached.py <target> or <target:port>")
        sys.exit(1)

    target = sys.argv[1]
    result = collect(target)

    print(json.dumps(result, indent=4))


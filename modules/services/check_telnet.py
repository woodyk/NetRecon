#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_telnet.py
# Author: Wadih Khairallah
# Description: Telnet Vulnerability Scanner for NetRecon
# Updated: 2025-04-28

import socket
import json
import time
import re
import sys
from datetime import datetime, timezone

TIMEOUT = 5
DEFAULT_PORT = 23

COMMON_DEFAULT_BANNERS = [
    "login:", "username:", "password:"
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

def grab_telnet_banner(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        banner = sock.recv(1024).decode(errors='ignore').strip()
        sock.close()
        if banner:
            if any(keyword in banner.lower() for keyword in ["linux", "unix", "cisco", "windows", "openbsd", "router", "switch"]):
                return {"status": "fail", "detail": f"Sensitive system info exposed in Telnet banner: {banner}"}
            else:
                return {"status": "info", "detail": f"Telnet banner: {banner}"}
    except Exception as e:
        return {"status": "error", "detail": f"Failed to grab Telnet banner: {str(e)}"}
    return {"status": "error", "detail": "No Telnet banner retrieved."}

def detect_plaintext_auth(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        sock.settimeout(TIMEOUT)
        time.sleep(1)
        response = sock.recv(4096).decode(errors='ignore')
        sock.close()
        if any(phrase.lower() in response.lower() for phrase in COMMON_DEFAULT_BANNERS):
            return {"status": "fail", "detail": "Telnet server prompts for credentials over plaintext (insecure)."}
        else:
            return {"status": "pass", "detail": "No immediate plaintext authentication prompts detected."}
    except Exception as e:
        return {"status": "error", "detail": f"Plaintext authentication detection failed: {str(e)}"}

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
            "summary": ["Telnet port not reachable."]
        }

    vulnerabilities["telnet_banner_check"] = grab_telnet_banner(host, port)
    vulnerabilities["plaintext_auth_check"] = detect_plaintext_auth(host, port)

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
        print("Usage: python3 check_telnet.py <target> or <target:port>")
        sys.exit(1)

    target = sys.argv[1]
    result = collect(target)

    print(json.dumps(result, indent=4))


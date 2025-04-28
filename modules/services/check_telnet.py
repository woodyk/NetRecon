#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_telnet.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-27 21:30:12
# Modified: 2025-04-27 21:34:26

import argparse
import socket
import json
import time

TIMEOUT = 5
TELNET_PORT = 23

COMMON_DEFAULT_BANNERS = [
    "login:", "Username:", "Password:"
]

def grab_telnet_banner(host, findings):
    try:
        sock = socket.create_connection((host, TELNET_PORT), timeout=TIMEOUT)
        banner = sock.recv(1024).decode(errors='ignore').strip()
        sock.close()
        if banner:
            findings.append(f"Telnet banner: {banner}")
            # Detect if it leaks system info
            if any(keyword in banner.lower() for keyword in ["linux", "unix", "cisco", "windows", "openbsd", "router", "switch"]):
                findings.append(f"Sensitive system info exposed in Telnet banner: {banner}")
        else:
            findings.append("Telnet server responded but no banner text was retrieved.")
    except Exception:
        findings.append("Failed to retrieve Telnet banner.")

def detect_plaintext_auth(host, findings):
    try:
        sock = socket.create_connection((host, TELNET_PORT), timeout=TIMEOUT)
        sock.settimeout(TIMEOUT)
        time.sleep(1)
        response = sock.recv(4096).decode(errors='ignore')
        sock.close()
        if any(phrase.lower() in response.lower() for phrase in COMMON_DEFAULT_BANNERS):
            findings.append("Telnet server prompts for credentials over plaintext (insecure).")
        else:
            findings.append("No immediate plaintext authentication prompts detected.")
    except Exception:
        findings.append("Plaintext authentication detection failed.")

def scan_telnet(target: str) -> dict:
    findings = []

    parsed_target = target.replace('http://', '').replace('https://', '').split('/')[0]

    try:
        sock = socket.create_connection((parsed_target, TELNET_PORT), timeout=TIMEOUT)
        findings.append(f"Telnet port {TELNET_PORT}/TCP is open.")
        sock.close()
    except Exception:
        findings.append(f"Telnet port {TELNET_PORT}/TCP is closed or filtered.")
        return {"domain": parsed_target, "findings": findings}

    # If port open, proceed with deeper checks
    grab_telnet_banner(parsed_target, findings)
    detect_plaintext_auth(parsed_target, findings)

    return {
        "domain": parsed_target,
        "findings": findings
    }

def main():
    parser = argparse.ArgumentParser(description="Telnet Service Vulnerability Scanner")
    parser.add_argument("--target", required=True, help="Target domain or IP")
    args = parser.parse_args()

    result = scan_telnet(args.target)

    print(json.dumps(result, indent=4))

if __name__ == "__main__":
    main()


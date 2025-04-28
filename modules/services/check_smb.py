#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_smb.py
# Author: Wadih Khairallah
# Description: SMB Vulnerability Scanner for NetRecon
# Updated: 2025-04-28

import json
import socket
import struct
import sys
import re
from datetime import datetime, timezone

# Constants
DEFAULT_SMB_PORT = 445
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

def build_negotiate_request():
    dialects = [
        b"\x02NT LM 0.12\x00",    # SMBv1
        b"\x02SMB 2.002\x00",     # SMB2
        b"\x02SMB 2.???\x00",     # SMB2 wildcard
        b"\x02SMB 3.0\x00",       # SMB3.0
        b"\x02SMB 3.02\x00",      # SMB3.02
        b"\x02SMB 3.1.1\x00"      # SMB3.1.1
    ]
    payload = b"".join(dialects)
    payload_len = len(payload) + 36

    header = (
        b"\x00" +
        struct.pack(">I", payload_len)[1:] +
        b"\xffSMB" +
        b"\x72" +
        b"\x00" +
        b"\x00\x00" +
        b"\x00\x00" +
        b"\x00\x00\x00\x00" +
        b"\x00\x00" +
        b"\x00\x00\x00\x00\x00\x00\x00\x00" +
        b"\x00\x00"
    )
    body = (
        b"\x00" +
        struct.pack("<H", len(payload)) +
        payload
    )
    return header + body

def send_negotiate_packet(host, port):
    packet = build_negotiate_request()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        s.connect((host, port))
        s.sendall(packet)
        response = s.recv(4096)
    except Exception:
        response = None
    finally:
        s.close()
    return response

def detect_smb_versions(response):
    try:
        if not response:
            return {"status": "error", "detail": "No SMB response received for version detection."}
        versions = []
        if b"NT LM 0.12" in response:
            versions.append("SMBv1")
        if b"SMB 2.002" in response:
            versions.append("SMBv2")
        if b"SMB 2.???" in response:
            versions.append("SMB2 wildcard")
        if b"SMB 3.0" in response:
            versions.append("SMBv3.0")
        if b"SMB 3.02" in response:
            versions.append("SMBv3.02")
        if b"SMB 3.1.1" in response:
            versions.append("SMBv3.1.1")
        if versions:
            return {"status": "info", "detail": "Supported SMB versions: " + ", ".join(versions)}
        return {"status": "fail", "detail": "Could not determine supported SMB versions."}
    except Exception as e:
        return {"status": "error", "detail": f"Version detection failed: {str(e)}"}

def check_null_session(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((host, port))
        s.sendall(b"\x00")
        data = s.recv(1024)
        s.close()
        if data:
            return {"status": "fail", "detail": "Null session (anonymous login) possible."}
        return {"status": "pass", "detail": "Null session not permitted."}
    except Exception:
        return {"status": "pass", "detail": "Null session not permitted."}

def check_signing_required(response):
    try:
        if not response:
            return {"status": "error", "detail": "No SMB response for signing verification."}
        if b"\x08\x00" in response or b"\x08\x01" in response:
            return {"status": "pass", "detail": "SMB signing required (good)."}
        return {"status": "fail", "detail": "SMB signing NOT required (vulnerable to MiTM)."}
    except Exception as e:
        return {"status": "error", "detail": f"Signing check failed: {str(e)}"}

def check_encryption_support(response):
    try:
        if not response:
            return {"status": "error", "detail": "No SMB response for encryption check."}
        if b"SMB 3.0" in response or b"SMB 3.1.1" in response:
            return {"status": "pass", "detail": "SMB encryption capability detected."}
        return {"status": "fail", "detail": "SMB encryption not supported (pre-3.0 dialects only)."}
    except Exception as e:
        return {"status": "error", "detail": f"Encryption support check failed: {str(e)}"}

def check_os_hostname_leak(response):
    try:
        if not response:
            return {"status": "error", "detail": "No SMB response for OS/hostname fingerprinting."}
        decoded = response.decode(errors="ignore")
        for line in decoded.split("\x00"):
            if "Windows" in line or "Samba" in line:
                return {"status": "info", "detail": f"OS/Software detected: {line.strip()}"}
        return {"status": "pass", "detail": "No OS or software info leaked."}
    except Exception as e:
        return {"status": "error", "detail": f"OS hostname leak check failed: {str(e)}"}

def collect(target: str):
    host, port = parse_target(target)
    port = port if port else DEFAULT_SMB_PORT
    vulnerabilities = {}
    summary = []

    if not check_port_open(host, port):
        return {
            "target": host,
            "port": [port],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "open": False,
            "vulnerabilities": {},
            "summary": ["SMB port not reachable."]
        }

    response = send_negotiate_packet(host, port)

    vulnerabilities["smb_version_check"] = detect_smb_versions(response)
    vulnerabilities["null_session_check"] = check_null_session(host, port)
    vulnerabilities["smb_signing_check"] = check_signing_required(response)
    vulnerabilities["smb_encryption_check"] = check_encryption_support(response)
    vulnerabilities["os_hostname_leak_check"] = check_os_hostname_leak(response)

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
        print("Usage: python3 check_smb.py <target> or <target:port>")
        sys.exit(1)

    target = sys.argv[1]
    result = collect(target)

    print(json.dumps(result, indent=4))


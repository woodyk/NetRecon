#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_smb.py
# Author: Wadih Khairallah
# Description: Comprehensive SMB protocol vulnerability scanner
# Created: 2025-04-28

import argparse
import json
import socket
import struct

# Constants
SMB_PORT = 445
TIMEOUT = 3

def build_negotiate_request():
    """Craft minimal SMB negotiate request."""
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
        struct.pack(">I", payload_len)[1:] +  # 3 bytes for length
        b"\xffSMB" +
        b"\x72" +      # NEGOTIATE command
        b"\x00" +      # Error class
        b"\x00\x00" +  # Reserved
        b"\x00\x00" +  # Flags
        b"\x00\x00\x00\x00" +  # Flags2
        b"\x00\x00" +  # PID High
        b"\x00\x00\x00\x00\x00\x00\x00\x00" +  # Signature
        b"\x00\x00" +  # Reserved
        b"\x00\x00"    # Tree ID
    )
    body = (
        b"\x00" +      # Word count
        struct.pack("<H", len(payload)) +  # Byte count
        payload
    )
    return header + body

def send_negotiate_packet(ip, timeout=TIMEOUT):
    """Send SMB negotiate request and return raw response."""
    packet = build_negotiate_request()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, SMB_PORT))
        s.sendall(packet)
        response = s.recv(4096)
    except Exception:
        response = None
    finally:
        s.close()
    return response

def check_smb_versions(response, findings):
    """Detect supported SMB protocol versions."""
    if not response:
        findings.append("No response received for version detection.")
        return

    versions = []
    if b"NT LM 0.12" in response:
        versions.append("SMBv1 (deprecated and dangerous)")
    if b"SMB 2.002" in response:
        versions.append("SMBv2")
    if b"SMB 2.??? " in response:
        versions.append("SMB2 wildcard support")
    if b"SMB 3.0" in response:
        versions.append("SMBv3.0")
    if b"SMB 3.02" in response:
        versions.append("SMBv3.02")
    if b"SMB 3.1.1" in response:
        versions.append("SMBv3.1.1")

    if versions:
        findings.append(f"Supported SMB versions: {', '.join(versions)}.")
    else:
        findings.append("Could not determine supported SMB versions.")

def check_null_session(ip, findings):
    """Test if null session authentication is permitted."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip, SMB_PORT))
        s.sendall(b"\x00")
        data = s.recv(1024)
        if data:
            findings.append("Null session (anonymous login) possible.")
        else:
            findings.append("Null session attempt refused (good).")
    except Exception:
        findings.append("Null session attempt failed (good).")
    finally:
        s.close()

def check_signing_enforcement(response, findings):
    """Check if SMB signing is required."""
    if not response:
        findings.append("Cannot verify signing without negotiation response.")
        return

    # Simple heuristic: check if SIGNING_REQUIRED flag (0x08) is set
    if b"\x08\x00" in response or b"\x08\x01" in response:
        findings.append("SMB signing appears required (good).")
    else:
        findings.append("SMB signing NOT required (vulnerable to MiTM).")

def check_encryption_support(response, findings):
    """Check if SMB encryption is supported."""
    if not response:
        findings.append("Cannot determine encryption support without response.")
        return

    if b"SMB 3.0" in response or b"SMB 3.1.1" in response:
        findings.append("SMB encryption capability detected (SMBv3+).")
    else:
        findings.append("SMB encryption not supported (pre-3.0 dialects only).")

def check_os_hostname_leak(response, findings):
    """Attempt to fingerprint OS version or hostname."""
    if not response:
        findings.append("Cannot fingerprint OS without response.")
        return

    decoded = response.decode(errors="ignore")
    for line in decoded.split("\x00"):
        if "Windows" in line or "Samba" in line:
            findings.append(f"OS or software detected: {line.strip()}")

def scan_smb(ip: str, timeout: int = TIMEOUT) -> dict:
    """Remote SMB vulnerability scan."""
    findings = []
    response = send_negotiate_packet(ip, timeout=timeout)

    check_smb_versions(response, findings)
    check_null_session(ip, findings)
    check_signing_enforcement(response, findings)
    check_encryption_support(response, findings)
    check_os_hostname_leak(response, findings)

    return {
        "ip": ip,
        "findings": findings
    }

def main():
    parser = argparse.ArgumentParser(description="Comprehensive SMB Vulnerability Scanner")
    parser.add_argument("--ip", required=True, help="Target SMB server IP address")
    args = parser.parse_args()

    result = scan_smb(ip=args.ip)

    print(json.dumps(result, indent=4))

if __name__ == "__main__":
    main()


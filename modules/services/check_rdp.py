#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_rdp.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-27 21:32:30
# Modified: 2025-04-27 21:34:19

import argparse
import socket
import ssl
import struct
import json
import time

TIMEOUT = 5
RDP_PORT = 3389

# TLS/SSL weak cipher signatures (similar to HTTPS checks)
WEAK_CIPHERS = [
    "RC4", "3DES", "NULL", "EXPORT", "DES", "MD5", "PSK", "SRP", "DSS"
]
DEPRECATED_TLS_VERSIONS = ["TLSv1", "TLSv1.1"]

def check_rdp_port(host, findings):
    try:
        sock = socket.create_connection((host, RDP_PORT), timeout=TIMEOUT)
        findings.append(f"RDP port {RDP_PORT}/TCP is open.")
        sock.close()
    except Exception:
        findings.append(f"RDP port {RDP_PORT}/TCP is closed or filtered.")

def grab_rdp_banner(host, findings):
    try:
        sock = socket.create_connection((host, RDP_PORT), timeout=TIMEOUT)
        sock.settimeout(TIMEOUT)
        # Send X.224 Connection Request
        pkt = b'\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x00\x00\x00\x00\x00\x00\x00'
        sock.sendall(pkt)
        data = sock.recv(1024)
        sock.close()
        if data:
            findings.append("Received RDP handshake response (X.224).")
        else:
            findings.append("No handshake response from RDP server.")
    except Exception:
        findings.append("Failed to grab RDP banner.")

def detect_rdp_protocol_version(host, findings):
    try:
        sock = socket.create_connection((host, RDP_PORT), timeout=TIMEOUT)
        sock.settimeout(TIMEOUT)
        # Send RDP Negotiation Request
        pkt = b'\x03\x00\x00\x1d\x02\xf0\x80\x7f\x65\x82\x01\x0d\x00\x08\x03\x00\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00'
        sock.sendall(pkt)
        data = sock.recv(1024)
        sock.close()
        if data and b"\x03\x00" in data:
            if b"\x0d\x02" in data:
                findings.append("Server requires Network Level Authentication (NLA).")
            else:
                findings.append("Server does NOT require NLA (potentially insecure).")
        else:
            findings.append("Could not determine RDP protocol version.")
    except Exception:
        findings.append("RDP protocol version detection failed.")

def check_tls_details(host, findings):
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(), server_hostname=host)
        conn.settimeout(TIMEOUT)
        conn.connect((host, RDP_PORT))
        cert = conn.getpeercert()

        ssl_version = conn.version()
        cipher = conn.cipher()

        if cert:
            expire_ts = ssl.cert_time_to_seconds(cert['notAfter'])
            import time
            if expire_ts < time.time():
                findings.append(f"Expired SSL certificate detected on RDP (port {RDP_PORT}).")
            issuer = dict(x[0] for x in cert['issuer'])
            if issuer.get('organizationName', '').lower() == "self-signed":
                findings.append("Self-signed SSL certificate detected on RDP server.")

        if ssl_version in DEPRECATED_TLS_VERSIONS:
            findings.append(f"Insecure TLS version {ssl_version} used on RDP.")

        if cipher and any(weak in cipher[0] for weak in WEAK_CIPHERS):
            findings.append(f"Weak SSL cipher used by RDP server: {cipher[0]}")

        findings.append(f"SSL/TLS in use: {ssl_version} with cipher {cipher[0]}")
        conn.close()
    except Exception as e:
        findings.append(f"TLS handshake with RDP server failed: {str(e)}")

def credssp_behavior_probe(host, findings):
    try:
        sock = socket.create_connection((host, RDP_PORT), timeout=TIMEOUT)
        sock.settimeout(TIMEOUT)
        pkt = b'\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x00\x00\x00\x00\x00\x00\x00'
        sock.sendall(pkt)
        data = sock.recv(1024)
        if b'\x02\xf0\x80' in data:
            findings.append("RDP server may be vulnerable to CredSSP-related downgrade attacks (CVE-2018-0886) if not patched.")
        sock.close()
    except Exception:
        findings.append("CredSSP behavior probe failed.")

def scan_rdp(target: str) -> dict:
    findings = []

    parsed_target = target.replace('http://', '').replace('https://', '').split('/')[0]

    check_rdp_port(parsed_target, findings)
    grab_rdp_banner(parsed_target, findings)
    detect_rdp_protocol_version(parsed_target, findings)
    check_tls_details(parsed_target, findings)
    credssp_behavior_probe(parsed_target, findings)

    return {
        "domain": parsed_target,
        "findings": findings
    }

def main():
    parser = argparse.ArgumentParser(description="RDP Service Vulnerability Scanner")
    parser.add_argument("--target", required=True, help="Target domain or IP")
    args = parser.parse_args()

    result = scan_rdp(args.target)

    print(json.dumps(result, indent=4))

if __name__ == "__main__":
    main()


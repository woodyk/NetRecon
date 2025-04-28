#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_rdp.py
# Author: Wadih Khairallah
# Description: RDP Vulnerability Scanner for NetRecon
# Updated: 2025-04-28

import json
import socket
import ssl
import struct
import sys
import re
import time
from datetime import datetime, timezone

TIMEOUT = 5
DEFAULT_RDP_PORT = 3389

WEAK_CIPHERS = ["RC4", "3DES", "NULL", "EXPORT", "DES", "MD5", "PSK", "SRP", "DSS"]
DEPRECATED_TLS_VERSIONS = ["TLSv1", "TLSv1.1"]

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

def grab_rdp_banner(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        pkt = b'\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x00\x00\x00\x00\x00\x00\x00'
        sock.sendall(pkt)
        data = sock.recv(1024)
        sock.close()
        if data:
            return {"status": "info", "detail": "Received RDP handshake response (X.224)."}
        return {"status": "fail", "detail": "No handshake response from RDP server."}
    except Exception as e:
        return {"status": "error", "detail": f"Failed to grab RDP banner: {str(e)}"}

def detect_rdp_protocol_version(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        pkt = b'\x03\x00\x00\x1d\x02\xf0\x80\x7f\x65\x82\x01\x0d\x00\x08\x03\x00\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00'
        sock.sendall(pkt)
        data = sock.recv(1024)
        sock.close()
        if data and b"\x03\x00" in data:
            if b"\x0d\x02" in data:
                return {"status": "pass", "detail": "Server requires Network Level Authentication (NLA)."}
            else:
                return {"status": "fail", "detail": "Server does NOT require NLA (potentially insecure)."}
        return {"status": "fail", "detail": "Could not determine RDP protocol version."}
    except Exception as e:
        return {"status": "error", "detail": f"RDP protocol version detection failed: {str(e)}"}

def check_tls_details(host, port):
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(), server_hostname=host)
        conn.settimeout(TIMEOUT)
        conn.connect((host, port))
        cert = conn.getpeercert()
        ssl_version = conn.version()
        cipher = conn.cipher()
        conn.close()

        issues = []

        if cert:
            expire_ts = ssl.cert_time_to_seconds(cert['notAfter'])
            if expire_ts < time.time():
                issues.append("Expired SSL certificate detected.")
        
        if ssl_version in DEPRECATED_TLS_VERSIONS:
            issues.append(f"Insecure TLS version: {ssl_version}")

        if cipher and any(weak in cipher[0] for weak in WEAK_CIPHERS):
            issues.append(f"Weak cipher detected: {cipher[0]}")

        if issues:
            return {"status": "fail", "detail": "; ".join(issues)}
        return {"status": "pass", "detail": f"SSL/TLS version {ssl_version} with cipher {cipher[0]}"}
    except Exception as e:
        return {"status": "error", "detail": f"TLS handshake failed: {str(e)}"}

def credssp_behavior_probe(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        pkt = b'\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x00\x00\x00\x00\x00\x00\x00'
        sock.sendall(pkt)
        data = sock.recv(1024)
        sock.close()
        if data and b'\x02\xf0\x80' in data:
            return {"status": "fail", "detail": "Possible CredSSP downgrade vulnerability (CVE-2018-0886) if unpatched."}
        return {"status": "pass", "detail": "No CredSSP downgrade behavior detected."}
    except Exception as e:
        return {"status": "error", "detail": f"CredSSP behavior probe failed: {str(e)}"}

def collect(target: str):
    host, port = parse_target(target)
    port = port if port else DEFAULT_RDP_PORT
    vulnerabilities = {}
    summary = []

    if not check_port_open(host, port):
        return {
            "target": host,
            "port": [port],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "open": False,
            "vulnerabilities": {},
            "summary": ["RDP port not reachable."]
        }

    vulnerabilities["rdp_banner"] = grab_rdp_banner(host, port)
    vulnerabilities["rdp_protocol_version"] = detect_rdp_protocol_version(host, port)
    vulnerabilities["rdp_tls_details"] = check_tls_details(host, port)
    vulnerabilities["rdp_credssp_behavior"] = credssp_behavior_probe(host, port)

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
        print("Usage: python3 check_rdp.py <target> or <target:port>")
        sys.exit(1)

    target = sys.argv[1]
    result = collect(target)

    print(json.dumps(result, indent=4))


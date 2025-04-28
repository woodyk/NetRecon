#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_mssql.py
# Author: Wadih Khairallah
# Description: MSSQL Vulnerability Scanner for NetRecon
# Updated: 2025-04-28

import json
import socket
import ssl
import struct
import sys
import re
import pytds
import time
from datetime import datetime, timezone

TIMEOUT = 5
DEFAULT_MSSQL_PORT = 1433
SQL_BROWSER_PORT = 1434  # UDP

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

def check_default_sa_login(host, port):
    try:
        conn = pytds.connect(server=host, database='', user='sa', password='', port=port, timeout=TIMEOUT)
        conn.close()
        return {"status": "fail", "detail": "Default 'sa' user login with no password is allowed (critical!)."}
    except pytds.LoginError as e:
        if "Login failed" in str(e):
            return {"status": "pass", "detail": "MSSQL server denied 'sa' login with no password (expected)."}
        return {"status": "error", "detail": f"MSSQL login error: {str(e)}"}
    except Exception as e:
        return {"status": "error", "detail": f"Default credential check failed: {str(e)}"}

def grab_mssql_banner(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        sock.settimeout(TIMEOUT)
        prelogin_pkt = b'\x12\x01\x00\x34' + b'\x00' * 48
        sock.sendall(prelogin_pkt)
        data = sock.recv(1024)
        sock.close()
        if data:
            return {"status": "info", "detail": "MSSQL server responded to pre-login handshake."}
        return {"status": "fail", "detail": "No MSSQL server response to pre-login handshake."}
    except Exception as e:
        return {"status": "error", "detail": f"Failed to grab MSSQL banner: {str(e)}"}

def check_ssl_support(host, port):
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
        return {"status": "pass", "detail": f"MSSQL SSL/TLS version {ssl_version} with cipher {cipher[0]}"}
    except Exception:
        return {"status": "error", "detail": "MSSQL SSL/TLS handshake not possible (likely using plain TCP)."}

def check_sql_browser_udp(host):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT)
        sock.sendto(b'\x03', (host, SQL_BROWSER_PORT))
        data, _ = sock.recvfrom(4096)
        sock.close()
        if data:
            return {"status": "fail", "detail": "SQL Browser UDP service leaking server instance information."}
        return {"status": "pass", "detail": "SQL Browser service present but no instance information leaked."}
    except Exception:
        return {"status": "pass", "detail": "SQL Browser UDP port 1434 closed or filtered."}

def collect(target: str):
    host, port = parse_target(target)
    port = port if port else DEFAULT_MSSQL_PORT
    vulnerabilities = {}
    summary = []

    if not check_port_open(host, port):
        return {
            "target": host,
            "port": [port],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "open": False,
            "vulnerabilities": {},
            "summary": ["MSSQL port not reachable."]
        }

    vulnerabilities["mssql_banner"] = grab_mssql_banner(host, port)
    vulnerabilities["mssql_default_sa_login"] = check_default_sa_login(host, port)
    vulnerabilities["mssql_ssl_support"] = check_ssl_support(host, port)
    vulnerabilities["mssql_sql_browser_udp"] = check_sql_browser_udp(host)

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
        print("Usage: python3 check_mssql.py <target> or <target:port>")
        sys.exit(1)

    target = sys.argv[1]
    result = collect(target)

    print(json.dumps(result, indent=4))


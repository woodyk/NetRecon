#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_mssql.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-27 21:37:43

import argparse
import socket
import ssl
import json
import struct
import pymssql

TIMEOUT = 5
MSSQL_PORT = 1433
SQL_BROWSER_PORT = 1434  # UDP

WEAK_CIPHERS = [
    "RC4", "3DES", "NULL", "EXPORT", "DES", "MD5", "PSK", "SRP", "DSS"
]
DEPRECATED_TLS_VERSIONS = ["TLSv1", "TLSv1.1"]

def check_mssql_port(host, findings):
    try:
        sock = socket.create_connection((host, MSSQL_PORT), timeout=TIMEOUT)
        findings.append(f"MSSQL port {MSSQL_PORT}/TCP is open.")
        sock.close()
    except Exception:
        findings.append(f"MSSQL port {MSSQL_PORT}/TCP is closed or filtered.")

def grab_mssql_banner(host, findings):
    try:
        sock = socket.create_connection((host, MSSQL_PORT), timeout=TIMEOUT)
        sock.settimeout(TIMEOUT)
        # Pre-login packet
        prelogin_pkt = b'\x12\x01\x00\x34\x00\x00\x00\x00' \
                       b'\x00\x00\x00\x00\x00\x00\x00\x00' \
                       b'\x00\x00\x00\x00\x00\x00\x00\x00' \
                       b'\x00\x00\x00\x00\x00\x00\x00\x00' \
                       b'\x00\x00\x00\x00\x00\x00\x00\x00' \
                       b'\x00\x00\x00\x00\x00\x00\x00\x00'
        sock.sendall(prelogin_pkt)
        data = sock.recv(1024)
        sock.close()
        if data:
            findings.append(f"MSSQL server responded to pre-login handshake (possible version fingerprinting).")
        else:
            findings.append("No response from MSSQL server to pre-login handshake.")
    except Exception:
        findings.append("Failed to grab MSSQL banner.")

def check_default_sa_login(host, findings):
    try:
        conn = pymssql.connect(server=host, user='sa', password='', login_timeout=TIMEOUT)
        findings.append("Default 'sa' user login with no password is allowed! Critical misconfiguration.")
        conn.close()
    except pymssql.InterfaceError:
        findings.append("MSSQL server refused unauthenticated login attempt (expected).")
    except pymssql.DatabaseError as e:
        if "Login failed" in str(e):
            findings.append("MSSQL server denied 'sa' login with no password (expected).")
        else:
            findings.append(f"MSSQL login error: {str(e)}")
    except Exception as e:
        findings.append(f"Default credential check failed: {str(e)}")

def check_ssl_support(host, findings):
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(), server_hostname=host)
        conn.settimeout(TIMEOUT)
        conn.connect((host, MSSQL_PORT))
        cert = conn.getpeercert()

        ssl_version = conn.version()
        cipher = conn.cipher()

        if cert:
            expire_ts = ssl.cert_time_to_seconds(cert['notAfter'])
            import time
            if expire_ts < time.time():
                findings.append(f"Expired SSL certificate detected on MSSQL port {MSSQL_PORT}.")
            issuer = dict(x[0] for x in cert['issuer'])
            if issuer.get('organizationName', '').lower() == "self-signed":
                findings.append("Self-signed SSL certificate detected on MSSQL server.")

        if ssl_version in DEPRECATED_TLS_VERSIONS:
            findings.append(f"Insecure TLS version {ssl_version} used on MSSQL server.")

        if cipher and any(weak in cipher[0] for weak in WEAK_CIPHERS):
            findings.append(f"Weak SSL cipher used by MSSQL server: {cipher[0]}")

        findings.append(f"MSSQL SSL/TLS in use: {ssl_version} with cipher {cipher[0]}")
        conn.close()
    except Exception:
        findings.append("MSSQL SSL/TLS handshake not possible (likely using plain TCP or encryption not enforced).")

def check_sql_browser_udp(host, findings):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT)
        # SQL Browser request (0x02 is the request type)
        sock.sendto(b'\x03', (host, SQL_BROWSER_PORT))
        data, _ = sock.recvfrom(4096)
        if data:
            findings.append("SQL Browser UDP service is active and leaking server instance information.")
        else:
            findings.append("SQL Browser service present but no instance information leaked.")
        sock.close()
    except Exception:
        findings.append("SQL Browser UDP port 1434 is closed or filtered.")

def scan_mssql(target: str) -> dict:
    findings = []

    parsed_target = target.replace('http://', '').replace('https://', '').split('/')[0]

    check_mssql_port(parsed_target, findings)
    grab_mssql_banner(parsed_target, findings)
    check_default_sa_login(parsed_target, findings)
    check_ssl_support(parsed_target, findings)
    check_sql_browser_udp(parsed_target, findings)

    return {
        "domain": parsed_target,
        "findings": findings
    }

def main():
    parser = argparse.ArgumentParser(description="MSSQL Database Vulnerability Scanner")
    parser.add_argument("--target", required=True, help="Target domain or IP")
    args = parser.parse_args()

    result = scan_mssql(args.target)

    print(json.dumps(result, indent=4))

if __name__ == "__main__":
    main()


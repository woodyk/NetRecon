#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_mysql.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-27 21:36:37
# Modified: 2025-04-27 21:37:34

import argparse
import json
import socket
import ssl
import pymysql
from pymysql.constants import CLIENT

TIMEOUT = 5
MYSQL_PORT = 3306

WEAK_CIPHERS = [
    "RC4", "3DES", "NULL", "EXPORT", "DES", "MD5", "PSK", "SRP", "DSS"
]
DEPRECATED_TLS_VERSIONS = ["TLSv1", "TLSv1.1"]

def check_mysql_port(host, findings):
    try:
        sock = socket.create_connection((host, MYSQL_PORT), timeout=TIMEOUT)
        findings.append(f"MySQL port {MYSQL_PORT}/TCP is open.")
        sock.close()
    except Exception:
        findings.append(f"MySQL port {MYSQL_PORT}/TCP is closed or filtered.")

def grab_mysql_banner(host, findings):
    try:
        sock = socket.create_connection((host, MYSQL_PORT), timeout=TIMEOUT)
        banner = sock.recv(1024)
        sock.close()
        if banner:
            findings.append(f"MySQL server handshake banner: {banner.hex()}")
        else:
            findings.append("No MySQL handshake banner received.")
    except Exception:
        findings.append("MySQL banner grabbing failed.")

def check_default_login(host, findings):
    try:
        conn = pymysql.connect(host=host, user='root', password='', connect_timeout=TIMEOUT)
        findings.append("Default root login without password is allowed! Critical misconfiguration.")
        conn.close()
    except pymysql.err.OperationalError as e:
        if "Access denied" in str(e):
            findings.append("Root login without password denied (expected).")
        else:
            findings.append(f"MySQL login test error: {str(e)}")
    except Exception as e:
        findings.append(f"MySQL default credential check failed: {str(e)}")

def check_ssl_support(host, findings):
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(), server_hostname=host)
        conn.settimeout(TIMEOUT)
        conn.connect((host, MYSQL_PORT))
        cert = conn.getpeercert()

        ssl_version = conn.version()
        cipher = conn.cipher()

        if cert:
            expire_ts = ssl.cert_time_to_seconds(cert['notAfter'])
            import time
            if expire_ts < time.time():
                findings.append(f"Expired SSL certificate detected on MySQL port {MYSQL_PORT}.")
            issuer = dict(x[0] for x in cert['issuer'])
            if issuer.get('organizationName', '').lower() == "self-signed":
                findings.append("Self-signed SSL certificate detected on MySQL server.")

        if ssl_version in DEPRECATED_TLS_VERSIONS:
            findings.append(f"Insecure TLS version {ssl_version} used on MySQL.")

        if cipher and any(weak in cipher[0] for weak in WEAK_CIPHERS):
            findings.append(f"Weak SSL cipher used by MySQL server: {cipher[0]}")

        findings.append(f"MySQL SSL/TLS in use: {ssl_version} with cipher {cipher[0]}")
        conn.close()
    except Exception:
        findings.append("MySQL SSL/TLS handshake not possible (likely plain TCP or STARTTLS required).")

def check_auth_plugin(host, findings):
    try:
        conn = pymysql.connect(host=host, user='root', password='incorrect', connect_timeout=TIMEOUT)
        conn.close()
    except pymysql.err.OperationalError as e:
        if hasattr(e, 'args') and len(e.args) >= 2:
            auth_error = e.args[1]
            if "plugin" in auth_error.lower():
                findings.append(f"MySQL authentication plugin exposed: {auth_error}")
    except Exception:
        findings.append("Authentication plugin check failed.")

def try_information_schema_access(host, findings):
    try:
        conn = pymysql.connect(host=host, user='root', password='incorrect', connect_timeout=TIMEOUT, client_flag=CLIENT.CONNECT_WITH_DB)
        cursor = conn.cursor()
        cursor.execute("SHOW DATABASES;")
        dbs = cursor.fetchall()
        if dbs:
            findings.append(f"Unauthenticated database enumeration possible: {dbs}")
        cursor.close()
        conn.close()
    except Exception:
        findings.append("Unauthenticated database enumeration not allowed (expected).")

def scan_mysql(target: str) -> dict:
    findings = []

    parsed_target = target.replace('http://', '').replace('https://', '').split('/')[0]

    check_mysql_port(parsed_target, findings)
    grab_mysql_banner(parsed_target, findings)
    check_default_login(parsed_target, findings)
    check_ssl_support(parsed_target, findings)
    check_auth_plugin(parsed_target, findings)
    try_information_schema_access(parsed_target, findings)

    return {
        "domain": parsed_target,
        "findings": findings
    }

def main():
    parser = argparse.ArgumentParser(description="MySQL Database Vulnerability Scanner")
    parser.add_argument("--target", required=True, help="Target domain or IP")
    args = parser.parse_args()

    result = scan_mysql(args.target)

    print(json.dumps(result, indent=4))

if __name__ == "__main__":
    main()


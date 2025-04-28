#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_mysql.py
# Author: Wadih Khairallah
# Description: MySQL Vulnerability Scanner for NetRecon
# Updated: 2025-04-28

import json
import socket
import ssl
import pymysql
import sys
import re
import time
from pymysql.constants import CLIENT
from datetime import datetime, timezone

TIMEOUT = 5
DEFAULT_MYSQL_PORT = 3306

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

def grab_mysql_banner(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        banner = sock.recv(1024)
        sock.close()
        if banner:
            return {"status": "info", "detail": f"MySQL handshake banner: {banner.hex()}"}
        return {"status": "fail", "detail": "No MySQL handshake banner received."}
    except Exception as e:
        return {"status": "error", "detail": f"MySQL banner grabbing failed: {str(e)}"}

def check_default_login(host, port):
    try:
        conn = pymysql.connect(host=host, user='root', password='', port=port, connect_timeout=TIMEOUT)
        conn.close()
        return {"status": "fail", "detail": "Default root login without password is allowed (critical!)."}
    except pymysql.err.OperationalError as e:
        if "Access denied" in str(e):
            return {"status": "pass", "detail": "Root login without password denied (expected)."}
        return {"status": "error", "detail": f"MySQL login test error: {str(e)}"}
    except Exception as e:
        return {"status": "error", "detail": f"MySQL default credential check failed: {str(e)}"}

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
            issues.append(f"Insecure TLS version {ssl_version}")

        if cipher and any(weak in cipher[0] for weak in WEAK_CIPHERS):
            issues.append(f"Weak cipher detected: {cipher[0]}")

        if issues:
            return {"status": "fail", "detail": "; ".join(issues)}
        return {"status": "pass", "detail": f"MySQL SSL/TLS in use: {ssl_version} with cipher {cipher[0]}"}
    except Exception:
        return {"status": "error", "detail": "MySQL SSL/TLS handshake not possible (likely plain TCP or STARTTLS required)."}

def check_auth_plugin(host, port):
    try:
        conn = pymysql.connect(host=host, user='root', password='incorrect', port=port, connect_timeout=TIMEOUT)
        conn.close()
    except pymysql.err.OperationalError as e:
        if hasattr(e, 'args') and len(e.args) >= 2:
            auth_error = e.args[1]
            if "plugin" in auth_error.lower():
                return {"status": "info", "detail": f"MySQL authentication plugin exposed: {auth_error}"}
    except Exception as e:
        return {"status": "error", "detail": f"MySQL auth plugin check failed: {str(e)}"}
    return {"status": "pass", "detail": "No authentication plugin information exposed."}

def try_information_schema_access(host, port):
    try:
        conn = pymysql.connect(
            host=host, user='root', password='incorrect', port=port,
            connect_timeout=TIMEOUT, client_flag=CLIENT.CONNECT_WITH_DB
        )
        cursor = conn.cursor()
        cursor.execute("SHOW DATABASES;")
        dbs = cursor.fetchall()
        if dbs:
            cursor.close()
            conn.close()
            return {"status": "fail", "detail": f"Unauthenticated database enumeration possible: {dbs}"}
        cursor.close()
        conn.close()
    except Exception:
        return {"status": "pass", "detail": "Unauthenticated database enumeration not allowed (expected)."}

def collect(target: str):
    host, port = parse_target(target)
    port = port if port else DEFAULT_MYSQL_PORT
    vulnerabilities = {}
    summary = []

    if not check_port_open(host, port):
        return {
            "target": host,
            "port": [port],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "open": False,
            "vulnerabilities": {},
            "summary": ["MySQL port not reachable."]
        }

    vulnerabilities["mysql_banner"] = grab_mysql_banner(host, port)
    vulnerabilities["mysql_default_login"] = check_default_login(host, port)
    vulnerabilities["mysql_ssl_support"] = check_ssl_support(host, port)
    vulnerabilities["mysql_auth_plugin"] = check_auth_plugin(host, port)
    vulnerabilities["mysql_information_schema"] = try_information_schema_access(host, port)

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
        print("Usage: python3 check_mysql.py <target> or <target:port>")
        sys.exit(1)

    target = sys.argv[1]
    result = collect(target)

    print(json.dumps(result, indent=4))


#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_postgres.py
# Author: Wadih Khairallah
# Description: PostgreSQL Vulnerability Scanner for NetRecon
# Updated: 2025-04-28

import json
import socket
import psycopg
import sys
import re
from datetime import datetime, timezone

DEFAULT_PORT = 5432
TIMEOUT = 5

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

def check_version_leak(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((host, port))
        data = s.recv(1024)
        s.close()
        if data:
            return {"status": "info", "detail": "PostgreSQL server banner received (version info likely exposed)."}
        return {"status": "pass", "detail": "No PostgreSQL server banner received."}
    except Exception as e:
        return {"status": "error", "detail": f"Version leak check failed: {str(e)}"}

def check_ssl_support(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((host, port))
        ssl_request = b'\x00\x00\x00\x08\x04\xd2\x16\x2f'
        s.sendall(ssl_request)
        resp = s.recv(1)
        s.close()
        if resp == b'S':
            return {"status": "pass", "detail": "SSL supported by PostgreSQL server."}
        elif resp == b'N':
            return {"status": "fail", "detail": "SSL not supported by PostgreSQL server."}
        else:
            return {"status": "fail", "detail": "Unexpected SSL negotiation response."}
    except Exception as e:
        return {"status": "error", "detail": f"SSL support check failed: {str(e)}"}

def check_default_login(host, port):
    try:
        conn = psycopg2.connect(
            host=host,
            port=port,
            user="postgres",
            password="postgres",
            connect_timeout=TIMEOUT
        )
        conn.close()
        return {"status": "fail", "detail": "Default credentials postgres/postgres accepted (critical!)."}
    except psycopg2.OperationalError as e:
        err_msg = str(e).lower()
        if "authentication failed" in err_msg or "password authentication failed" in err_msg:
            return {"status": "pass", "detail": "Default credentials rejected (good)."}
        elif "no password supplied" in err_msg or "trust" in err_msg:
            return {"status": "fail", "detail": "Weak authentication detected (trust authentication likely enabled)."}
        return {"status": "error", "detail": f"Default credential check error: {str(e)}"}
    except Exception as e:
        return {"status": "error", "detail": f"Default credential check failed: {str(e)}"}

def collect(target: str):
    host, port = parse_target(target)
    port = port if port else DEFAULT_PORT
    vulnerabilities = {}
    summary = []

    if not check_port_open(host, port):
        return {
            "target": host,
            "port": [port],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "open": False,
            "vulnerabilities": {},
            "summary": ["PostgreSQL port not reachable."]
        }

    vulnerabilities["postgres_version_leak"] = check_version_leak(host, port)
    vulnerabilities["postgres_ssl_support"] = check_ssl_support(host, port)
    vulnerabilities["postgres_default_login"] = check_default_login(host, port)

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
        print("Usage: python3 check_postgres.py <target> or <target:port>")
        sys.exit(1)

    target = sys.argv[1]
    result = collect(target)

    print(json.dumps(result, indent=4))


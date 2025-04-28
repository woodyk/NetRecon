#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_postgres.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-27 21:57:50

import argparse
import json
import socket
import psycopg2
import psycopg2.extensions

# Constants
DEFAULT_PORT = 5432
TIMEOUT = 5


def check_version_leak(target, port, findings):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((target, port))
        data = s.recv(1024)
        if data:
            findings.append("PostgreSQL server banner received (version info likely exposed).")
        else:
            findings.append("No PostgreSQL server banner received.")
    except Exception as e:
        findings.append(f"Version leak check failed: {str(e)}")
    finally:
        s.close()


def check_ssl_support(target, port, findings):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((target, port))
        ssl_request = b'\x00\x00\x00\x08\x04\xd2\x16\x2f'
        s.sendall(ssl_request)
        resp = s.recv(1)
        if resp == b'S':
            findings.append("SSL supported by server.")
        elif resp == b'N':
            findings.append("SSL not supported by server.")
        else:
            findings.append("Unexpected SSL negotiation response.")
    except Exception as e:
        findings.append(f"SSL support check failed: {str(e)}")
    finally:
        s.close()


def check_default_login(target, port, findings):
    try:
        conn = psycopg2.connect(
            host=target,
            port=port,
            user="postgres",
            password="postgres",
            connect_timeout=TIMEOUT
        )
        findings.append("Default credentials postgres/postgres accepted (critical).")
        conn.close()
    except psycopg2.OperationalError as e:
        err_msg = str(e).lower()
        if "authentication failed" in err_msg or "password authentication failed" in err_msg:
            findings.append("Default credentials rejected (good).")
        elif "no password supplied" in err_msg or "trust" in err_msg:
            findings.append("Weak authentication detected (trust authentication likely enabled).")
        else:
            findings.append(f"Default credential check error: {str(e)}")
    except Exception as e:
        findings.append(f"Default credential check failed: {str(e)}")


def scan_postgres(target: str, port: int = DEFAULT_PORT) -> dict:
    """Remote PostgreSQL vulnerability scan."""
    findings = []

    check_version_leak(target, port, findings)
    check_ssl_support(target, port, findings)
    check_default_login(target, port, findings)

    return {
        "ip": target,
        "port": port,
        "findings": findings
    }


def main():
    parser = argparse.ArgumentParser(description="PostgreSQL Server Vulnerability Scanner")
    parser.add_argument("--ip", required=True, help="Target PostgreSQL server IP address")
    parser.add_argument("--port", type=int, default=5432, help="Target PostgreSQL server port (default 5432)")
    args = parser.parse_args()

    result = scan_postgres(target=args.ip, port=args.port)

    print(json.dumps(result, indent=4))


if __name__ == "__main__":
    main()


#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_redis.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-27 21:59:59

"""
check_redis.py
Sovereign Modular Network Vulnerability Scanner - Redis Module
Author: Wadih Khairallah
"""

import argparse
import json
import socket

# Constants
DEFAULT_PORT = 6379
TIMEOUT = 3


def send_redis_command(sock, command: str) -> str:
    try:
        cmd = f"*1\r\n${len(command)}\r\n{command}\r\n"
        sock.sendall(cmd.encode())
        response = sock.recv(4096)
        return response.decode(errors="ignore")
    except Exception:
        return ""


def check_open_access(target, port, findings):
    try:
        sock = socket.create_connection((target, port), timeout=TIMEOUT)
        response = send_redis_command(sock, "PING")
        if "PONG" in response:
            findings.append("Redis server responded without authentication (critical).")
        else:
            findings.append("Redis PING command did not respond normally.")
        sock.close()
    except Exception as e:
        findings.append(f"Open access check failed: {str(e)}")


def check_version_info(target, port, findings):
    try:
        sock = socket.create_connection((target, port), timeout=TIMEOUT)
        response = send_redis_command(sock, "INFO")
        if "redis_version:" in response:
            for line in response.splitlines():
                if line.startswith("redis_version:"):
                    findings.append(f"Redis version detected: {line.split(':')[1].strip()}.")
                    break
        else:
            findings.append("Could not determine Redis version.")
        sock.close()
    except Exception as e:
        findings.append(f"Version info check failed: {str(e)}")


def check_default_password(target, port, findings):
    try:
        sock = socket.create_connection((target, port), timeout=TIMEOUT)
        response = send_redis_command(sock, "AUTH """)
        if "OK" in response:
            findings.append("Redis accepted blank password authentication (critical).")
        elif "NOAUTH" in response:
            findings.append("Redis requires authentication (good).")
        else:
            findings.append("Redis authentication behavior unclear.")
        sock.close()
    except Exception as e:
        findings.append(f"Default password check failed: {str(e)}")


def check_protected_mode(target, port, findings):
    try:
        sock = socket.create_connection((target, port), timeout=TIMEOUT)
        response = send_redis_command(sock, "CONFIG GET protected-mode")
        if "protected-mode" in response:
            if "yes" in response:
                findings.append("Redis protected mode is enabled (good).")
            else:
                findings.append("Redis protected mode is disabled (dangerous if publicly exposed).")
        else:
            findings.append("Could not verify protected mode status.")
        sock.close()
    except Exception as e:
        findings.append(f"Protected mode check failed: {str(e)}")


def check_config_exposure(target, port, findings):
    try:
        sock = socket.create_connection((target, port), timeout=TIMEOUT)
        response = send_redis_command(sock, "CONFIG GET *")
        if "requirepass" in response:
            findings.append("Redis CONFIG GET allowed without authentication (critical misconfiguration).")
        else:
            findings.append("Redis CONFIG GET not exposed without authentication.")
        sock.close()
    except Exception as e:
        findings.append(f"Config exposure check failed: {str(e)}")


def scan_redis(target: str, port: int = DEFAULT_PORT) -> dict:
    """Remote Redis vulnerability scan."""
    findings = []

    check_open_access(target, port, findings)
    check_version_info(target, port, findings)
    check_default_password(target, port, findings)
    check_protected_mode(target, port, findings)
    check_config_exposure(target, port, findings)

    return {
        "ip": target,
        "port": port,
        "findings": findings
    }


def main():
    parser = argparse.ArgumentParser(description="Redis Server Vulnerability Scanner")
    parser.add_argument("--ip", required=True, help="Target Redis server IP address")
    parser.add_argument("--port", type=int, default=6379, help="Target Redis server port (default 6379)")
    args = parser.parse_args()

    result = scan_redis(target=args.ip, port=args.port)

    print(json.dumps(result, indent=4))


if __name__ == "__main__":
    main()

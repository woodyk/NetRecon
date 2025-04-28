#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_redis.py
# Author: Wadih Khairallah
# Description: Redis Vulnerability Scanner for NetRecon
# Updated: 2025-04-28

import json
import socket
import sys
import re
from datetime import datetime, timezone

# Constants
DEFAULT_PORT = 6379
TIMEOUT = 3

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

def send_redis_command(sock, command: str) -> str:
    try:
        cmd = f"*1\r\n${len(command)}\r\n{command}\r\n"
        sock.sendall(cmd.encode())
        response = sock.recv(4096)
        return response.decode(errors="ignore")
    except Exception:
        return ""

def check_open_access(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        response = send_redis_command(sock, "PING")
        sock.close()
        if "PONG" in response:
            return {"status": "fail", "detail": "Redis server responded without authentication (critical)."}
        return {"status": "pass", "detail": "Redis PING command did not respond normally."}
    except Exception as e:
        return {"status": "error", "detail": f"Open access check failed: {str(e)}"}

def check_version_info(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        response = send_redis_command(sock, "INFO")
        sock.close()
        if "redis_version:" in response:
            for line in response.splitlines():
                if line.startswith("redis_version:"):
                    version = line.split(':')[1].strip()
                    return {"status": "info", "detail": f"Redis version detected: {version}."}
        return {"status": "fail", "detail": "Could not determine Redis version."}
    except Exception as e:
        return {"status": "error", "detail": f"Version info check failed: {str(e)}"}

def check_default_password(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        response = send_redis_command(sock, 'AUTH ""')
        sock.close()
        if "OK" in response:
            return {"status": "fail", "detail": "Redis accepted blank password authentication (critical)."}
        if "NOAUTH" in response:
            return {"status": "pass", "detail": "Redis requires authentication (good)."}
        return {"status": "fail", "detail": "Redis authentication behavior unclear."}
    except Exception as e:
        return {"status": "error", "detail": f"Default password check failed: {str(e)}"}

def check_protected_mode(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        response = send_redis_command(sock, "CONFIG GET protected-mode")
        sock.close()
        if "protected-mode" in response:
            if "yes" in response:
                return {"status": "pass", "detail": "Redis protected mode is enabled (good)."}
            else:
                return {"status": "fail", "detail": "Redis protected mode is disabled (dangerous if publicly exposed)."}
        return {"status": "fail", "detail": "Could not verify protected mode status."}
    except Exception as e:
        return {"status": "error", "detail": f"Protected mode check failed: {str(e)}"}

def check_config_exposure(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        response = send_redis_command(sock, "CONFIG GET *")
        sock.close()
        if "requirepass" in response:
            return {"status": "fail", "detail": "Redis CONFIG GET allowed without authentication (critical misconfiguration)."}
        return {"status": "pass", "detail": "Redis CONFIG GET not exposed without authentication."}
    except Exception as e:
        return {"status": "error", "detail": f"Config exposure check failed: {str(e)}"}

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
            "summary": ["Redis port not reachable."]
        }

    vulnerabilities["redis_open_access"] = check_open_access(host, port)
    vulnerabilities["redis_version_info"] = check_version_info(host, port)
    vulnerabilities["redis_default_password"] = check_default_password(host, port)
    vulnerabilities["redis_protected_mode"] = check_protected_mode(host, port)
    vulnerabilities["redis_config_exposure"] = check_config_exposure(host, port)

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
        print("Usage: python3 check_redis.py <target> or <target:port>")
        sys.exit(1)

    target = sys.argv[1]
    result = collect(target)

    print(json.dumps(result, indent=4))


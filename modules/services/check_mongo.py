#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_mongo.py
# Author: Wadih Khairallah
# Description: MongoDB Vulnerability Scanner for NetRecon
# Updated: 2025-04-28

import json
import socket
import struct
import sys
import re
from datetime import datetime, timezone

# Constants
DEFAULT_PORT = 27017
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

def build_isMaster():
    request_id = 1
    flags = 0
    full_collection_name = b"admin.$cmd\x00"
    number_to_skip = 0
    number_to_return = -1
    query_bson = b"\x10isMaster\x00\x01\x00\x00\x00\x00"  # BSON for { isMaster: 1 }
    header = struct.pack("<iiii", 16 + len(full_collection_name) + 8 + len(query_bson), request_id, 0, 2004)
    message = header
    message += struct.pack("<i", flags)
    message += full_collection_name
    message += struct.pack("<ii", number_to_skip, number_to_return)
    message += query_bson
    return message

def send_mongo_command(sock, command: bytes) -> bytes:
    try:
        sock.sendall(command)
        response = sock.recv(4096)
        return response
    except Exception:
        return b""

def check_open_access(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        sock.close()
        return {"status": "pass", "detail": "MongoDB port open and accepting TCP connections."}
    except Exception as e:
        return {"status": "error", "detail": f"MongoDB TCP connection failed: {str(e)}"}

def check_version_info(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        command = build_isMaster()
        response = send_mongo_command(sock, command)
        sock.close()
        decoded = response.decode(errors="ignore")
        if "version" in decoded:
            for line in decoded.split("\x00"):
                if "version" in line:
                    return {"status": "info", "detail": f"MongoDB version disclosed: {line.strip()}"}
        return {"status": "fail", "detail": "Could not determine MongoDB version."}
    except Exception as e:
        return {"status": "error", "detail": f"Version info check failed: {str(e)}"}

def check_authentication_required(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        command = build_isMaster()
        response = send_mongo_command(sock, command)
        sock.close()
        if b"Unauthorized" in response or b"requires authentication" in response:
            return {"status": "pass", "detail": "MongoDB server requires authentication (good)."}
        return {"status": "fail", "detail": "MongoDB server did not clearly enforce authentication (potential risk)."}
    except Exception as e:
        return {"status": "error", "detail": f"Authentication enforcement check failed: {str(e)}"}

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
            "summary": ["MongoDB port not reachable."]
        }

    vulnerabilities["mongo_open_access"] = check_open_access(host, port)
    vulnerabilities["mongo_version_info"] = check_version_info(host, port)
    vulnerabilities["mongo_authentication_check"] = check_authentication_required(host, port)

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
        print("Usage: python3 check_mongo.py <target> or <target:port>")
        sys.exit(1)

    target = sys.argv[1]
    result = collect(target)

    print(json.dumps(result, indent=4))


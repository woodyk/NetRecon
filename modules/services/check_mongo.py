#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_mongo.py
# Author: Wadih Khairallah
# Description: """

import argparse
import json
import socket
import struct

# Constants
DEFAULT_PORT = 27017
TIMEOUT = 3


def build_isMaster():
    """Build a simple isMaster command for MongoDB handshake."""
    request_id = 1
    flags = 0
    full_collection_name = b"admin.$cmd\x00"
    number_to_skip = 0
    number_to_return = -1
    query = {
        "isMaster": 1
    }
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


def check_open_access(target, port, findings):
    try:
        sock = socket.create_connection((target, port), timeout=TIMEOUT)
        sock.close()
        findings.append("MongoDB port open and accepting TCP connections.")
    except Exception as e:
        findings.append(f"MongoDB TCP connection failed: {str(e)}")


def check_version_info(target, port, findings):
    try:
        sock = socket.create_connection((target, port), timeout=TIMEOUT)
        command = build_isMaster()
        response = send_mongo_command(sock, command)
        decoded = response.decode(errors="ignore")
        if "version" in decoded:
            for line in decoded.split("\x00"):
                if "version" in line:
                    findings.append(f"MongoDB version disclosed: {line.strip()}.")
                    break
        else:
            findings.append("Could not determine MongoDB version.")
        sock.close()
    except Exception as e:
        findings.append(f"Version info check failed: {str(e)}")


def check_authentication_required(target, port, findings):
    try:
        sock = socket.create_connection((target, port), timeout=TIMEOUT)
        command = build_isMaster()
        response = send_mongo_command(sock, command)
        if b"Unauthorized" in response or b"requires authentication" in response:
            findings.append("MongoDB server requires authentication (good).")
        else:
            findings.append("MongoDB server did not clearly enforce authentication (potential risk).")
        sock.close()
    except Exception as e:
        findings.append(f"Authentication enforcement check failed: {str(e)}")


def scan_mongo(target: str, port: int = DEFAULT_PORT) -> dict:
    """Remote MongoDB vulnerability scan."""
    findings = []

    check_open_access(target, port, findings)
    check_version_info(target, port, findings)
    check_authentication_required(target, port, findings)

    return {
        "ip": target,
        "port": port,
        "findings": findings
    }


def main():
    parser = argparse.ArgumentParser(description="MongoDB Server Vulnerability Scanner")
    parser.add_argument("--ip", required=True, help="Target MongoDB server IP address")
    parser.add_argument("--port", type=int, default=27017, help="Target MongoDB server port (default 27017)")
    args = parser.parse_args()

    result = scan_mongo(target=args.ip, port=args.port)

    print(json.dumps(result, indent=4))


if __name__ == "__main__":
    main()
# Created: 2025-04-27 22:03:11



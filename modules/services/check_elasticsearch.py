#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_elasticsearch.py
# Author: Wadih Khairallah
# Description: Elasticsearch Vulnerability Scanner for NetRecon
# Updated: 2025-04-28

import json
import http.client
import socket
import sys
import re
from datetime import datetime, timezone

# Constants
DEFAULT_PORT = 9200
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
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return True
    except Exception:
        return False

def http_get(host, port, path="/") -> str:
    try:
        conn = http.client.HTTPConnection(host, port, timeout=TIMEOUT)
        conn.request("GET", path)
        response = conn.getresponse()
        data = response.read().decode(errors="ignore")
        conn.close()
        return data
    except Exception:
        return ""

def check_open_access(host, port):
    try:
        data = http_get(host, port, "/")
        if data:
            return {"status": "fail", "detail": "Elasticsearch server responded without authentication (critical)."}
        else:
            return {"status": "pass", "detail": "No open access detected (no response or authentication enforced)."}
    except Exception as e:
        return {"status": "error", "detail": f"Open access check failed: {str(e)}"}

def check_version_info(host, port):
    try:
        data = http_get(host, port, "/")
        if "version" in data and "number" in data:
            version_index = data.find("\"number\":\"")
            if version_index != -1:
                version_start = version_index + len("\"number\":\"")
                version_end = data.find("\"", version_start)
                version = data[version_start:version_end]
                return {"status": "info", "detail": f"Elasticsearch version detected: {version}."}
        return {"status": "pass", "detail": "Could not determine Elasticsearch version."}
    except Exception as e:
        return {"status": "error", "detail": f"Version info check failed: {str(e)}"}

def check_cluster_info(host, port):
    try:
        data = http_get(host, port, "/_cluster/health")
        if data and "cluster_name" in data:
            return {"status": "fail", "detail": "Cluster health information accessible without authentication."}
        else:
            return {"status": "pass", "detail": "Cluster health endpoint not accessible or protected."}
    except Exception as e:
        return {"status": "error", "detail": f"Cluster info check failed: {str(e)}"}

def check_unauthenticated_query(host, port):
    try:
        data = http_get(host, port, "/_cat/indices?v")
        if data and "index" in data:
            return {"status": "fail", "detail": "Index listing accessible without authentication (critical)."}
        else:
            return {"status": "pass", "detail": "Index listing endpoint not accessible or protected."}
    except Exception as e:
        return {"status": "error", "detail": f"Unauthenticated query check failed: {str(e)}"}

def collect(target: str):
    host, port = parse_target(target)
    port = port if port else DEFAULT_PORT
    open_ports = []
    vulnerabilities = {}
    summary = []

    if check_port_open(host, port):
        open_ports.append(port)
    else:
        return {
            "target": host,
            "port": [port],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "open": False,
            "vulnerabilities": {},
            "summary": ["Elasticsearch port not reachable."]
        }

    vulnerabilities["open_access_check"] = check_open_access(host, port)
    vulnerabilities["version_info_check"] = check_version_info(host, port)
    vulnerabilities["cluster_info_check"] = check_cluster_info(host, port)
    vulnerabilities["unauthenticated_query_check"] = check_unauthenticated_query(host, port)

    return {
        "target": host,
        "port": open_ports,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "open": True,
        "vulnerabilities": vulnerabilities,
        "summary": summary
    }

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 check_elasticsearch.py <target> or <target:port>")
        sys.exit(1)

    target = sys.argv[1]
    result = collect(target)

    print(json.dumps(result, indent=4))


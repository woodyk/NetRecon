#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_elasticsearch.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-27 22:04:32

import argparse
import json
import http.client
import socket

# Constants
DEFAULT_PORT = 9200
TIMEOUT = 3


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


def check_open_access(target, port, findings):
    try:
        data = http_get(target, port, "/")
        if data:
            findings.append("Elasticsearch server responded without authentication (critical).")
        else:
            findings.append("No response from Elasticsearch server.")
    except Exception as e:
        findings.append(f"Open access check failed: {str(e)}")


def check_version_info(target, port, findings):
    try:
        data = http_get(target, port, "/")
        if "version" in data:
            if "number" in data:
                version_index = data.find("\"number\":\"")
                if version_index != -1:
                    version_start = version_index + len("\"number\":\"")
                    version_end = data.find("\"", version_start)
                    version = data[version_start:version_end]
                    findings.append(f"Elasticsearch version detected: {version}.")
        else:
            findings.append("Could not determine Elasticsearch version.")
    except Exception as e:
        findings.append(f"Version info check failed: {str(e)}")


def check_cluster_info(target, port, findings):
    try:
        data = http_get(target, port, "/_cluster/health")
        if data and "cluster_name" in data:
            findings.append("Cluster health information accessible without authentication.")
        else:
            findings.append("Cluster health endpoint not accessible or protected.")
    except Exception as e:
        findings.append(f"Cluster info check failed: {str(e)}")


def check_unauthenticated_query(target, port, findings):
    try:
        data = http_get(target, port, "/_cat/indices?v")
        if data and "index" in data:
            findings.append("Index listing accessible without authentication (critical).")
        else:
            findings.append("Index listing endpoint not accessible or protected.")
    except Exception as e:
        findings.append(f"Unauthenticated query check failed: {str(e)}")


def scan_elasticsearch(target: str, port: int = DEFAULT_PORT) -> dict:
    """Remote Elasticsearch vulnerability scan."""
    findings = []

    check_open_access(target, port, findings)
    check_version_info(target, port, findings)
    check_cluster_info(target, port, findings)
    check_unauthenticated_query(target, port, findings)

    return {
        "ip": target,
        "port": port,
        "findings": findings
    }


def main():
    parser = argparse.ArgumentParser(description="Elasticsearch Server Vulnerability Scanner")
    parser.add_argument("--ip", required=True, help="Target Elasticsearch server IP address")
    parser.add_argument("--port", type=int, default=9200, help="Target Elasticsearch server port (default 9200)")
    args = parser.parse_args()

    result = scan_elasticsearch(target=args.ip, port=args.port)

    print(json.dumps(result, indent=4))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: nmap_recon.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-28 18:41:36
# Modified: 2025-04-29 14:58:54

import nmap
import shutil

# ===== Configuration =====
FULL_SCAN = False  # Set to False for fast (top 1000 ports) scan

def collect(target):
    result = {
        "status": "success",
        "data": {}
    }

    try:
        # Check if nmap is installed
        if not shutil.which("nmap"):
            raise EnvironmentError("Nmap binary not found. Please install nmap to use this module.")

        nm = nmap.PortScanner()

        tcp_arguments = "-sS -sV -O -Pn"
        udp_arguments = "-sU -Pn"

        if FULL_SCAN:
            tcp_arguments += " -p-"
            udp_arguments += " -p-"

        # Full or fast TCP scan
        nm.scan(
            hosts=target,
            arguments=tcp_arguments
        )

        if target not in nm.all_hosts():
            raise RuntimeError(f"TCP Scan: Target {target} not responding or scan failed.")

        target_data = nm[target]

        open_tcp_ports = {}
        if 'tcp' in target_data:
            for port, port_data in target_data['tcp'].items():
                if port_data.get('state') == 'open':
                    open_tcp_ports[port] = {
                        "service": port_data.get('name', 'unknown'),
                        "product": port_data.get('product', ''),
                        "version": port_data.get('version', ''),
                        "extrainfo": port_data.get('extrainfo', '')
                    }

        result["data"]["open_tcp_ports"] = open_tcp_ports

        # Now run a UDP scan
        nm_udp = nmap.PortScanner()
        nm_udp.scan(
            hosts=target,
            arguments=udp_arguments
        )

        udp_data = nm_udp[target]
        open_udp_ports = {}
        if 'udp' in udp_data:
            for port, port_data in udp_data['udp'].items():
                if port_data.get('state') == 'open':
                    open_udp_ports[port] = {
                        "service": port_data.get('name', 'unknown'),
                        "product": port_data.get('product', ''),
                        "version": port_data.get('version', ''),
                        "extrainfo": port_data.get('extrainfo', '')
                    }

        result["data"]["open_udp_ports"] = open_udp_ports

        # Parse OS fingerprinting (from TCP scan)
        os_matches = target_data.get('osmatch', [])
        if os_matches:
            result["data"]["os_guess"] = [
                {
                    "name": match.get('name'),
                    "accuracy": match.get('accuracy')
                } for match in os_matches
            ]
        else:
            result["data"]["os_guess"] = []

    except Exception as e:
        result["status"] = "error"
        result["data"] = {}
        result["error"] = str(e)

    return result


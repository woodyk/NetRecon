#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: ssl_cert_recon.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-28 18:30:21

import ssl
import socket

def collect(target):
    result = {}
    try:
        host, port = target, 443  # default HTTPS port

        # If input already has port (domain:port)
        if ":" in target:
            host, port = target.split(":")
            port = int(port)

        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        if cert:
            result["subject"] = dict(x[0] for x in cert.get("subject", []))
            result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
            result["version"] = cert.get("version")
            result["serialNumber"] = cert.get("serialNumber")
            result["notBefore"] = cert.get("notBefore")
            result["notAfter"] = cert.get("notAfter")
            result["subjectAltName"] = cert.get("subjectAltName", [])
        else:
            result["error"] = "No certificate received."

    except Exception as e:
        result["error"] = str(e)

    return result


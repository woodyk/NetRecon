#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: ssl_cert_recon.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-28 18:30:21

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ssl
import socket
import ipaddress
import tempfile
import os

def is_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def collect(target):
    result = {
        "status": "success",
        "data": {}
    }

    try:
        host, port = target, 443

        if ":" in target:
            host, port = target.split(":")
            port = int(port)

        context = ssl._create_unverified_context()

        with socket.create_connection((host, int(port)), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host if not is_ip(host) else None) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)

        if not der_cert:
            result["status"] = "error"
            result["error"] = "No certificate returned."
            return result

        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
        result["data"]["pem"] = pem_cert

        # Parse cert fields using test_decode_cert
        with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix=".pem") as tmp:
            tmp.write(pem_cert)
            tmp_path = tmp.name

        parsed = ssl._ssl._test_decode_cert(tmp_path)
        os.unlink(tmp_path)

        result["data"]["subject"] = dict(x[0] for x in parsed.get("subject", []))
        result["data"]["issuer"] = dict(x[0] for x in parsed.get("issuer", []))
        result["data"]["version"] = parsed.get("version")
        result["data"]["serialNumber"] = parsed.get("serialNumber")
        result["data"]["notBefore"] = parsed.get("notBefore")
        result["data"]["notAfter"] = parsed.get("notAfter")
        result["data"]["subjectAltName"] = parsed.get("subjectAltName", [])

    except Exception as e:
        result["status"] = "error"
        result["data"] = {}
        result["error"] = str(e)

    return result


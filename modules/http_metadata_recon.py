#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: http_metadata_recon.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-28 18:30:55
# Modified: 2025-04-28 18:36:04

import http.client

def collect(target):
    result = {
        "status": "success",
        "data": {}
    }
    try:
        host = target
        port = 80
        scheme = "http"

        if ":" in target:
            host, port = target.split(":")
            port = int(port)

        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("HEAD", "/")
        resp = conn.getresponse()

        result["data"]["status"] = resp.status
        result["data"]["reason"] = resp.reason
        result["data"]["headers"] = dict(resp.getheaders())

        conn.close()

    except Exception as e:
        result["status"] = "error"
        result["data"] = {}
        result["error"] = str(e)

    return result

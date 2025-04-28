#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: http_metadata_recon.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-28 18:30:55

import http.client
import urllib.parse

def collect(target):
    result = {}
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

        result["status"] = resp.status
        result["reason"] = resp.reason
        result["headers"] = dict(resp.getheaders())

        conn.close()

    except Exception as e:
        result["error"] = str(e)

    return result


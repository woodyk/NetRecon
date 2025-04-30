#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: geolocation_recon.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-28 18:40:43

import requests
import socket
import ipaddress

def collect(target):
    result = {
        "status": "success",
        "data": {}
    }
    try:
        ip = target
        try:
            # If domain is given, resolve to IP
            ipaddress.ip_address(target)
        except ValueError:
            ip = socket.gethostbyname(target)

        query_url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"

        resp = requests.get(query_url, timeout=10)

        if resp.status_code == 200:
            geo_data = resp.json()
            if geo_data.get("status") == "success":
                result["data"] = geo_data
            else:
                result["status"] = "error"
                result["data"] = {}
                result["error"] = geo_data.get("message", "Unknown error in GeoIP lookup.")
        else:
            result["status"] = "error"
            result["data"] = {}
            result["error"] = f"GeoIP service returned status code: {resp.status_code}"

    except Exception as e:
        result["status"] = "error"
        result["data"] = {}
        result["error"] = str(e)

    return result

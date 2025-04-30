#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: asn_info_recon.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-28 18:30:39
# Modified: 2025-04-28 18:35:34

import ipaddress
from ipwhois import IPWhois

def collect(target):
    result = {
        "status": "success",
        "data": {}
    }
    try:
        ip = target
        if not any(c.isdigit() for c in target.split(".")[0]):
            import socket
            ip = socket.gethostbyname(target)

        ip_obj = ipaddress.ip_address(ip)

        obj = IPWhois(str(ip_obj))
        data = obj.lookup_rdap(depth=1)

        result["data"]["asn"] = data.get("asn")
        result["data"]["asn_description"] = data.get("asn_description")
        result["data"]["asn_cidr"] = data.get("asn_cidr")
        result["data"]["asn_country_code"] = data.get("asn_country_code")

    except Exception as e:
        result["status"] = "error"
        result["data"] = {}
        result["error"] = str(e)

    return result

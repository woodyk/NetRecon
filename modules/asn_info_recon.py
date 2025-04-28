#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: asn_info_recon.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-28 18:30:39

import ipaddress
from ipwhois import IPWhois

def collect(target):
    result = {}
    try:
        ip = target
        if not any(c.isdigit() for c in target.split(".")[0]):  # likely domain, not IP
            import socket
            ip = socket.gethostbyname(target)

        ip_obj = ipaddress.ip_address(ip)

        obj = IPWhois(str(ip_obj))
        data = obj.lookup_rdap(depth=1)

        result["asn"] = data.get("asn")
        result["asn_description"] = data.get("asn_description")
        result["asn_cidr"] = data.get("asn_cidr")
        result["asn_country_code"] = data.get("asn_country_code")

    except Exception as e:
        result["error"] = str(e)

    return result


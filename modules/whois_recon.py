# -*- coding: utf-8 -*-
#
# File: whois_recon.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-28 18:39:49
# Modified: 2025-04-29 14:55:55

import whois
import ipaddress
from ipwhois import IPWhois

def collect(target):
    result = {
        "status": "success",
        "data": {}
    }

    try:
        is_ip = False
        try:
            ipaddress.ip_address(target)
            is_ip = True
        except ValueError:
            pass

        if is_ip:
            # IP WHOIS (RDAP)
            obj = IPWhois(target)
            ipwhois_data = obj.lookup_rdap(depth=1)

            result["data"]["asn"] = ipwhois_data.get("asn")
            result["data"]["asn_country_code"] = ipwhois_data.get("asn_country_code")
            result["data"]["asn_description"] = ipwhois_data.get("asn_description")
            result["data"]["asn_registry"] = ipwhois_data.get("asn_registry")
            result["data"]["network"] = ipwhois_data.get("network", {}).get("cidr")
            result["data"]["org"] = ipwhois_data.get("network", {}).get("name")
            result["data"]["address"] = ipwhois_data.get("network", {}).get("address")
            result["data"]["country"] = ipwhois_data.get("network", {}).get("country")

        else:
            # Domain WHOIS
            domain_info = whois.whois(target)

            result["data"]["registrar"] = domain_info.registrar
            result["data"]["creation_date"] = (
                [str(d) for d in domain_info.creation_date]
                if isinstance(domain_info.creation_date, list)
                else str(domain_info.creation_date)
            )
            result["data"]["expiration_date"] = (
                [str(d) for d in domain_info.expiration_date]
                if isinstance(domain_info.expiration_date, list)
                else str(domain_info.expiration_date)
            )
            result["data"]["organization"] = domain_info.org
            result["data"]["country"] = domain_info.country
            result["data"]["address"] = domain_info.address

    except Exception as e:
        result["status"] = "error"
        result["data"] = {}
        result["error"] = str(e)

    return result


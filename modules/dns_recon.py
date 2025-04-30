#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: dns_recon.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-28 15:53:58
# Modified: 2025-04-29 14:29:16

import dns.resolver
import dns.reversename
import ipaddress

def is_ip(address):
    """
    Check if the input is an IP address.
    """
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
        resolver = dns.resolver.Resolver()

        if is_ip(target):
            # Handle IP Address: perform PTR (reverse DNS)
            try:
                reversed_name = dns.reversename.from_address(target)
                answers = resolver.resolve(reversed_name, "PTR", lifetime=5)
                result["data"]["PTR"] = [str(rdata) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout) as e:
                result["data"]["PTR_error"] = str(e)
        else:
            # Handle Domain: perform standard DNS lookups
            record_types = ["A", "AAAA", "MX", "NS", "SOA", "TXT", "CNAME"]

            for rtype in record_types:
                try:
                    answers = resolver.resolve(target, rtype, lifetime=5)
                    result["data"][rtype] = [str(rdata) for rdata in answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout) as e:
                    result["data"][f"{rtype}_error"] = str(e)

    except Exception as e:
        result["status"] = "error"
        result["data"] = {}
        result["error"] = str(e)

    return result

if __name__ == "__main__":
    # Test with both IP and domain name
    test_ip = "8.8.8.8"
    test_domain = "example.com"

    print("IP Test Result:")
    print(collect(test_ip))

    print("\nDomain Test Result:")
    print(collect(test_domain))

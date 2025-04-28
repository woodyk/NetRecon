#!/usr/bin/env python3
#
# whois_recon.py

import whois
import re
from ipwhois import IPWhois

def is_domain(name):
    # Check if input is a domain (not an IP address)
    ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$|^([a-fA-F0-9:]+:+)+[a-fA-F0-9]+$")
    return not ip_pattern.match(name)

def serialize_datetime(value):
    """Helper to serialize datetime objects or lists into ISO8601 strings."""
    if isinstance(value, list):
        return [v.isoformat() if hasattr(v, 'isoformat') else str(v) for v in value if v]
    if hasattr(value, 'isoformat'):
        return value.isoformat()
    return str(value) if value else None

def collect(query):
    if is_domain(query):
        # Perform WHOIS lookup for domain
        try:
            whois_data = whois.whois(query)
            return {
                "registrar": whois_data.registrar,
                "creation_date": serialize_datetime(whois_data.creation_date),
                "expiration_date": serialize_datetime(whois_data.expiration_date),
                "organization": whois_data.org,
                "country": whois_data.country,
                "address": whois_data.address if isinstance(whois_data.address, list) else [whois_data.address] if whois_data.address else []
            }
        except Exception as e:
            return {"error": f"Domain WHOIS lookup failed: {str(e)}"}
    else:
        # Perform WHOIS lookup for IP address
        try:
            ipwhois = IPWhois(query)
            whois_data = ipwhois.lookup_whois()
            return {
                "asn": whois_data.get("asn"),
                "asn_country_code": whois_data.get("asn_country_code"),
                "asn_description": whois_data.get("asn_description"),
                "asn_registry": whois_data.get("asn_registry"),
                "network": whois_data.get("network", {}).get("cidr"),
                "org": whois_data.get("network", {}).get("org"),
                "address": whois_data.get("network", {}).get("address"),
                "country": whois_data.get("network", {}).get("country")
            }
        except Exception as e:
            return {"error": f"IP WHOIS lookup failed: {str(e)}"}

if __name__ == "__main__":
    # Test with both IP and domain
    test_ip = "8.8.8.8"
    test_domain = "example.com"

    print("IP WHOIS Result:")
    print(collect(test_ip))

    print("\nDomain WHOIS Result:")
    print(collect(test_domain))


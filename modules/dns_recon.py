#!/usr/bin/env python3
#
# dns_recon.py

import dns.resolver
import dns.reversename
import re

def is_ip(address):
    # Regular expression to check if the input is a valid IP address (IPv4 or IPv6)
    ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$|^([a-fA-F0-9:]+:+)+[a-fA-F0-9]+$")
    return bool(ip_pattern.match(address))

def collect(address):
    records = {}

    if is_ip(address):
        # Process as IP address, attempt PTR lookup
        try:
            rev_name = dns.reversename.from_address(address)
            records["PTR"] = [rdata.to_text() for rdata in dns.resolver.resolve(rev_name, "PTR")]
        except Exception as e:
            records["PTR_error"] = str(e)
    else:
        # Process as domain name, attempt various DNS record lookups
        try:
            records["A"] = [rdata.to_text() for rdata in dns.resolver.resolve(address, "A")]
        except Exception as e:
            records["A_error"] = str(e)

        try:
            records["AAAA"] = [rdata.to_text() for rdata in dns.resolver.resolve(address, "AAAA")]
        except Exception as e:
            records["AAAA_error"] = str(e)

        try:
            records["MX"] = [rdata.to_text() for rdata in dns.resolver.resolve(address, "MX")]
        except Exception as e:
            records["MX_error"] = str(e)

        try:
            records["TXT"] = [rdata.to_text() for rdata in dns.resolver.resolve(address, "TXT")]
        except Exception as e:
            records["TXT_error"] = str(e)

        try:
            records["NS"] = [rdata.to_text() for rdata in dns.resolver.resolve(address, "NS")]
        except Exception as e:
            records["NS_error"] = str(e)

    return records

if __name__ == "__main__":
    # Test with both IP and domain name
    test_ip = "8.8.8.8"
    test_domain = "example.com"

    print("IP Test Result:")
    print(collect(test_ip))

    print("\nDomain Test Result:")
    print(collect(test_domain))

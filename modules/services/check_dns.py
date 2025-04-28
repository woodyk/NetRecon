#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_dns.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-27 21:00:25
# Modified: 2025-04-27 21:06:13

# modules/dns.py

import argparse
import json
import random
import string
import dns.resolver
import dns.query
import dns.zone
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.exception

def random_domain(base_domain: str) -> str:
    rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    return f"{rand}.{base_domain}"

def check_recursion(ip, findings):
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [ip]
        resolver.lifetime = 3
        answer = resolver.resolve('google.com', 'A')
        if answer.rrset:
            findings.append("Open recursion detected: server answers external queries.")
    except dns.resolver.NoNameservers:
        findings.append("Recursion refused (good).")
    except dns.resolver.Timeout:
        findings.append("Timeout during recursion test.")
    except Exception as e:
        findings.append(f"Recursion test failed: {str(e)}")

def check_version_disclosure(ip, findings):
    try:
        query = dns.message.make_query('version.bind', dns.rdatatype.TXT, dns.rdataclass.CH)
        response = dns.query.udp(query, ip, timeout=3)
        for answer in response.answer:
            for item in answer.items:
                findings.append(f"Version disclosure detected: {item.to_text()}")
                return
        findings.append("No version disclosure detected.")
    except dns.exception.Timeout:
        findings.append("Timeout during version disclosure test.")
    except Exception as e:
        findings.append(f"Version disclosure check failed: {str(e)}")

def check_zone_transfer(ip, domain, findings):
    try:
        xfr = dns.query.xfr(ip, domain, timeout=5)
        zone = dns.zone.from_xfr(xfr)
        if zone:
            findings.append("Zone transfer allowed (critical vulnerability).")
            findings.append(f"Enumerated {len(zone.nodes.keys())} records via AXFR.")
    except dns.exception.FormError:
        findings.append("Zone transfer refused (expected).")
    except dns.exception.Timeout:
        findings.append("Timeout during zone transfer test.")
    except Exception as e:
        findings.append(f"Zone transfer check failed: {str(e)}")

def check_dnssec_support(ip, findings):
    try:
        query = dns.message.make_query('dnssec-failed.org', dns.rdatatype.DNSKEY)
        response = dns.query.udp(query, ip, timeout=3)
        for answer in response.answer:
            if answer.rdtype == dns.rdatatype.DNSKEY:
                findings.append("DNSSEC support detected.")
                return
        findings.append("No DNSSEC support detected.")
    except Exception as e:
        findings.append(f"DNSSEC support check failed: {str(e)}")

def check_wildcard_behavior(ip, domain, findings):
    random_subdomain = random_domain(domain)
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [ip]
        resolver.lifetime = 3
        answer = resolver.resolve(random_subdomain, 'A')
        if answer.rrset:
            findings.append(f"Wildcard DNS behavior detected: {random_subdomain} resolves unexpectedly.")
    except dns.resolver.NXDOMAIN:
        findings.append("No wildcard DNS behavior detected.")
    except Exception as e:
        findings.append(f"Wildcard test failed: {str(e)}")

def check_nxdomain_resistance(ip, domain, findings):
    random_subdomain = random_domain(domain)
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [ip]
        resolver.lifetime = 3
        resolver.resolve(random_subdomain, 'A')
        findings.append("Potential NXDOMAIN handling weakness (server responds to invalid domains).")
    except dns.resolver.NXDOMAIN:
        findings.append("NXDOMAIN properly handled.")
    except Exception as e:
        findings.append(f"NXDOMAIN resistance check failed: {str(e)}")

def check_rebinding_protection(ip, domain, findings):
    # This is a shallow test - real rebinding attacks need TTL manipulation
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [ip]
        resolver.lifetime = 3
        answer = resolver.resolve(domain, 'A')
        if answer.rrset and answer.rrset.ttl < 300:
            findings.append(f"Low TTL detected ({answer.rrset.ttl}s) - may allow DNS rebinding.")
        else:
            findings.append("No DNS rebinding vulnerability detected based on TTL.")
    except Exception as e:
        findings.append(f"Rebinding protection check failed: {str(e)}")

def scan_dns(ip: str, domain: str, timeout: int = 5) -> dict:
    """Remote DNS vulnerability scan."""
    findings = []

    check_recursion(ip, findings)
    check_version_disclosure(ip, findings)
    check_zone_transfer(ip, domain, findings)
    check_dnssec_support(ip, findings)
    check_wildcard_behavior(ip, domain, findings)
    check_nxdomain_resistance(ip, domain, findings)
    check_rebinding_protection(ip, domain, findings)
    # Amplification and tunneling are complex and may require a second phase

    return {
        "ip": ip,
        "domain": domain,
        "findings": findings
    }

def main():
    parser = argparse.ArgumentParser(description="DNS Server Vulnerability Scanner")
    parser.add_argument("--ip", required=True, help="Target DNS server IP address")
    parser.add_argument("--domain", required=True, help="Domain name to use for zone transfer and other checks")
    args = parser.parse_args()

    result = scan_dns(ip=args.ip, domain=args.domain)

    print(json.dumps(result, indent=4))

if __name__ == "__main__":
    main()


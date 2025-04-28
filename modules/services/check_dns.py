#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_dns.py
# Author: Wadih Khairallah
# Description: DNS Vulnerability Scanner for NetRecon
# Updated: 2025-04-28

import random
import string
import dns.resolver
import dns.query
import dns.zone
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.exception
import re
from datetime import datetime, timezone

def is_ip(address):
    ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$|^([a-fA-F0-9:]+:+)+[a-fA-F0-9]+$")
    return bool(ip_pattern.match(address))

def parse_target(target):
    parts = target.strip().lower().split(':')
    host = parts[0]
    port = int(parts[1]) if len(parts) == 2 and parts[1].isdigit() else None
    return host, port

def resolve_a_record(name):
    try:
        name = name.lower().strip()
        a_answers = dns.resolver.resolve(name, 'A')
        return str(a_answers[0])
    except Exception:
        try:
            aaaa_answers = dns.resolver.resolve(name, 'AAAA')
            return str(aaaa_answers[0])
        except Exception:
            return None

def random_domain(base_domain: str) -> str:
    rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    return f"{rand}.{base_domain}"

def check_recursion(ip, port):
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [ip]
        resolver.port = port
        resolver.lifetime = 3
        answer = resolver.resolve('google.com', 'A')
        if answer.rrset:
            return {"status": "fail", "detail": "Open recursion detected: server answers external queries."}
    except dns.resolver.NoNameservers:
        return {"status": "pass", "detail": "Recursion refused (good)."}
    except dns.resolver.Timeout:
        return {"status": "error", "detail": "Timeout during recursion test."}
    except Exception as e:
        return {"status": "error", "detail": f"Recursion test failed: {str(e)}"}
    return {"status": "pass", "detail": "Recursion properly restricted."}

def check_version_disclosure(ip, port):
    try:
        query = dns.message.make_query('version.bind', dns.rdatatype.TXT, dns.rdataclass.CH)
        response = dns.query.udp(query, ip, timeout=3, port=port)
        for answer in response.answer:
            for item in answer.items:
                return {"status": "fail", "detail": f"Version disclosure detected: {item.to_text()}"}
        return {"status": "pass", "detail": "No version disclosure detected."}
    except Exception as e:
        return {"status": "error", "detail": f"Version disclosure check failed: {str(e)}"}

def check_zone_transfer(ip, domain, port):
    try:
        xfr = dns.query.xfr(ip, domain, timeout=5, port=port)
        zone = dns.zone.from_xfr(xfr)
        if zone:
            return {"status": "fail", "detail": f"Zone transfer allowed! {len(zone.nodes.keys())} records leaked."}
    except dns.exception.FormError:
        return {"status": "pass", "detail": "Zone transfer refused (expected)."}
    except dns.exception.Timeout:
        return {"status": "error", "detail": "Timeout during zone transfer test."}
    except Exception as e:
        return {"status": "error", "detail": f"Zone transfer check failed: {str(e)}"}
    return {"status": "pass", "detail": "Zone transfer properly restricted."}

def check_dnssec_support(ip, port):
    try:
        query = dns.message.make_query('dnssec-failed.org', dns.rdatatype.DNSKEY)
        response = dns.query.udp(query, ip, timeout=3, port=port)
        for answer in response.answer:
            if answer.rdtype == dns.rdatatype.DNSKEY:
                return {"status": "pass", "detail": "DNSSEC support detected."}
        return {"status": "fail", "detail": "No DNSSEC support detected."}
    except Exception as e:
        return {"status": "error", "detail": f"DNSSEC support check failed: {str(e)}"}

def check_wildcard_behavior(ip, domain, port):
    random_subdomain = random_domain(domain)
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [ip]
        resolver.port = port
        resolver.lifetime = 3
        answer = resolver.resolve(random_subdomain, 'A')
        if answer.rrset:
            return {"status": "fail", "detail": f"Wildcard DNS behavior detected: {random_subdomain} resolves unexpectedly."}
    except dns.resolver.NXDOMAIN:
        return {"status": "pass", "detail": "No wildcard DNS behavior detected."}
    except Exception as e:
        return {"status": "error", "detail": f"Wildcard test failed: {str(e)}"}

def check_nxdomain_resistance(ip, domain, port):
    random_subdomain = random_domain(domain)
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [ip]
        resolver.port = port
        resolver.lifetime = 3
        resolver.resolve(random_subdomain, 'A')
        return {"status": "fail", "detail": "Server responds to invalid domains (potential NXDOMAIN weakness)."}
    except dns.resolver.NXDOMAIN:
        return {"status": "pass", "detail": "NXDOMAIN properly handled."}
    except Exception as e:
        return {"status": "error", "detail": f"NXDOMAIN resistance check failed: {str(e)}"}

def check_rebinding_protection(ip, domain, port):
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [ip]
        resolver.port = port
        resolver.lifetime = 3
        answer = resolver.resolve(domain, 'A')
        if answer.rrset and answer.rrset.ttl < 300:
            return {"status": "fail", "detail": f"Low TTL detected ({answer.rrset.ttl}s) - may allow DNS rebinding."}
        else:
            return {"status": "pass", "detail": "No DNS rebinding vulnerability detected based on TTL."}
    except Exception as e:
        return {"status": "error", "detail": f"Rebinding protection check failed: {str(e)}"}

def scan_dns(ip: str, domain: str, port: int) -> dict:
    vulnerabilities = {}
    summary = []
    open_service = False

    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [ip]
        resolver.port = port
        resolver.lifetime = 3
        answer = resolver.resolve('google.com', 'A')
        if answer.rrset:
            open_service = True
    except Exception:
        open_service = False
        summary.append("Port not reachable or service unavailable.")

    if open_service:
        vulnerabilities["recursion_test"] = check_recursion(ip, port)
        vulnerabilities["version_disclosure"] = check_version_disclosure(ip, port)
        vulnerabilities["zone_transfer"] = check_zone_transfer(ip, domain, port)
        vulnerabilities["dnssec_support"] = check_dnssec_support(ip, port)
        vulnerabilities["wildcard_dns"] = check_wildcard_behavior(ip, domain, port)
        vulnerabilities["nxdomain_resistance"] = check_nxdomain_resistance(ip, domain, port)
        vulnerabilities["dns_rebinding"] = check_rebinding_protection(ip, domain, port)

    return {
        "target": domain,
        "port": port,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "open": open_service,
        "vulnerabilities": vulnerabilities,
        "summary": summary
    }

def collect(target: str):
    host, port = parse_target(target)
    port = port if port else 53

    if is_ip(host):
        ip = host
        domain = host
    else:
        ip = resolve_a_record(host)
        domain = host
        if not ip:
            return {
                "target": host,
                "port": port,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "open": False,
                "vulnerabilities": {},
                "summary": [f"Failed to resolve IP for {host}"]
            }

    return scan_dns(ip, domain, port)

if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) != 2:
        print("Usage: python3 check_dns.py <target> or <target:port>")
        sys.exit(1)

    target = sys.argv[1]
    result = collect(target)

    print(json.dumps(result, indent=4))


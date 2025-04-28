#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_ldap.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-27 21:34:59

import argparse
import json
import socket
import ssl
from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, ANONYMOUS, SUBTREE

TIMEOUT = 5
LDAP_PORT = 389
LDAPS_PORT = 636

SENSITIVE_ATTRIBUTES = ['userPassword', 'shadowLastChange']

WEAK_CIPHERS = [
    "RC4", "3DES", "NULL", "EXPORT", "DES", "MD5", "PSK", "SRP", "DSS"
]
DEPRECATED_TLS_VERSIONS = ["TLSv1", "TLSv1.1"]

def check_ldap_port(host, port, findings):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        findings.append(f"LDAP port {port}/TCP is open.")
        sock.close()
    except Exception:
        findings.append(f"LDAP port {port}/TCP is closed or filtered.")

def banner_grab(host, port, findings):
    try:
        server = Server(host, port=port, get_info=ALL, connect_timeout=TIMEOUT)
        conn = Connection(server)
        conn.open()
        if server.info and server.info.naming_contexts:
            findings.append(f"LDAP banner on port {port}: Naming Contexts - {server.info.naming_contexts}")
        else:
            findings.append(f"LDAP banner grab succeeded on port {port}, but minimal info retrieved.")
        conn.unbind()
    except Exception:
        findings.append(f"LDAP banner grab failed on port {port}.")

def anonymous_bind_test(host, port, findings):
    try:
        server = Server(host, port=port, connect_timeout=TIMEOUT)
        conn = Connection(server, authentication=ANONYMOUS)
        if conn.bind():
            findings.append(f"Anonymous bind is allowed on LDAP port {port}!")
        else:
            findings.append(f"Anonymous bind rejected on LDAP port {port}.")
        conn.unbind()
    except Exception:
        findings.append(f"Anonymous bind test failed on LDAP port {port}.")

def simple_bind_without_encryption(host, port, findings):
    try:
        server = Server(host, port=port, connect_timeout=TIMEOUT)
        conn = Connection(server, user='fakeuser', password='fakepass', authentication=SIMPLE)
        conn.open()
        conn.bind()
        findings.append(f"Simple bind attempt succeeded over plaintext on LDAP port {port}. (Credentials exposed!)")
        conn.unbind()
    except Exception:
        findings.append(f"Simple bind attempt over plaintext failed (expected behavior).")

def starttls_support_check(host, findings):
    try:
        server = Server(host, port=LDAP_PORT, connect_timeout=TIMEOUT, use_ssl=False)
        conn = Connection(server)
        conn.open()
        if conn.start_tls():
            findings.append("StartTLS is supported and works on LDAP port 389.")
        else:
            findings.append("StartTLS is NOT supported or refused on LDAP port 389.")
        conn.unbind()
    except Exception:
        findings.append("StartTLS support check failed on LDAP port 389.")

def check_ssl_details(host, port, findings):
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(), server_hostname=host)
        conn.settimeout(TIMEOUT)
        conn.connect((host, port))
        cert = conn.getpeercert()

        ssl_version = conn.version()
        cipher = conn.cipher()

        if cert:
            expire_ts = ssl.cert_time_to_seconds(cert['notAfter'])
            import time
            if expire_ts < time.time():
                findings.append(f"Expired SSL certificate detected on LDAPS port {port}.")
            issuer = dict(x[0] for x in cert['issuer'])
            if issuer.get('organizationName', '').lower() == "self-signed":
                findings.append("Self-signed SSL certificate detected on LDAPS server.")

        if ssl_version in DEPRECATED_TLS_VERSIONS:
            findings.append(f"Insecure TLS version {ssl_version} used on LDAPS.")

        if cipher and any(weak in cipher[0] for weak in WEAK_CIPHERS):
            findings.append(f"Weak SSL cipher used by LDAPS server: {cipher[0]}")

        findings.append(f"SSL/TLS in use: {ssl_version} with cipher {cipher[0]}")
        conn.close()
    except Exception as e:
        findings.append(f"SSL/TLS handshake with LDAPS server failed: {str(e)}")

def sensitive_attribute_read_test(host, port, findings):
    try:
        server = Server(host, port=port, get_info=ALL, connect_timeout=TIMEOUT)
        conn = Connection(server, authentication=ANONYMOUS)
        if conn.bind():
            conn.search(search_base='', search_filter='(objectClass=*)', search_scope=SUBTREE, attributes=SENSITIVE_ATTRIBUTES)
            for entry in conn.entries:
                for attribute in SENSITIVE_ATTRIBUTES:
                    if attribute in entry.entry_attributes:
                        findings.append(f"Sensitive attribute {attribute} exposed without authentication!")
            conn.unbind()
    except Exception:
        findings.append(f"Sensitive attribute read test failed on port {port}.")

def scan_ldap(target: str) -> dict:
    findings = []

    parsed_target = target.replace('http://', '').replace('https://', '').split('/')[0]

    # Check LDAP port 389
    check_ldap_port(parsed_target, LDAP_PORT, findings)
    banner_grab(parsed_target, LDAP_PORT, findings)
    anonymous_bind_test(parsed_target, LDAP_PORT, findings)
    simple_bind_without_encryption(parsed_target, LDAP_PORT, findings)
    starttls_support_check(parsed_target, findings)
    sensitive_attribute_read_test(parsed_target, LDAP_PORT, findings)

    # Check LDAPS port 636
    check_ldap_port(parsed_target, LDAPS_PORT, findings)
    banner_grab(parsed_target, LDAPS_PORT, findings)
    check_ssl_details(parsed_target, LDAPS_PORT, findings)

    return {
        "domain": parsed_target,
        "findings": findings
    }

def main():
    parser = argparse.ArgumentParser(description="LDAP/LDAPS Vulnerability Scanner")
    parser.add_argument("--target", required=True, help="Target domain or IP")
    args = parser.parse_args()

    result = scan_ldap(args.target)

    print(json.dumps(result, indent=4))

if __name__ == "__main__":
    main()


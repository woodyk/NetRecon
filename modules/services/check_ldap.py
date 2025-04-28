#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_ldap.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-28 17:45:23
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_ldap.py
# Author: Wadih Khairallah
# Description: LDAP/LDAPS Vulnerability Scanner for NetRecon
# Updated: 2025-04-28

import json
import socket
import ssl
import sys
import re
from ldap3 import Server, Connection, ALL, SIMPLE, ANONYMOUS, SUBTREE
from datetime import datetime, timezone

TIMEOUT = 5
DEFAULT_LDAP_PORT = 389
DEFAULT_LDAPS_PORT = 636

SENSITIVE_ATTRIBUTES = ['userPassword', 'shadowLastChange']
WEAK_CIPHERS = ["RC4", "3DES", "NULL", "EXPORT", "DES", "MD5", "PSK", "SRP", "DSS"]
DEPRECATED_TLS_VERSIONS = ["TLSv1", "TLSv1.1"]

def is_ip(address):
    ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$|^([a-fA-F0-9:]+:+)+[a-fA-F0-9]+$")
    return bool(ip_pattern.match(address))

def parse_target(target):
    parts = target.strip().lower().split(':')
    host = parts[0]
    port = int(parts[1]) if len(parts) == 2 and parts[1].isdigit() else None
    return host, port

def check_port_open(host, port):
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return True
    except Exception:
        return False

def banner_grab(host, port):
    try:
        server = Server(host, port=port, get_info=ALL, connect_timeout=TIMEOUT)
        conn = Connection(server)
        conn.open()
        if server.info and server.info.naming_contexts:
            contexts = server.info.naming_contexts
            conn.unbind()
            return {"status": "info", "detail": f"Naming Contexts: {contexts}"}
        conn.unbind()
        return {"status": "pass", "detail": "LDAP banner grab succeeded but minimal info retrieved."}
    except Exception as e:
        return {"status": "error", "detail": f"LDAP banner grab failed: {str(e)}"}

def anonymous_bind_test(host, port):
    try:
        server = Server(host, port=port, connect_timeout=TIMEOUT)
        conn = Connection(server, authentication=ANONYMOUS)
        if conn.bind():
            conn.unbind()
            return {"status": "fail", "detail": "Anonymous bind allowed on LDAP server!"}
        conn.unbind()
        return {"status": "pass", "detail": "Anonymous bind not allowed."}
    except Exception as e:
        return {"status": "error", "detail": f"Anonymous bind test failed: {str(e)}"}

def simple_bind_without_encryption(host, port):
    try:
        server = Server(host, port=port, connect_timeout=TIMEOUT)
        conn = Connection(server, user='fakeuser', password='fakepass', authentication=SIMPLE)
        conn.open()
        conn.bind()
        conn.unbind()
        return {"status": "fail", "detail": "Simple bind succeeded without encryption (credentials exposed!)."}
    except Exception:
        return {"status": "pass", "detail": "Simple bind without encryption failed (expected)."}

def starttls_support_check(host, port):
    try:
        server = Server(host, port=port, connect_timeout=TIMEOUT, use_ssl=False)
        conn = Connection(server)
        conn.open()
        if conn.start_tls():
            conn.unbind()
            return {"status": "pass", "detail": "StartTLS supported and works."}
        conn.unbind()
        return {"status": "fail", "detail": "StartTLS not supported or refused."}
    except Exception as e:
        return {"status": "error", "detail": f"StartTLS support check failed: {str(e)}"}

def sensitive_attribute_read_test(host, port):
    try:
        server = Server(host, port=port, get_info=ALL, connect_timeout=TIMEOUT)
        conn = Connection(server, authentication=ANONYMOUS)
        if conn.bind():
            conn.search(search_base='', search_filter='(objectClass=*)', search_scope=SUBTREE, attributes=SENSITIVE_ATTRIBUTES)
            for entry in conn.entries:
                for attribute in SENSITIVE_ATTRIBUTES:
                    if attribute in entry.entry_attributes:
                        conn.unbind()
                        return {"status": "fail", "detail": f"Sensitive attribute {attribute} exposed without authentication!"}
            conn.unbind()
            return {"status": "pass", "detail": "No sensitive attributes exposed without authentication."}
        else:
            return {"status": "pass", "detail": "Anonymous bind refused, no attribute exposure."}
    except Exception as e:
        return {"status": "error", "detail": f"Sensitive attribute read test failed: {str(e)}"}

def check_ssl_details(host, port):
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(), server_hostname=host)
        conn.settimeout(TIMEOUT)
        conn.connect((host, port))
        cert = conn.getpeercert()
        ssl_version = conn.version()
        cipher = conn.cipher()

        issues = []
        if cert:
            expire_ts = ssl.cert_time_to_seconds(cert['notAfter'])
            import time
            if expire_ts < time.time():
                issues.append("Expired SSL certificate detected.")
            issuer = dict(x[0] for x in cert['issuer'])
            if issuer.get('organizationName', '').lower() == "self-signed":
                issues.append("Self-signed SSL certificate detected.")

        if ssl_version in DEPRECATED_TLS_VERSIONS:
            issues.append(f"Insecure TLS version {ssl_version} used.")

        if cipher and any(weak in cipher[0] for weak in WEAK_CIPHERS):
            issues.append(f"Weak cipher used: {cipher[0]}")

        conn.close()

        if issues:
            return {"status": "fail", "detail": "; ".join(issues)}
        return {"status": "pass", "detail": f"SSL/TLS in use: {ssl_version} with cipher {cipher[0]}"}
    except Exception as e:
        return {"status": "error", "detail": f"SSL/TLS handshake failed: {str(e)}"}

def collect(target: str):
    host, port = parse_target(target)
    vulnerabilities = {}
    summary = []
    open_ports = []

    ports_to_check = [DEFAULT_LDAP_PORT, DEFAULT_LDAPS_PORT]

    for p in ports_to_check:
        if check_port_open(host, p):
            open_ports.append(p)

    if not open_ports:
        return {
            "target": host,
            "port": ports_to_check,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "open": False,
            "vulnerabilities": {},
            "summary": ["No reachable LDAP/LDAPS ports found."]
        }

    if DEFAULT_LDAP_PORT in open_ports:
        vulnerabilities["ldap_banner"] = banner_grab(host, DEFAULT_LDAP_PORT)
        vulnerabilities["anonymous_bind"] = anonymous_bind_test(host, DEFAULT_LDAP_PORT)
        vulnerabilities["simple_bind_plaintext"] = simple_bind_without_encryption(host, DEFAULT_LDAP_PORT)
        vulnerabilities["starttls_support"] = starttls_support_check(host, DEFAULT_LDAP_PORT)
        vulnerabilities["sensitive_attribute_exposure"] = sensitive_attribute_read_test(host, DEFAULT_LDAP_PORT)

    if DEFAULT_LDAPS_PORT in open_ports:
        vulnerabilities["ldaps_banner"] = banner_grab(host, DEFAULT_LDAPS_PORT)
        vulnerabilities["ldaps_ssl_check"] = check_ssl_details(host, DEFAULT_LDAPS_PORT)

    return {
        "target": host,
        "port": open_ports,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "open": True,
        "vulnerabilities": vulnerabilities,
        "summary": summary
    }

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 check_ldap.py <target> or <target:port>")
        sys.exit(1)

    target = sys.argv[1]
    result = collect(target)

    print(json.dumps(result, indent=4))


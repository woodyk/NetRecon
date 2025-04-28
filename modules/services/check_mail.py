#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_mail.py
# Author: Wadih Khairallah
# Description: Mail Server Vulnerability Scanner for NetRecon
# Updated: 2025-04-28

import socket
import ssl
import json
import dns.resolver
import sys
import re
import time
from datetime import datetime, timezone

DEFAULT_PORTS = {
    "SMTP": [25, 465, 587],
    "POP3": [110, 995],
    "IMAP": [143, 993],
}

WEAK_CIPHERS = ["RC4", "3DES", "NULL", "EXPORT", "DES", "MD5", "PSK", "SRP", "DSS"]
DEPRECATED_TLS_VERSIONS = ["TLSv1", "TLSv1.1"]

TIMEOUT = 5

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

def grab_banner(host, port, use_ssl=False):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        if use_ssl:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
        banner = sock.recv(1024).decode(errors='ignore').strip()
        sock.close()
        return {"status": "info", "detail": f"Banner on port {port}: {banner}"}
    except Exception as e:
        return {"status": "error", "detail": f"Failed to grab banner on port {port}: {str(e)}"}

def starttls_supported(host, port, protocol):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        sock.settimeout(TIMEOUT)
        sock.recv(1024)

        if protocol == "SMTP":
            sock.sendall(b"EHLO test.local\r\n")
        elif protocol == "POP3":
            sock.sendall(b"CAPA\r\n")
        elif protocol == "IMAP":
            sock.sendall(b". CAPABILITY\r\n")

        data = sock.recv(4096).decode(errors='ignore')
        sock.close()
        if "STARTTLS" in data.upper():
            return {"status": "pass", "detail": f"{protocol} STARTTLS supported on port {port}."}
        else:
            return {"status": "fail", "detail": f"{protocol} STARTTLS not supported on port {port}."}
    except Exception as e:
        return {"status": "error", "detail": f"STARTTLS check failed on port {port}: {str(e)}"}

def check_ssl_details(host, port):
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(), server_hostname=host)
        conn.settimeout(TIMEOUT)
        conn.connect((host, port))
        cert = conn.getpeercert()
        ssl_version = conn.version()
        cipher = conn.cipher()
        conn.close()

        issues = []

        if cert:
            expire_ts = ssl.cert_time_to_seconds(cert['notAfter'])
            if expire_ts < time.time():
                issues.append("Expired SSL certificate.")
        
        if ssl_version in DEPRECATED_TLS_VERSIONS:
            issues.append(f"Insecure TLS version: {ssl_version}")

        if cipher and any(weak in cipher[0] for weak in WEAK_CIPHERS):
            issues.append(f"Weak cipher detected: {cipher[0]}")

        if issues:
            return {"status": "fail", "detail": "; ".join(issues)}
        return {"status": "pass", "detail": f"SSL/TLS looks strong: {ssl_version} with cipher {cipher[0]}"}
    except Exception as e:
        return {"status": "error", "detail": f"SSL/TLS check failed: {str(e)}"}

def test_open_relay(host):
    try:
        sock = socket.create_connection((host, 25), timeout=TIMEOUT)
        sock.recv(1024)
        sock.sendall(b"HELO test.local\r\n")
        sock.recv(1024)
        sock.sendall(b"MAIL FROM:<test@test.local>\r\n")
        sock.recv(1024)
        sock.sendall(b"RCPT TO:<test@externaldomain.com>\r\n")
        response = sock.recv(1024).decode(errors='ignore')
        sock.sendall(b"QUIT\r\n")
        sock.close()
        if "relaying denied" not in response.lower() and "authentication required" not in response.lower():
            return {"status": "fail", "detail": "Possible SMTP open relay detected on port 25."}
        return {"status": "pass", "detail": "SMTP relay properly restricted."}
    except Exception as e:
        return {"status": "error", "detail": f"SMTP open relay check failed: {str(e)}"}

def check_auth_mechanisms(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        sock.recv(1024)
        sock.sendall(b"EHLO test.local\r\n")
        data = sock.recv(4096).decode(errors='ignore')
        sock.close()
        if "AUTH" in data.upper():
            if "PLAIN" in data.upper():
                return {"status": "fail", "detail": f"Plaintext SMTP authentication supported on port {port}."}
            else:
                return {"status": "info", "detail": f"SMTP authentication methods detected on port {port}."}
        return {"status": "pass", "detail": "No SMTP authentication methods exposed."}
    except Exception as e:
        return {"status": "error", "detail": f"SMTP authentication mechanism check failed: {str(e)}"}

def check_mta_sts(domain):
    try:
        records = dns.resolver.resolve(f"_mta-sts.{domain}", 'TXT')
        if records:
            return {"status": "pass", "detail": "MTA-STS policy found in DNS."}
    except Exception:
        return {"status": "fail", "detail": "No MTA-STS policy found."}

def check_tls_reporting(domain):
    try:
        records = dns.resolver.resolve(f"_smtp._tls.{domain}", 'TXT')
        if records:
            return {"status": "pass", "detail": "TLS-RPT policy found in DNS."}
    except Exception:
        return {"status": "fail", "detail": "No TLS-RPT policy found."}

def collect(target: str):
    host, port = parse_target(target)
    vulnerabilities = {}
    summary = []
    open_ports = []

    for protocol, ports in DEFAULT_PORTS.items():
        for p in ports:
            if check_port_open(host, p):
                open_ports.append(p)
                use_ssl = p in [465, 993, 995]
                vulnerabilities[f"{protocol.lower()}_banner_{p}"] = grab_banner(host, p, use_ssl=use_ssl)
                if use_ssl:
                    vulnerabilities[f"{protocol.lower()}_ssl_details_{p}"] = check_ssl_details(host, p)
                else:
                    vulnerabilities[f"{protocol.lower()}_starttls_{p}"] = starttls_supported(host, p, protocol)

    if not open_ports:
        return {
            "target": host,
            "port": [port for ports in DEFAULT_PORTS.values() for port in ports],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "open": False,
            "vulnerabilities": {},
            "summary": ["No reachable SMTP/POP3/IMAP ports found."]
        }

    vulnerabilities["smtp_open_relay_test"] = test_open_relay(host)
    vulnerabilities["smtp_auth_mechanisms_check"] = check_auth_mechanisms(host, 25)
    vulnerabilities["mta_sts_check"] = check_mta_sts(host)
    vulnerabilities["tls_rpt_check"] = check_tls_reporting(host)

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
        print("Usage: python3 check_mail.py <target> or <target:port>")
        sys.exit(1)

    target = sys.argv[1]
    result = collect(target)

    print(json.dumps(result, indent=4))


#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_mail.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-27 21:22:50
# Modified: 2025-04-27 21:34:39

import argparse
import socket
import ssl
import json
import base64
import dns.resolver

DEFAULT_PORTS = {
    "SMTP": [25, 465, 587],
    "POP3": [110, 995],
    "IMAP": [143, 993],
}

WEAK_CIPHERS = [
    "RC4", "3DES", "NULL", "EXPORT", "DES", "MD5", "PSK", "SRP", "DSS"
]

DEPRECATED_TLS_VERSIONS = ["TLSv1", "TLSv1.1"]

TIMEOUT = 5

def grab_banner(host, port, use_ssl=False):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        if use_ssl:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
        banner = sock.recv(1024).decode(errors='ignore').strip()
        sock.close()
        return banner
    except Exception:
        return None

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
        return "STARTTLS" in data.upper()
    except Exception:
        return False

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
                findings.append(f"Expired SSL certificate detected on port {port}.")
        
        if ssl_version in DEPRECATED_TLS_VERSIONS:
            findings.append(f"Insecure TLS version {ssl_version} detected on port {port}.")

        if cipher and any(weak in cipher[0] for weak in WEAK_CIPHERS):
            findings.append(f"Weak cipher suite detected on port {port}: {cipher[0]}")

        conn.close()
    except Exception as e:
        findings.append(f"SSL details check failed on port {port}: {str(e)}")

def test_open_relay(host, findings):
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
            findings.append("Possible SMTP open relay detected on port 25.")
    except Exception:
        findings.append("SMTP open relay check failed on port 25.")

def check_auth_mechanisms(host, port, findings):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        sock.recv(1024)
        sock.sendall(b"EHLO test.local\r\n")
        data = sock.recv(4096).decode(errors='ignore')
        if "AUTH" in data.upper():
            findings.append(f"SMTP authentication methods exposed on port {port}: {data.strip()}")
            if "PLAIN" in data.upper() and port in [25, 587]:
                findings.append(f"Plaintext SMTP authentication supported without implicit TLS on port {port}.")
        sock.close()
    except Exception:
        findings.append(f"SMTP authentication mechanism check failed on port {port}.")

def check_mta_sts(domain, findings):
    try:
        records = dns.resolver.resolve(f"_mta-sts.{domain}", 'TXT')
        if records:
            findings.append("MTA-STS policy found in DNS.")
    except Exception:
        findings.append("No MTA-STS policy found.")

def check_tls_reporting(domain, findings):
    try:
        records = dns.resolver.resolve(f"_smtp._tls.{domain}", 'TXT')
        if records:
            findings.append("TLS reporting (TLS-RPT) policy found in DNS.")
    except Exception:
        findings.append("No TLS-RPT policy found.")

def scan_mail(target: str) -> dict:
    findings = []

    parsed_target = target.replace('http://', '').replace('https://', '').split('/')[0]

    for protocol, ports in DEFAULT_PORTS.items():
        for port in ports:
            use_ssl = port in [465, 993, 995]
            banner = grab_banner(parsed_target, port, use_ssl=use_ssl)
            if banner:
                findings.append(f"{protocol} banner on port {port}: {banner}")

            if use_ssl:
                check_ssl_details(parsed_target, port, findings)
            else:
                if protocol in ["SMTP", "POP3", "IMAP"]:
                    if starttls_supported(parsed_target, port, protocol):
                        findings.append(f"{protocol} STARTTLS supported on port {port}.")
                    else:
                        findings.append(f"{protocol} STARTTLS NOT supported on port {port}.")

    # Special checks
    test_open_relay(parsed_target, findings)
    check_auth_mechanisms(parsed_target, 25, findings)
    check_mta_sts(parsed_target, findings)
    check_tls_reporting(parsed_target, findings)

    return {
        "domain": parsed_target,
        "findings": findings
    }

def main():
    parser = argparse.ArgumentParser(description="Mail Server Vulnerability Scanner (SMTP, POP3, IMAP)")
    parser.add_argument("--target", required=True, help="Target domain or IP")
    args = parser.parse_args()

    result = scan_mail(args.target)

    print(json.dumps(result, indent=4))

if __name__ == "__main__":
    main()


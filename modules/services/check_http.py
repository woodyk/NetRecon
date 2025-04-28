#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_http.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-27 21:08:31
# Modified: 2025-04-27 21:34:50

import argparse
import json
import ssl
import socket
import requests
import dns.resolver
from urllib.parse import urljoin, urlparse

requests.packages.urllib3.disable_warnings()

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

WEAK_CIPHERS = [
    "RC4", "3DES", "NULL", "EXPORT", "DES", "MD5", "PSK", "SRP", "DSS"
]

DEPRECATED_TLS_VERSIONS = ["TLSv1", "TLSv1.1"]

COMMON_FILES = [
    "robots.txt", ".git/", ".env", ".DS_Store", ".htaccess", "config.php"
]

def get_http_banner(url, findings):
    try:
        response = requests.head(url, timeout=5, allow_redirects=True, verify=False)
        server = response.headers.get('Server')
        powered_by = response.headers.get('X-Powered-By')
        if server:
            findings.append(f"Server header present: {server}")
        if powered_by:
            findings.append(f"X-Powered-By header present: {powered_by}")
    except Exception as e:
        findings.append(f"HTTP banner grabbing failed: {str(e)}")

def check_tls_certificate(hostname, findings):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as sock:
            sock.settimeout(5)
            sock.connect((hostname, 443))
            cert = sock.getpeercert()

            if cert:
                expire_ts = ssl.cert_time_to_seconds(cert['notAfter'])
                import time
                if expire_ts < time.time():
                    findings.append("Expired SSL certificate detected.")
                subject = dict(x[0] for x in cert['subject'])
                findings.append(f"SSL Certificate Common Name: {subject.get('commonName')}")
    except Exception as e:
        findings.append(f"TLS certificate check failed: {str(e)}")

def check_tls_ciphers(hostname, findings):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as sock:
            sock.settimeout(5)
            sock.connect((hostname, 443))
            cipher = sock.cipher()
            if cipher:
                cipher_name = cipher[0]
                findings.append(f"SSL Cipher in use: {cipher_name}")
                if any(weak in cipher_name for weak in WEAK_CIPHERS):
                    findings.append(f"Weak SSL cipher detected: {cipher_name}")
    except Exception as e:
        findings.append(f"TLS cipher check failed: {str(e)}")

def check_tls_version(hostname, findings):
    try:
        sock = socket.create_connection((hostname, 443), timeout=5)
        context = ssl.create_default_context()
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            version = ssock.version()
            if version in DEPRECATED_TLS_VERSIONS:
                findings.append(f"Insecure TLS version detected: {version}")
            findings.append(f"TLS version in use: {version}")
    except Exception as e:
        findings.append(f"TLS version check failed: {str(e)}")

def check_security_headers(url, findings):
    try:
        response = requests.get(url, timeout=5, verify=False)
        for header in SECURITY_HEADERS:
            if header not in response.headers:
                findings.append(f"Missing security header: {header}")
    except Exception as e:
        findings.append(f"Security headers check failed: {str(e)}")

def check_directory_listing(url, findings):
    try:
        response = requests.get(url, timeout=5, verify=False)
        if "Index of /" in response.text and response.status_code == 200:
            findings.append("Potential directory listing exposure detected.")
    except Exception as e:
        findings.append(f"Directory listing check failed: {str(e)}")

def check_default_files(url, findings):
    for file in COMMON_FILES:
        try:
            full_url = urljoin(url, file)
            response = requests.get(full_url, timeout=5, verify=False)
            if response.status_code == 200:
                findings.append(f"Sensitive file or directory exposed: {file}")
        except Exception:
            continue

def check_open_redirect(url, findings):
    try:
        parsed = urlparse(url)
        redirect_test_url = urljoin(url, "/redirect?url=https://example.com")
        response = requests.get(redirect_test_url, timeout=5, allow_redirects=False, verify=False)
        location = response.headers.get('Location')
        if location and "example.com" in location:
            findings.append("Potential open redirect vulnerability detected.")
    except Exception as e:
        findings.append(f"Open redirect check failed: {str(e)}")

def check_allowed_methods(url, findings):
    try:
        response = requests.options(url, timeout=5, verify=False)
        methods = response.headers.get('Allow')
        if methods:
            allowed = [m.strip() for m in methods.split(',')]
            findings.append(f"Allowed HTTP methods: {', '.join(allowed)}")
            dangerous = set(allowed).intersection({'PUT', 'DELETE', 'TRACE', 'CONNECT'})
            if dangerous:
                findings.append(f"Dangerous HTTP methods enabled: {', '.join(dangerous)}")
    except Exception as e:
        findings.append(f"Allowed methods check failed: {str(e)}")

def check_http_to_https_redirect(domain, findings):
    try:
        http_url = f"http://{domain}"
        response = requests.get(http_url, timeout=5, allow_redirects=False)
        location = response.headers.get('Location')
        if location and location.startswith('https://'):
            findings.append("HTTP to HTTPS redirection is correctly configured.")
        else:
            findings.append("HTTP to HTTPS redirection missing or misconfigured.")
    except Exception as e:
        findings.append(f"HTTP to HTTPS redirection check failed: {str(e)}")

def check_spf_dmarc(domain, findings):
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        spf_found = any('v=spf1' in str(r) for r in txt_records)
        dmarc_found = any('v=DMARC1' in str(r) for r in txt_records)
        if not spf_found:
            findings.append("SPF record missing in DNS.")
        if not dmarc_found:
            findings.append("DMARC record missing in DNS.")
    except Exception as e:
        findings.append(f"SPF/DMARC check failed: {str(e)}")

def check_websocket_upgrade(url, findings):
    try:
        response = requests.get(url, timeout=5, verify=False)
        if 'Upgrade' in response.headers and 'websocket' in response.headers.get('Upgrade', '').lower():
            findings.append("WebSocket upgrade detected in headers.")
    except Exception as e:
        findings.append(f"WebSocket upgrade check failed: {str(e)}")

def check_http2_support(domain, findings):
    try:
        conn = socket.create_connection((domain, 443), timeout=5)
        context = ssl.create_default_context()
        with context.wrap_socket(conn, server_hostname=domain) as sock:
            negotiated = sock.selected_alpn_protocol()
            if negotiated == 'h2':
                findings.append("HTTP/2 protocol supported (ALPN h2 negotiated).")
            elif not negotiated:
                findings.append("No ALPN protocol negotiated (HTTP/1.1 assumed).")
    except Exception as e:
        findings.append(f"HTTP/2 support check failed: {str(e)}")

def scan_http(target: str) -> dict:
    """Comprehensive HTTP/HTTPS network vulnerability scan."""
    findings = []

    if not target.startswith("http"):
        target = "http://" + target

    parsed = urlparse(target)
    domain = parsed.hostname

    urls_to_scan = [f"http://{domain}", f"https://{domain}"]

    for url in urls_to_scan:
        get_http_banner(url, findings)
        check_security_headers(url, findings)
        check_directory_listing(url, findings)
        check_default_files(url, findings)
        check_open_redirect(url, findings)
        check_allowed_methods(url, findings)
        check_websocket_upgrade(url, findings)

    try:
        check_tls_certificate(domain, findings)
        check_tls_ciphers(domain, findings)
        check_tls_version(domain, findings)
        check_http2_support(domain, findings)
    except Exception:
        pass

    check_spf_dmarc(domain, findings)
    check_http_to_https_redirect(domain, findings)

    return {
        "domain": domain,
        "findings": findings
    }

def main():
    parser = argparse.ArgumentParser(description="Network-Level HTTP/HTTPS Vulnerability Scanner")
    parser.add_argument("--target", required=True, help="Target domain or IP")
    args = parser.parse_args()

    result = scan_http(args.target)

    print(json.dumps(result, indent=4))

if __name__ == "__main__":
    main()


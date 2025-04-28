#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_http.py
# Author: Wadih Khairallah
# Description: HTTP/HTTPS Vulnerability Scanner for NetRecon
# Updated: 2025-04-28

import json
import ssl
import socket
import requests
import dns.resolver
from urllib.parse import urljoin, urlparse
import re
import sys
from datetime import datetime, timezone

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
        with socket.create_connection((host, port), timeout=3):
            return True
    except Exception:
        return False

def get_http_banner(url):
    try:
        response = requests.head(url, timeout=5, allow_redirects=True, verify=False)
        server = response.headers.get('Server')
        powered_by = response.headers.get('X-Powered-By')
        details = []
        if server:
            details.append(f"Server: {server}")
        if powered_by:
            details.append(f"X-Powered-By: {powered_by}")
        if details:
            return {"status": "info", "detail": "; ".join(details)}
    except Exception as e:
        return {"status": "error", "detail": f"HTTP banner grabbing failed: {str(e)}"}
    return {"status": "error", "detail": "No server/banner information found."}

def check_tls_certificate(hostname):
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
                    return {"status": "fail", "detail": "Expired SSL certificate detected."}
                subject = dict(x[0] for x in cert['subject'])
                return {"status": "pass", "detail": f"SSL Certificate CN: {subject.get('commonName', 'N/A')}"}
    except Exception as e:
        return {"status": "error", "detail": f"TLS certificate check failed: {str(e)}"}

def check_tls_ciphers(hostname):
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
                if any(weak in cipher_name for weak in WEAK_CIPHERS):
                    return {"status": "fail", "detail": f"Weak SSL cipher detected: {cipher_name}"}
                return {"status": "pass", "detail": f"Cipher used: {cipher_name}"}
    except Exception as e:
        return {"status": "error", "detail": f"TLS cipher check failed: {str(e)}"}

def check_tls_version(hostname):
    try:
        sock = socket.create_connection((hostname, 443), timeout=5)
        context = ssl.create_default_context()
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            version = ssock.version()
            if version in DEPRECATED_TLS_VERSIONS:
                return {"status": "fail", "detail": f"Insecure TLS version detected: {version}"}
            return {"status": "pass", "detail": f"TLS version: {version}"}
    except Exception as e:
        return {"status": "error", "detail": f"TLS version check failed: {str(e)}"}

def check_security_headers(url):
    try:
        response = requests.get(url, timeout=5, verify=False)
        missing = []
        for header in SECURITY_HEADERS:
            if header not in response.headers:
                missing.append(header)
        if missing:
            return {"status": "fail", "detail": f"Missing headers: {', '.join(missing)}"}
        return {"status": "pass", "detail": "All standard security headers present."}
    except Exception as e:
        return {"status": "error", "detail": f"Security headers check failed: {str(e)}"}

def check_directory_listing(url):
    try:
        response = requests.get(url, timeout=5, verify=False)
        if "Index of /" in response.text and response.status_code == 200:
            return {"status": "fail", "detail": "Potential directory listing exposure detected."}
    except Exception as e:
        return {"status": "error", "detail": f"Directory listing check failed: {str(e)}"}
    return {"status": "pass", "detail": "No directory listing exposed."}

def check_default_files(url):
    exposures = []
    for file in COMMON_FILES:
        try:
            full_url = urljoin(url, file)
            response = requests.get(full_url, timeout=5, verify=False)
            if response.status_code == 200:
                exposures.append(file)
        except Exception:
            continue
    if exposures:
        return {"status": "fail", "detail": f"Exposed sensitive files: {', '.join(exposures)}"}
    return {"status": "pass", "detail": "No sensitive files exposed."}

def check_open_redirect(url):
    try:
        parsed = urlparse(url)
        redirect_test_url = urljoin(url, "/redirect?url=https://example.com")
        response = requests.get(redirect_test_url, timeout=5, allow_redirects=False, verify=False)
        location = response.headers.get('Location')
        if location and "example.com" in location:
            return {"status": "fail", "detail": "Potential open redirect vulnerability detected."}
    except Exception as e:
        return {"status": "error", "detail": f"Open redirect check failed: {str(e)}"}
    return {"status": "pass", "detail": "No open redirect detected."}

def check_allowed_methods(url):
    try:
        response = requests.options(url, timeout=5, verify=False)
        methods = response.headers.get('Allow')
        if methods:
            allowed = [m.strip() for m in methods.split(',')]
            dangerous = set(allowed).intersection({'PUT', 'DELETE', 'TRACE', 'CONNECT'})
            if dangerous:
                return {"status": "fail", "detail": f"Dangerous methods enabled: {', '.join(dangerous)}"}
            return {"status": "pass", "detail": f"Allowed methods: {', '.join(allowed)}"}
    except Exception as e:
        return {"status": "error", "detail": f"Allowed methods check failed: {str(e)}"}
    return {"status": "error", "detail": "Could not retrieve allowed HTTP methods."}

def check_http_to_https_redirect(domain):
    try:
        http_url = f"http://{domain}"
        response = requests.get(http_url, timeout=5, allow_redirects=False)
        location = response.headers.get('Location')
        if location and location.startswith('https://'):
            return {"status": "pass", "detail": "HTTP to HTTPS redirection configured."}
        else:
            return {"status": "fail", "detail": "HTTP to HTTPS redirection missing or misconfigured."}
    except Exception as e:
        return {"status": "error", "detail": f"HTTP to HTTPS redirection check failed: {str(e)}"}

def check_spf_dmarc(domain):
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        spf_found = any('v=spf1' in str(r) for r in txt_records)
        dmarc_found = any('v=DMARC1' in str(r) for r in txt_records)
        if not spf_found or not dmarc_found:
            missing = []
            if not spf_found:
                missing.append("SPF")
            if not dmarc_found:
                missing.append("DMARC")
            return {"status": "fail", "detail": f"Missing DNS records: {', '.join(missing)}"}
        return {"status": "pass", "detail": "SPF and DMARC records found."}
    except Exception as e:
        return {"status": "error", "detail": f"SPF/DMARC check failed: {str(e)}"}

def check_websocket_upgrade(url):
    try:
        response = requests.get(url, timeout=5, verify=False)
        if 'Upgrade' in response.headers and 'websocket' in response.headers.get('Upgrade', '').lower():
            return {"status": "info", "detail": "WebSocket upgrade supported."}
    except Exception as e:
        return {"status": "error", "detail": f"WebSocket upgrade check failed: {str(e)}"}
    return {"status": "pass", "detail": "No WebSocket upgrade headers detected."}

def check_http2_support(domain):
    try:
        conn = socket.create_connection((domain, 443), timeout=5)
        context = ssl.create_default_context()
        with context.wrap_socket(conn, server_hostname=domain) as sock:
            negotiated = sock.selected_alpn_protocol()
            if negotiated == 'h2':
                return {"status": "pass", "detail": "HTTP/2 supported."}
            return {"status": "fail", "detail": "HTTP/2 not supported."}
    except Exception as e:
        return {"status": "error", "detail": f"HTTP/2 support check failed: {str(e)}"}

# --- COLLECT ---
def collect(target: str):
    host, custom_port = parse_target(target)
    ports = [custom_port] if custom_port else [80, 443]
    open_ports = []
    vulnerabilities = {}
    summary = []

    for port in ports:
        if check_port_open(host, port):
            open_ports.append(port)

    if not open_ports:
        return {
            "target": host,
            "port": ports,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "open": False,
            "vulnerabilities": {},
            "summary": ["No reachable HTTP/HTTPS ports found."]
        }

    urls = []
    if 80 in open_ports:
        urls.append(f"http://{host}")
    if 443 in open_ports:
        urls.append(f"https://{host}")

    for url in urls:
        vulnerabilities["http_banner"] = get_http_banner(url)
        vulnerabilities["http_security_headers"] = check_security_headers(url)
        vulnerabilities["directory_listing_test"] = check_directory_listing(url)
        vulnerabilities["sensitive_file_exposure"] = check_default_files(url)
        vulnerabilities["open_redirect_test"] = check_open_redirect(url)
        vulnerabilities["allowed_http_methods"] = check_allowed_methods(url)
        vulnerabilities["websocket_upgrade_check"] = check_websocket_upgrade(url)

    vulnerabilities["tls_certificate_check"] = check_tls_certificate(host)
    vulnerabilities["tls_cipher_strength"] = check_tls_ciphers(host)
    vulnerabilities["tls_version_check"] = check_tls_version(host)
    vulnerabilities["spf_dmarc_check"] = check_spf_dmarc(host)
    vulnerabilities["http_to_https_redirect"] = check_http_to_https_redirect(host)
    vulnerabilities["http2_support_check"] = check_http2_support(host)

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
        print("Usage: python3 check_http.py <target> or <target:port>")
        sys.exit(1)

    target = sys.argv[1]
    result = collect(target)

    print(json.dumps(result, indent=4))


#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_ftp.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-27 21:24:44

# modules/check_ftp.py

import argparse
import json
import socket
import ssl
from ftplib import FTP, FTP_TLS, error_perm

TIMEOUT = 5
FTP_PORTS = [21, 990]  # 21 = FTP, 990 = FTPS implicit

WEAK_CIPHERS = [
    "RC4", "3DES", "NULL", "EXPORT", "DES", "MD5", "PSK", "SRP", "DSS"
]

DEPRECATED_TLS_VERSIONS = ["TLSv1", "TLSv1.1"]

def grab_banner(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        banner = sock.recv(1024).decode(errors='ignore').strip()
        sock.close()
        return banner
    except Exception:
        return None

def check_anonymous_login(host, port, findings):
    try:
        ftp = FTP()
        ftp.connect(host, port, timeout=TIMEOUT)
        resp = ftp.login()
        if '230' in resp:
            findings.append(f"Anonymous login allowed on port {port}.")
        ftp.quit()
    except error_perm:
        findings.append(f"Anonymous login denied on port {port}.")
    except Exception:
        findings.append(f"Anonymous login check failed on port {port}.")

def check_ftps_support(host, findings):
    try:
        ftps = FTP_TLS()
        ftps.connect(host, 21, timeout=TIMEOUT)
        resp = ftps.sendcmd('FEAT')
        if "AUTH TLS" in resp or "AUTH SSL" in resp:
            findings.append("Explicit FTPS (AUTH TLS) supported on FTP port 21.")
        ftps.quit()
    except Exception:
        findings.append("Explicit FTPS (AUTH TLS) not supported on FTP port 21.")

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

            issuer = dict(x[0] for x in cert['issuer'])
            if issuer.get('organizationName', '').lower() == "self-signed":
                findings.append(f"Self-signed SSL certificate detected on port {port}.")

        if ssl_version in DEPRECATED_TLS_VERSIONS:
            findings.append(f"Insecure TLS version {ssl_version} detected on port {port}.")

        if cipher and any(weak in cipher[0] for weak in WEAK_CIPHERS):
            findings.append(f"Weak SSL cipher suite detected on port {port}: {cipher[0]}")

        conn.close()
    except Exception as e:
        findings.append(f"SSL certificate/cipher check failed on port {port}: {str(e)}")

def check_pasv_support(host, port, findings):
    try:
        ftp = FTP()
        ftp.connect(host, port, timeout=TIMEOUT)
        ftp.login('anonymous', 'anonymous@example.com')
        resp = ftp.sendcmd('PASV')
        if '227' in resp:
            findings.append(f"Passive mode (PASV) supported on port {port}.")
        ftp.quit()
    except Exception:
        findings.append(f"Passive mode support check failed on port {port}.")

def check_active_support(host, port, findings):
    try:
        ftp = FTP()
        ftp.connect(host, port, timeout=TIMEOUT)
        ftp.login('anonymous', 'anonymous@example.com')
        try:
            ftp.sendcmd('PORT 127,0,0,1,7,138')  # harmless dummy PORT command
            findings.append(f"Active mode (PORT) appears accepted on port {port}.")
        except error_perm:
            findings.append(f"Active mode (PORT) rejected on port {port}.")
        ftp.quit()
    except Exception:
        findings.append(f"Active mode support check failed on port {port}.")

def check_directory_traversal(host, port, findings):
    try:
        ftp = FTP()
        ftp.connect(host, port, timeout=TIMEOUT)
        ftp.login('anonymous', 'anonymous@example.com')
        try:
            ftp.cwd('../../')
            findings.append(f"Possible directory traversal allowed on port {port}.")
        except error_perm:
            findings.append(f"No directory traversal allowed on port {port}.")
        ftp.quit()
    except Exception:
        findings.append(f"Directory traversal check failed on port {port}.")

def scan_ftp(target: str) -> dict:
    findings = []

    parsed_target = target.replace('http://', '').replace('https://', '').split('/')[0]

    for port in FTP_PORTS:
        banner = grab_banner(parsed_target, port)
        if banner:
            findings.append(f"FTP banner on port {port}: {banner}")

        if port == 21:
            check_anonymous_login(parsed_target, port, findings)
            check_ftps_support(parsed_target, findings)
            check_pasv_support(parsed_target, port, findings)
            check_active_support(parsed_target, port, findings)
            check_directory_traversal(parsed_target, port, findings)

        if port == 990:  # FTPS implicit
            check_ssl_details(parsed_target, port, findings)

    return {
        "domain": parsed_target,
        "findings": findings
    }

def main():
    parser = argparse.ArgumentParser(description="FTP/FTPS Vulnerability Scanner")
    parser.add_argument("--target", required=True, help="Target domain or IP")
    args = parser.parse_args()

    result = scan_ftp(args.target)

    print(json.dumps(result, indent=4))

if __name__ == "__main__":
    main()


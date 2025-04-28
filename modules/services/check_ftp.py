#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_ftp.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-28 17:24:40
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_ftp.py
# Author: Wadih Khairallah
# Description: FTP/FTPS Vulnerability Scanner for NetRecon
# Updated: 2025-04-28

import socket
import ssl
from ftplib import FTP, FTP_TLS, error_perm
import json
import sys
import re
from datetime import datetime, timezone

TIMEOUT = 5
DEFAULT_PORTS = [21, 990]  # 21 = FTP, 990 = FTPS (Implicit)

WEAK_CIPHERS = [
    "RC4", "3DES", "NULL", "EXPORT", "DES", "MD5", "PSK", "SRP", "DSS"
]

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

def grab_banner(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        banner = sock.recv(1024).decode(errors='ignore').strip()
        sock.close()
        if banner:
            return {"status": "info", "detail": f"FTP banner on port {port}: {banner}"}
    except Exception as e:
        return {"status": "error", "detail": f"Failed to grab FTP banner on port {port}: {str(e)}"}
    return {"status": "error", "detail": f"No banner received on port {port}"}

def check_anonymous_login(host, port):
    try:
        ftp = FTP()
        ftp.connect(host, port, timeout=TIMEOUT)
        resp = ftp.login()
        ftp.quit()
        if '230' in resp:
            return {"status": "fail", "detail": f"Anonymous login allowed on port {port}."}
        else:
            return {"status": "pass", "detail": f"Anonymous login denied on port {port}."}
    except error_perm:
        return {"status": "pass", "detail": f"Anonymous login denied on port {port}."}
    except Exception as e:
        return {"status": "error", "detail": f"Anonymous login check failed on port {port}: {str(e)}"}

def check_ftps_support(host):
    try:
        ftps = FTP_TLS()
        ftps.connect(host, 21, timeout=TIMEOUT)
        resp = ftps.sendcmd('FEAT')
        ftps.quit()
        if "AUTH TLS" in resp or "AUTH SSL" in resp:
            return {"status": "pass", "detail": "Explicit FTPS (AUTH TLS) supported on FTP port 21."}
        return {"status": "fail", "detail": "Explicit FTPS (AUTH TLS) not supported on FTP port 21."}
    except Exception as e:
        return {"status": "error", "detail": f"FTPS support check failed: {str(e)}"}

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

        details = []

        if cert:
            expire_ts = ssl.cert_time_to_seconds(cert['notAfter'])
            import time
            if expire_ts < time.time():
                details.append("Expired SSL certificate detected.")
            issuer = dict(x[0] for x in cert['issuer'])
            if issuer.get('organizationName', '').lower() == "self-signed":
                details.append("Self-signed SSL certificate detected.")

        if ssl_version in DEPRECATED_TLS_VERSIONS:
            details.append(f"Insecure TLS version {ssl_version} detected.")

        if cipher and any(weak in cipher[0] for weak in WEAK_CIPHERS):
            details.append(f"Weak SSL cipher suite detected: {cipher[0]}")

        if details:
            return {"status": "fail", "detail": "; ".join(details)}
        return {"status": "pass", "detail": "SSL/TLS configuration appears strong."}
    except Exception as e:
        return {"status": "error", "detail": f"SSL/TLS check failed on port {port}: {str(e)}"}

def check_pasv_support(host, port):
    try:
        ftp = FTP()
        ftp.connect(host, port, timeout=TIMEOUT)
        ftp.login('anonymous', 'anonymous@example.com')
        resp = ftp.sendcmd('PASV')
        ftp.quit()
        if '227' in resp:
            return {"status": "pass", "detail": f"Passive mode (PASV) supported on port {port}."}
        return {"status": "fail", "detail": f"Passive mode (PASV) not supported on port {port}."}
    except Exception as e:
        return {"status": "error", "detail": f"Passive mode check failed on port {port}: {str(e)}"}

def check_active_support(host, port):
    try:
        ftp = FTP()
        ftp.connect(host, port, timeout=TIMEOUT)
        ftp.login('anonymous', 'anonymous@example.com')
        try:
            ftp.sendcmd('PORT 127,0,0,1,7,138')
            ftp.quit()
            return {"status": "pass", "detail": f"Active mode (PORT) accepted on port {port}."}
        except error_perm:
            ftp.quit()
            return {"status": "fail", "detail": f"Active mode (PORT) rejected on port {port}."}
    except Exception as e:
        return {"status": "error", "detail": f"Active mode check failed on port {port}: {str(e)}"}

def check_directory_traversal(host, port):
    try:
        ftp = FTP()
        ftp.connect(host, port, timeout=TIMEOUT)
        ftp.login('anonymous', 'anonymous@example.com')
        try:
            ftp.cwd('../../')
            ftp.quit()
            return {"status": "fail", "detail": f"Possible directory traversal allowed on port {port}."}
        except error_perm:
            ftp.quit()
            return {"status": "pass", "detail": f"No directory traversal allowed on port {port}."}
    except Exception as e:
        return {"status": "error", "detail": f"Directory traversal check failed on port {port}: {str(e)}"}

# --- COLLECT ---
def collect(target: str):
    host, custom_port = parse_target(target)
    ports = [custom_port] if custom_port else DEFAULT_PORTS
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
            "summary": ["No reachable FTP/FTPS ports found."]
        }

    for port in open_ports:
        vulnerabilities[f"banner_{port}"] = grab_banner(host, port)

        if port == 21:
            vulnerabilities["anonymous_login"] = check_anonymous_login(host, port)
            vulnerabilities["ftps_support"] = check_ftps_support(host)
            vulnerabilities["pasv_support"] = check_pasv_support(host, port)
            vulnerabilities["active_support"] = check_active_support(host, port)
            vulnerabilities["directory_traversal"] = check_directory_traversal(host, port)

        if port == 990:
            vulnerabilities["ssl_tls_details"] = check_ssl_details(host, port)

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
        print("Usage: python3 check_ftp.py <target> or <target:port>")
        sys.exit(1)

    target = sys.argv[1]
    result = collect(target)

    print(json.dumps(result, indent=4))


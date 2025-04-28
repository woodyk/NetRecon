#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_snmp.py
# Author: Wadih Khairallah
# Description: SNMP Vulnerability Scanner for NetRecon
# Updated: 2025-04-28

import json
import socket
import sys
import re
from datetime import datetime, timezone
from pysnmp.hlapi import *

COMMON_COMMUNITIES = ['public', 'private']
SENSITIVE_OIDS = {
    'sysDescr': '1.3.6.1.2.1.1.1.0',
    'sysContact': '1.3.6.1.2.1.1.4.0',
    'sysName': '1.3.6.1.2.1.1.5.0',
    'sysLocation': '1.3.6.1.2.1.1.6.0',
}

TIMEOUT = 5
DEFAULT_SNMP_PORT = 161

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
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        sock.close()
        return True
    except Exception:
        return False

def detect_snmp_version(host, port):
    try:
        for version, community in [(1, 'public'), (2, 'public')]:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=0 if version == 1 else 1),
                UdpTransportTarget((host, port), timeout=TIMEOUT, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
            )
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            if not errorIndication and not errorStatus:
                return {"status": "pass", "detail": f"SNMPv{version} detected as responsive."}
        return {"status": "fail", "detail": "No SNMPv1/v2c response detected; possibly SNMPv3 only."}
    except Exception as e:
        return {"status": "error", "detail": f"SNMP version detection failed: {str(e)}"}

def test_default_communities(host, port):
    try:
        accepted = []
        for community in COMMON_COMMUNITIES:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((host, port), timeout=TIMEOUT, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
            )
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            if not errorIndication and not errorStatus:
                accepted.append(community)
        if accepted:
            return {"status": "fail", "detail": f"Accepted default community strings: {', '.join(accepted)}"}
        return {"status": "pass", "detail": "Default community strings rejected."}
    except Exception as e:
        return {"status": "error", "detail": f"Default community test failed: {str(e)}"}

def read_sensitive_oids(host, port):
    try:
        exposures = []
        for label, oid in SENSITIVE_OIDS.items():
            iterator = getCmd(
                SnmpEngine(),
                CommunityData('public'),
                UdpTransportTarget((host, port), timeout=TIMEOUT, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            if not errorIndication and not errorStatus:
                for varBind in varBinds:
                    exposures.append(f"{label}: {varBind[1]}")
        if exposures:
            return {"status": "fail", "detail": "Sensitive SNMP attributes exposed: " + "; ".join(exposures)}
        return {"status": "pass", "detail": "No sensitive attributes exposed."}
    except Exception as e:
        return {"status": "error", "detail": f"Sensitive OID read test failed: {str(e)}"}

def attempt_bulk_walk(host, port):
    try:
        count = 0
        for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
            SnmpEngine(),
            CommunityData('public'),
            UdpTransportTarget((host, port), timeout=TIMEOUT, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity('SNMPv2-MIB', 'system')),
            lexicographicMode=False,
        ):
            if not errorIndication and not errorStatus:
                count += 1
            if count > 50:
                break
        if count > 0:
            return {"status": "fail", "detail": f"SNMP bulk walk possible ({count} entries retrieved)."}
        return {"status": "pass", "detail": "SNMP bulk walk restricted."}
    except Exception as e:
        return {"status": "error", "detail": f"SNMP bulk walk test failed: {str(e)}"}

def test_amplification(host, port):
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData('public'),
            UdpTransportTarget((host, port), timeout=TIMEOUT, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0))
        )
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        if not errorIndication and not errorStatus:
            total_bytes = sum(len(str(v)) for v in varBinds)
            if total_bytes > 200:
                return {"status": "fail", "detail": f"Potential SNMP amplification risk (response {total_bytes} bytes)."}
        return {"status": "pass", "detail": "No significant amplification detected."}
    except Exception as e:
        return {"status": "error", "detail": f"Amplification test failed: {str(e)}"}

def test_snmp_set_operation(host, port):
    try:
        iterator = setCmd(
            SnmpEngine(),
            CommunityData('public'),
            UdpTransportTarget((host, port), timeout=TIMEOUT, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.4.0'), OctetString('test'))
        )
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        if not errorIndication and not errorStatus:
            return {"status": "fail", "detail": "SNMP SET allowed without proper authorization!"}
        return {"status": "pass", "detail": "SNMP SET restricted as expected."}
    except Exception:
        return {"status": "pass", "detail": "SNMP SET restricted as expected."}

def check_trap_service_exposure(host):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(b"test", (host, 162))
        try:
            data, _ = sock.recvfrom(1024)
            if data:
                return {"status": "fail", "detail": "SNMP Trap port (UDP 162) is open and responding."}
        except socket.timeout:
            return {"status": "pass", "detail": "SNMP Trap port closed or non-responsive (good)."}
        finally:
            sock.close()
    except Exception as e:
        return {"status": "error", "detail": f"SNMP trap exposure test failed: {str(e)}"}

def collect(target: str):
    host, port = parse_target(target)
    port = port if port else DEFAULT_SNMP_PORT
    vulnerabilities = {}
    summary = []

    if not check_port_open(host, port):
        return {
            "target": host,
            "port": [port],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "open": False,
            "vulnerabilities": {},
            "summary": ["SNMP port not reachable."]
        }

    vulnerabilities["snmp_version_check"] = detect_snmp_version(host, port)
    vulnerabilities["default_community_check"] = test_default_communities(host, port)
    vulnerabilities["sensitive_oids_check"] = read_sensitive_oids(host, port)
    vulnerabilities["bulk_walk_check"] = attempt_bulk_walk(host, port)
    vulnerabilities["amplification_check"] = test_amplification(host, port)
    vulnerabilities["snmp_set_check"] = test_snmp_set_operation(host, port)
    vulnerabilities["trap_exposure_check"] = check_trap_service_exposure(host)

    return {
        "target": host,
        "port": [port],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "open": True,
        "vulnerabilities": vulnerabilities,
        "summary": summary
    }

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 check_snmp.py <target> or <target:port>")
        sys.exit(1)

    target = sys.argv[1]
    result = collect(target)

    print(json.dumps(result, indent=4))


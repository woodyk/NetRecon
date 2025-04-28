#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: check_snmp.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-27 21:28:20
# Modified: 2025-04-27 21:34:32

import argparse
import json
import socket
from pysnmp.hlapi import *
import dns.resolver

COMMON_COMMUNITIES = ['public', 'private']
SENSITIVE_OIDS = {
    'sysDescr': '1.3.6.1.2.1.1.1.0',
    'sysContact': '1.3.6.1.2.1.1.4.0',
    'sysName': '1.3.6.1.2.1.1.5.0',
    'sysLocation': '1.3.6.1.2.1.1.6.0',
}

def detect_snmp_version(host, findings):
    # Try v1 and v2c with public community
    for version, community in [(1, 'public'), (2, 'public')]:
        try:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=0 if version == 1 else 1),
                UdpTransportTarget((host, 161), timeout=2, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
            )
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            if not errorIndication and not errorStatus:
                findings.append(f"SNMPv{version} detected as responsive.")
                return
        except Exception:
            continue
    findings.append("SNMPv3 only or no response detected.")

def test_default_communities(host, findings):
    for community in COMMON_COMMUNITIES:
        try:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((host, 161), timeout=2, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
            )
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            if not errorIndication and not errorStatus:
                findings.append(f"Default community string '{community}' is accepted!")
        except Exception:
            continue

def read_sensitive_oids(host, findings):
    for label, oid in SENSITIVE_OIDS.items():
        try:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData('public'),
                UdpTransportTarget((host, 161), timeout=2, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            if not errorIndication and not errorStatus:
                for varBind in varBinds:
                    findings.append(f"{label}: {varBind[1]}")
        except Exception:
            continue

def attempt_bulk_walk(host, findings):
    try:
        count = 0
        for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
            SnmpEngine(),
            CommunityData('public'),
            UdpTransportTarget((host, 161), timeout=2, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity('SNMPv2-MIB', 'system')),
            lexicographicMode=False,
        ):
            if not errorIndication and not errorStatus:
                count += 1
            if count > 50:  # limit reporting
                break
        if count > 0:
            findings.append(f"SNMP Walk is possible, {count} objects retrieved.")
    except Exception:
        pass

def test_amplification(host, findings):
    try:
        # Send minimal query
        minimal_request = getCmd(
            SnmpEngine(),
            CommunityData('public'),
            UdpTransportTarget((host, 161), timeout=2, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0))
        )
        errorIndication, errorStatus, errorIndex, varBinds = next(minimal_request)
        if not errorIndication and not errorStatus:
            # Response size estimation
            total_bytes = sum(len(str(v)) for v in varBinds)
            if total_bytes > 200:
                findings.append(f"SNMP server may be vulnerable to amplification (large response: {total_bytes} bytes).")
    except Exception:
        pass

def test_snmp_set_operation(host, findings):
    try:
        # Attempt safe dummy SET operation (will usually be blocked)
        iterator = setCmd(
            SnmpEngine(),
            CommunityData('public'),
            UdpTransportTarget((host, 161), timeout=2, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.4.0'), OctetString('test'))
        )
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        if not errorIndication and not errorStatus:
            findings.append("SNMP SET allowed without authentication! (Potential critical misconfiguration)")
    except Exception:
        findings.append("SNMP SET operation rejected (expected).")

def check_trap_service_exposure(host, findings):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(b"test", (host, 162))
        try:
            data, _ = sock.recvfrom(1024)
            if data:
                findings.append("SNMP Trap port (UDP 162) is open and responsive.")
        except socket.timeout:
            findings.append("SNMP Trap port (UDP 162) not responding.")
        finally:
            sock.close()
    except Exception:
        findings.append("SNMP Trap exposure check failed.")

def scan_snmp(target: str) -> dict:
    findings = []
    parsed_target = target.replace('http://', '').replace('https://', '').split('/')[0]

    detect_snmp_version(parsed_target, findings)
    test_default_communities(parsed_target, findings)
    read_sensitive_oids(parsed_target, findings)
    attempt_bulk_walk(parsed_target, findings)
    test_amplification(parsed_target, findings)
    test_snmp_set_operation(parsed_target, findings)
    check_trap_service_exposure(parsed_target, findings)

    return {
        "domain": parsed_target,
        "findings": findings
    }

def main():
    parser = argparse.ArgumentParser(description="SNMP Service Vulnerability Scanner")
    parser.add_argument("--target", required=True, help="Target domain or IP")
    args = parser.parse_args()

    result = scan_snmp(args.target)

    print(json.dumps(result, indent=4))

if __name__ == "__main__":
    main()


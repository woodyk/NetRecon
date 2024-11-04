#!/usr/bin/env python3
#
# ports_recon.py

import nmap

# Define a comprehensive range of ports, including standard, common, and duplicate ports
PORT_RANGE = "1-65535"  # Full range; adjust as needed for a faster scan

# Check for privilaged ports only
PORT_RANGE = "1-1024"

def collect(ip):
    nm = nmap.PortScanner()
    open_ports = {}

    try:
        # Run the nmap scan with options: '-sS' for stealth scan, '-T4' for faster speed
        nm.scan(ip, PORT_RANGE, arguments="-sS -T4")
        
        # Check if any host was detected by nmap
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                # Retrieve open ports for each protocol (e.g., tcp, udp)
                ports = nm[ip][proto].keys()
                for port in ports:
                    port_info = nm[ip][proto][port]
                    if port_info['state'] == 'open':
                        open_ports[port] = {
                            "state": port_info['state'],
                            "service": port_info['name'],
                            "product": port_info.get('product', ''),
                            "version": port_info.get('version', ''),
                            "extra_info": port_info.get('extrainfo', '')
                        }
    except Exception as e:
        return {"error": str(e)}

    return {"open_ports": open_ports}

if __name__ == "__main__":
    ip = "8.8.8.8"  # Test IP address
    print(collect(ip))

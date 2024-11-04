#!/usr/bin/env python3
#
# netrecon.py

import json
import argparse
import ipaddress
import importlib
import pkgutil
import os

# Adjust the directory path for the modules folder
MODULES_DIR = os.path.join(os.path.dirname(__file__), "modules")

def expand_ips(ips):
    """Expands a single IP, CIDR block, or comma-separated list into individual IPs."""
    expanded_ips = []
    for ip in ips.split(","):
        ip = ip.strip()
        try:
            # Check if it's a CIDR block
            network = ipaddress.ip_network(ip, strict=False)
            expanded_ips.extend([str(addr) for addr in network.hosts()])
        except ValueError:
            # If not a CIDR block, treat as a single IP
            expanded_ips.append(ip)
    return expanded_ips

def aggregate_data(ip):
    """Dynamically aggregates data from all modules in the modules package for a given IP."""
    results = {}
    
    # Discover and load all modules in the "modules" directory
    for loader, module_name, is_pkg in pkgutil.iter_modules([MODULES_DIR]):
        module = importlib.import_module(f"modules.{module_name}")
        
        # Check if the module has a 'collect' function
        if hasattr(module, 'collect'):
            try:
                # Run the 'collect' function and add the output to results
                results[module_name] = module.collect(ip)
            except Exception as e:
                results[module_name] = {"error": str(e)}

    return results

def run_recon(ip_addresses, save=False):
    results = {}

    for ip in ip_addresses:
        # Aggregate data for the IP
        ip_data = aggregate_data(ip)
        results[ip] = ip_data

        # Pretty print the JSON to stdout
        print(f"\nResults for {ip}:\n")
        print(json.dumps(ip_data, indent=4))

        # Save to individual files if the save option is enabled
        if save:
            with open(f"{ip}.json", "w") as file:
                json.dump(ip_data, file, indent=4)
                print(f"\nData for {ip} saved to {ip}.json")

    return results

def main():
    parser = argparse.ArgumentParser(description="NetRecon IP Reconnaissance Tool")
    parser.add_argument(
        "ips",
        help="A single IP address, CIDR block, or a comma-separated list of IP addresses or CIDR blocks to scan"
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="Save results to individual JSON files"
    )
    args = parser.parse_args()

    # Expand any CIDR blocks or comma-separated lists into individual IPs
    ip_addresses = expand_ips(args.ips)

    # Run reconnaissance with or without saving
    run_recon(ip_addresses, save=args.save)

if __name__ == "__main__":
    main()

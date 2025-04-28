#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: netrecon.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-27 20:38:02
# Modified: 2025-04-28 18:16:24

import os
import sys
import json
import socket
import ipaddress
import importlib.util
import traceback
from datetime import datetime, timezone

# ===== Utility Functions =====

def expand_ips(target):
    """
    Expand the input target to a list of IPs.
    Supports:
        - Single IP
        - CIDR block
        - Domain (resolves to IP)
    """
    ips = []
    try:
        # CIDR notation
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            for ip in net.hosts():
                ips.append(str(ip))
        else:
            # Try resolving domain to IP
            ip = socket.gethostbyname(target)
            ips.append(ip)
    except Exception as e:
        ips.append(target)  # fallback: treat as is
    return ips

def aggregate_data(results):
    """
    Post-process results.
    Currently a placeholder for future normalization.
    """
    # Example: Move *_error fields under 'errors' sub-block in each module
    for module, data in results.items():
        if isinstance(data, dict):
            errors = {}
            keys_to_remove = []
            for key in data:
                if key.endswith("_error"):
                    errors[key] = data[key]
                    keys_to_remove.append(key)
            for key in keys_to_remove:
                del data[key]
            if errors:
                data['errors'] = errors
    return results

def dynamic_import(module_path, module_name):
    """
    Dynamically import a Python module given a path.
    """
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

# ===== Orchestration Core =====

def run_recon_modules(target, modules_dir="modules"):
    """
    Run all *_recon.py modules on the target.
    """
    results = {}
    module_files = [f for f in os.listdir(modules_dir) if f.endswith("_recon.py")]

    for module_file in sorted(module_files):  # alphabetical execution
        module_name = module_file[:-3]  # remove '.py'
        module_path = os.path.join(modules_dir, module_file)

        try:
            module = dynamic_import(module_path, module_name)
            if hasattr(module, "collect"):
                output = module.collect(target)
                results[module_name] = output
            else:
                results[module_name] = {"error": "Missing 'collect' function"}
        except Exception as e:
            results[module_name] = {
                "error": f"Failed to run {module_name}: {str(e)}",
                "traceback": traceback.format_exc()
            }

    return results

def main():
    if len(sys.argv) != 2:
        print("Usage: ./netrecon.py <target>")
        sys.exit(1)

    input_target = sys.argv[1]
    expanded_targets = expand_ips(input_target)

    final_results = {}

    for target in expanded_targets:
        print(f"\n[+] Running NetRecon modules on: {target}\n")
        results = run_recon_modules(target)
        results["timestamp"] = datetime.now(timezone.utc).isoformat()
        aggregated = aggregate_data(results)
        final_results[target] = aggregated

    print(json.dumps(final_results, indent=4))

if __name__ == "__main__":
    main()


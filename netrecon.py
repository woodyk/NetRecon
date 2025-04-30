#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: netrecon.py
# Author: Wadih Khairallah
# Description: NetRecon Orchestration Core (unaltered target unless CIDR)
# Created: 2025-04-27 20:38:02
# Modified: 2025-04-28 20:16:24

import os
import sys
import json
import importlib.util
import traceback
import ipaddress
from datetime import datetime, timezone

# ===== Utility Functions =====

def expand_cidr(target):
    """
    Expand a CIDR block to a list of IPs.
    """
    ips = []
    try:
        net = ipaddress.ip_network(target, strict=False)
        for ip in net.hosts():
            ips.append(str(ip))
    except ValueError:
        ips.append(target)  # Not a CIDR, treat as a single item
    return ips

def aggregate_data(results):
    """
    Post-process results.
    """
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
    Run all *_recon.py modules on the given target.
    """
    results = {}
    module_files = [f for f in os.listdir(modules_dir) if f.endswith("_recon.py")]

    for module_file in sorted(module_files):
        module_name = module_file[:-3]  # strip '.py'
        module_path = os.path.join(modules_dir, module_file)

        print(f"[*] Running module: {module_name} on {target}")

        try:
            module = dynamic_import(module_path, module_name)
            if hasattr(module, "collect"):
                output = module.collect(target)
                results[module_name] = output
            else:
                results[module_name] = {"status": "error", "data": {}, "error": "Missing 'collect' function"}
        except Exception as e:
            results[module_name] = {
                "status": "error",
                "data": {},
                "error": f"Failed to run {module_name}: {str(e)}",
                "traceback": traceback.format_exc()
            }

        print(f"[+] Completed module: {module_name} on {target}")

    return results

def main():
    if len(sys.argv) != 2:
        print("Usage: ./netrecon.py <target or targets>")
        sys.exit(1)

    input_arg = sys.argv[1]

    if "," in input_arg:
        # Comma-separated list
        targets = [t.strip() for t in input_arg.split(",") if t.strip()]
    else:
        targets = [input_arg.strip()]

    final_targets = []

    for target in targets:
        if "/" in target:
            # Expand CIDR blocks
            expanded = expand_cidr(target)
            final_targets.extend(expanded)
        else:
            final_targets.append(target)

    final_results = {}

    for target in final_targets:
        print(f"\n[+] Starting Recon on: {target}\n")
        results = run_recon_modules(target)
        results["timestamp"] = datetime.now(timezone.utc).isoformat()
        aggregated = aggregate_data(results)
        final_results[target] = aggregated

    print(json.dumps(final_results, indent=4))

if __name__ == "__main__":
    main()


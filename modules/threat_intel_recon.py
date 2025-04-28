#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: threat_intel_recon.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-28 18:23:02
#!/usr/bin/env python3
#
# threat_intel_recon.py

import requests
import os

# API key for AbuseIPDB
API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def get_abuseipdb_reports(ip, page=1, per_page=25):
    """Fetches threat intelligence reports from AbuseIPDB."""
    url = "https://api.abuseipdb.com/api/v2/reports"
    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "page": page,
        "perPage": per_page
    }
    
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json().get("data", {})
        return {
            "total_reports": data.get("total", 0),
            "reports": data.get("results", [])
        }
    except Exception as e:
        return {"error": f"AbuseIPDB reports lookup failed: {str(e)}"}

def collect(ip):
    """Collects threat intelligence data from AbuseIPDB for a given IP."""
    threat_data = {
        "abuseipdb": get_abuseipdb_reports(ip)
    }
    return threat_data

if __name__ == "__main__":
    ip = "54.87.182.78"  # Test IP address
    print(collect(ip))

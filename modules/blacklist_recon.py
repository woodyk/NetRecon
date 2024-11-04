#!/usr/bin/env python3
#
# blacklist_recon.py

import requests
import os

API_KEY = os.getenv("ABUSEIPDB_API_KEY") 

def collect(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": ""
    }

    blacklist_results = {}

    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            blacklist_results = {
                "isPublic": data.get("data", {}).get("isPublic", "Unknown"),
                "abuseConfidenceScore": data.get("data", {}).get("abuseConfidenceScore", "Unknown"),
                "countryCode": data.get("data", {}).get("countryCode", "Unknown"),
                "usageType": data.get("data", {}).get("usageType", "Unknown"),
                "isp": data.get("data", {}).get("isp", "Unknown"),
                "domain": data.get("data", {}).get("domain", "Unknown"),
                "hostnames": data.get("data", {}).get("hostnames", [])
            }
        else:
            blacklist_results = {"error": f"Not Listed, status code: {response.status_code}"}
    except Exception as e:
        blacklist_results = {"error": str(e)}

    return {"blacklist": blacklist_results}

if __name__ == "__main__":
    ip = "118.25.6.39"
    print(collect(ip))

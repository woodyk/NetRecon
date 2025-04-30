#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: threat_intel_recon.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-04-28 18:23:02
# Modified: 2025-04-28 18:39:18

import requests

def collect(target):
    result = {
        "status": "success",
        "data": {}
    }
    try:
        headers = {
            'Accept': 'application/json',
            'Key': 'YOUR_ABUSEIPDB_API_KEY_HERE'
        }
        query_url = f"https://api.abuseipdb.com/api/v2/reports?ipAddress={target}&maxAgeInDays=90"

        resp = requests.get(query_url, headers=headers, timeout=10)

        if resp.status_code == 200:
            reports = resp.json().get("data", [])
            result["data"]["reports"] = reports
        elif resp.status_code == 401:
            result["status"] = "error"
            result["data"] = {}
            result["error"] = "Unauthorized access to AbuseIPDB API (401)."
        elif resp.status_code == 422:
            result["status"] = "error"
            result["data"] = {}
            result["error"] = "Unprocessable request to AbuseIPDB API (422)."
        else:
            result["status"] = "error"
            result["data"] = {}
            result["error"] = f"Unexpected response from AbuseIPDB API: {resp.status_code}"

    except Exception as e:
        result["status"] = "error"
        result["data"] = {}
        result["error"] = str(e)

    return result


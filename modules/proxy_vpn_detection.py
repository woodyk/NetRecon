#!/usr/bin/env python3
#
# proxy_vpn_detection.py

import requests

def collect(ip):
    try:
        response = requests.get(f"https://proxycheck.io/v2/{ip}")
        data = response.json().get(ip, {})
        return {
            "proxy": data.get("proxy"),
            "vpn": data.get("vpn"),
            "type": data.get("type"),
            "isPublic": data.get("isPublic")
        }
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    ip = "8.8.8.8"
    print(collect(ip))

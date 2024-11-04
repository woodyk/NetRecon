#!/usr/bin/env python3
#
# geolocation_recon.py

import requests

def collect(query):
    url = f"http://ip-api.com/json/{query}"
    fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
    params = {"fields": fields}

    try:
        response = requests.get(url, params=params)
        data = response.json()

        if data.get("status") == "success":
            return {
                "country": data.get("country"),
                "countryCode": data.get("countryCode"),
                "region": data.get("region"),
                "regionName": data.get("regionName"),
                "city": data.get("city"),
                "zip": data.get("zip"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "timezone": data.get("timezone"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "as": data.get("as"),
                "query": data.get("query")
            }
        else:
            return {"error": data.get("message", "Unknown error")}
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    # Test with an IP address or domain name
    test_query = "24.48.0.1"
    print(collect(test_query))

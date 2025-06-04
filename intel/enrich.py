import requests
from ipwhois import IPWhois

def enrich_ip_virustotal(ip, api_key):
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": api_key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return stats
    except:
        pass
    return None

def get_geo_asn(ip):
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap()
        return {
            "asn": result.get("asn"),
            "org": result.get("network", {}).get("name"),
            "country": result.get("asn_country_code")
        }
    except:
        return {"asn": None, "org": None, "country": None}

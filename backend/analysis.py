import requests

from config import ABUSEIPDB_API_KEY
def check_ip(ip):

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    response = requests.get(
        url,
        headers=headers,
        params=params
    )

    data = response.json()

    return {
        "ip": data["data"]["ipAddress"],
        "threat_score": data["data"]["abuseConfidenceScore"],
        "country": data["data"]["countryCode"],
        "isp": data["data"]["isp"],
        "domain": data["data"]["domain"],
        "usage_type": data["data"]["usageType"],
        "total_reports": data["data"]["totalReports"]
    }
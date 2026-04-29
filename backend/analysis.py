import requests
import base64

from config import ABUSEIPDB_API_KEY
from config import VT_API_KEY
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
def scan_url(url):

    url_bytes = url.encode('utf-8')

    url_id = base64.urlsafe_b64encode(
        url_bytes
    ).decode().strip("=")

    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    headers = {
        "x-apikey": VT_API_KEY
    }

    response = requests.get(
        endpoint,
        headers=headers
    )

    data = response.json()

    stats = data["data"]["attributes"]["last_analysis_stats"]

    malicious = stats["malicious"]

    suspicious = stats["suspicious"]

    harmless = stats["harmless"]

    reputation_score = harmless - malicious

    return {
        "url": url,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "reputation_score": reputation_score
    }
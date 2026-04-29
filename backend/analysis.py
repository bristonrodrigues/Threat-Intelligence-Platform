import requests
import base64

from config import ABUSEIPDB_API_KEY
from config import VT_API_KEY

from database import save_threat
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

    threat_score = data["data"]["abuseConfidenceScore"]

    if threat_score >= 60:
        severity = "High"

    elif threat_score >= 20:
        severity = "Medium"

    else:
        severity = "Low"

    save_threat(
        ip=ip,
        url="N/A",
        severity=severity,
        threat_type="Malicious IP"
    )

    return {
        "ip": data["data"]["ipAddress"],
        "threat_score": threat_score,
        "severity": severity,
        "country": data["data"]["countryCode"],
        "isp": data["data"]["isp"],
        "domain": data["data"]["domain"],
        "usage_type": data["data"]["usageType"],
        "total_reports": data["data"]["totalReports"]
    }
import requests
import base64

from config import ABUSEIPDB_API_KEY
from config import VT_API_KEY


# =========================================
# Severity Logic
# =========================================

def get_severity(score):

    if score >= 80:
        return "High"

    elif score >= 50:
        return "Medium"

    else:
        return "Low"


# =========================================
# Threat Classification Logic
# =========================================

def classify_threat(score):

    if score >= 90:
        return "Botnet"

    elif score >= 75:
        return "Malware"

    elif score >= 60:
        return "Phishing"

    elif score >= 40:
        return "Spam"

    else:
        return "Suspicious"


# =========================================
# IP Reputation Scanner
# =========================================

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

    score = data["data"]["abuseConfidenceScore"]

    severity = get_severity(score)

    threat_type = classify_threat(score)

    return {
        "ip": data["data"]["ipAddress"],
        "threat_score": score,
        "severity": severity,
        "threat_type": threat_type,
        "country": data["data"]["countryCode"],
        "isp": data["data"]["isp"],
        "domain": data["data"]["domain"],
        "usage_type": data["data"]["usageType"],
        "total_reports": data["data"]["totalReports"]
    }


# =========================================
# URL Scanner
# =========================================

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

    score = malicious * 10

    severity = get_severity(score)

    threat_type = classify_threat(score)

    return {
        "url": url,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "reputation_score": reputation_score,
        "severity": severity,
        "threat_type": threat_type
    }
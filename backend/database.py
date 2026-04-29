from pymongo import MongoClient

from config import MONGO_URI


client = MongoClient(MONGO_URI)

db = client["threat_intelligence"]


threats_collection = db["threats"]

alerts_collection = db["alerts"]

users_collection = db["users"]

scan_history_collection = db["scan_history"]
from datetime import datetime


def save_threat(ip, url, severity, threat_type):

    threat_data = {
        "ip": ip,
        "url": url,
        "severity": severity,
        "threat_type": threat_type,
        "timestamp": datetime.now()
    }

    threats_collection.insert_one(threat_data)

    print("Threat stored successfully")
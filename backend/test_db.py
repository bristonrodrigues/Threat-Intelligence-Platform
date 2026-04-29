from database import threats_collection

data = {
    "ip": "8.8.8.8",
    "threat_score": 0,
    "country": "US"
}

threats_collection.insert_one(data)

print("Data inserted successfully")
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    send_file
)

from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user,
    current_user
)

from bson.objectid import ObjectId
import bcrypt
import os
import hashlib
import requests
import pandas as pd
import io

from config import VT_API_KEY
from auth import User
from feature_extractor import extract_features
from datetime import datetime
from pymongo import MongoClient
from ml_model import predict_url
from alerts import send_email_alert
import csv
from flask import Response

import threading
import time
import random

# =============================
# APP CONFIG
# =============================
app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static"
)

app.secret_key = "supersecretkey"

# =============================
# DATABASE
# =============================
client = MongoClient("mongodb://localhost:27017/")
db = client["threat_intelligence"]
collection = db["threats"]
alerts_collection = db["alerts"]

# =============================
# LOGIN MANAGER
# =============================
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    user_data = db.users.find_one({"_id": ObjectId(user_id)})
    if user_data:
        return User(user_data)
    return None


request_count = 0
last_high_count = 0
last_alert_time = 0


# =============================
# AUTH ROUTES
# =============================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        hashed_password = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        )

        db.users.insert_one({
            "username": username,
            "email": email,
            "password": hashed_password
        })

        return redirect('/login')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user_data = db.users.find_one({"email": email})

        if user_data:
            if bcrypt.checkpw(password.encode('utf-8'), user_data['password']):
                user = User(user_data)
                login_user(user)
                return redirect('/')

        return "Invalid Email or Password"

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')


# =============================
# AUTO THREAT GENERATOR (FIXED)
# =============================
def auto_generate_threats():
    global last_high_count, last_alert_time

    while True:
        threat = {
            "ip": f"192.168.{random.randint(0,255)}.{random.randint(0,255)}",
            "severity": "High" if random.random() < 0.1 else "Low",
            "threat_type": random.choice(["Phishing", "Malware", "DDoS"]),
            "timestamp": datetime.now()
        }

        collection.insert_one(threat)

        current_high_count = collection.count_documents({"severity": "High"})
        current_time = time.time()

        if current_high_count > last_high_count and (current_time - last_alert_time > 60):

            message = f"""
🚨 HIGH THREAT DETECTED

IP: {threat['ip']}
Type: {threat['threat_type']}
Severity: {threat['severity']}
Time: {threat['timestamp']}
"""

            send_email_alert("🚨 New High Threat Detected", message)

            alerts_collection.insert_one({
                "threat_type": threat['threat_type'],
                "severity": threat['severity'],
                "notification": "Email",
                "status": "Sent",
                "timestamp": datetime.now()
            })

            last_alert_time = current_time

        last_high_count = current_high_count
        time.sleep(30)


# =============================
# PAGES
# =============================
@app.route('/')
@login_required
def home():
    return render_template("index.html")


@app.route('/threat_feed')
def threat_feed():
    return render_template('threat_feed.html')


@app.route('/alerts')
def alerts():
    return render_template('alerts.html')


@app.route('/reports')
def reports():
    return render_template('reports.html')


@app.route('/analytics')
def analytics():
    return render_template('analytics.html')


@app.route('/url_scanner')
@login_required
def url_scanner():
    return render_template('url_scanner.html')


@app.route('/file_scanner')
@login_required
def file_scanner():
    return render_template('file_scanner.html')


# =============================
# API ROUTES
# =============================
@app.route('/api/threats')
@login_required
def get_threats():
    threats = list(
        collection.find({}, {'_id': 0})
        .sort("timestamp", -1)
        .limit(10)
    )
    return jsonify(threats)


@app.route('/api/analytics')
@login_required
def get_analytics():
    high = collection.count_documents({"severity": "High"})
    low = collection.count_documents({"severity": "Low"})
    phishing = collection.count_documents({"threat_type": "Phishing"})
    safe = low
    alerts = alerts_collection.count_documents({})

    return jsonify({
        "high": high,
        "low": low,
        "phishing": phishing,
        "safe": safe,
        "alerts": alerts
    })


@app.route('/api/alerts')
@login_required
def get_alerts():
    alerts = list(
        alerts_collection.find({}, {'_id': 0})
        .sort("timestamp", -1)
        .limit(20)
    )
    return jsonify(alerts)


@app.route('/api/trend')
def get_trend():

    labels = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]

    data = []

    base = 100

    for i in range(7):
        base += random.randint(-20, 30)   # smooth variation
        data.append(max(base, 10))

    return {
        "labels": labels,
        "data": data
    }


# =============================
# PREDICT ROUTE
# =============================
@app.route('/predict', methods=['POST'])
def predict():

    global request_count

    request_count += 1
    if request_count > 100:
        return jsonify({"error": "API Rate Limit Exceeded"})

    data = request.get_json()

    url = data.get("url")

    print("URL RECEIVED:", url)

    # Extract features
    features = extract_features(url)
    print("FEATURES:", features)

    # Convert to DataFrame
    features_df = pd.DataFrame([features])

    try:
        result = predict_url(features_df)

        # Fix pandas Series issue
        # 🔥 FORCE CONVERT TO STRING (BEST FIX)
        result['risk_level'] = str(result['risk_level'])
        result['prediction'] = str(result['prediction'])

# Clean values like "['High']" → "High"
        result['risk_level'] = result['risk_level'].replace("[", "").replace("]", "").replace("'", "")
        result['prediction'] = result['prediction'].replace("[", "").replace("]", "").replace("'", "")

        print("RESULT:", result)

    except Exception as e:
        print("ERROR:", e)
        return jsonify({"error": str(e)})

    # Save to DB
    threat_data = {
        "ip": "192.168.1.10",
        "threat_type": result['prediction'],
        "severity": result['risk_level'],
        "timestamp": datetime.now()
    }

    collection.insert_one(threat_data)

    # Email alert
    if result['risk_level'] == "High":

        message = f"""
🚨 HIGH THREAT DETECTED

Prediction: {result['prediction']}
Risk: {result['risk_level']}
"""

        send_email_alert("🚨 High Threat Detected", message)

        alerts_collection.insert_one({
            "threat_type": result['prediction'],
            "severity": result['risk_level'],
            "notification": "Email",
            "status": "Sent",
            "timestamp": datetime.now()
        })

    return jsonify(result)
# =============================
# DOWNLOAD REPORT
@app.route('/download-report')
def download_report():

    # 👉 GET ID FROM URL
    report_id = request.args.get("id")

    # 👉 GET DATA FROM DB
    data = list(collection.find({}, {"_id": 0}))

    # 👉 MAKE EACH REPORT UNIQUE
    if report_id:
        report_id = int(report_id)

        start = report_id * 5
        end = start + 5

        data = data[start:end]

    def generate():

        yield "IP,Threat Type,Severity,Status\n"

        for t in data:
            yield f"{t.get('ip','-')},{t.get('threat_type','-')},{t.get('severity','-')},Active\n"

    return Response(
        generate(),
        mimetype='text/csv',
        headers={
            "Content-Disposition": f"attachment; filename=report_{report_id}.csv"
        }
    )
# =============================
# RUN APP
# =============================
if __name__ == "__main__":
    threading.Thread(target=auto_generate_threats, daemon=True).start()
    app.run(debug=True)
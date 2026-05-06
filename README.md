# AI-Based Threat Intelligence and Phishing Detection Platform

## 📌 Project Overview

The AI-Based Threat Intelligence and Phishing Detection Platform is a cybersecurity system developed to detect phishing URLs using machine learning techniques and provide real-time threat monitoring through an interactive dashboard.

The platform includes URL scanning, analytics visualization, attack map monitoring, alert generation, and role-based access control.

---

## 🚀 Features

- User Authentication (Admin/User)
- URL Phishing Detection using Machine Learning
- Real-Time Threat Dashboard
- Live Threat Feed
- World Attack Map Visualization
- Threat Analytics
- Email Alert Notifications
- CSV Report Generation
- Role-Based Access Control

---

## 🛠️ Technologies Used

### Frontend
- HTML
- CSS
- Bootstrap
- JavaScript

### Backend
- Python
- Flask

### Database
- MongoDB

### Machine Learning
- Scikit-learn
- Pandas
- NumPy

### Visualization
- Chart.js
- Leaflet.js

### Alerts
- SMTP Email Alerts

---

## 🧠 System Workflow

1. User logs into the system
2. User enters URL into scanner
3. Backend processes the URL
4. Features are extracted from the URL
5. ML model predicts Safe or Phishing
6. Results are stored in MongoDB
7. Dashboard updates analytics and alerts

---

## 📂 Project Structure

```bash
backend/
│
├── app.py
├── predict.py
├── feature_extraction.py
├── requirements.txt
│
├── models/
│   ├── phishing_model.pkl
│   └── scaler.pkl
│
├── templates/
├── static/
└── reports/
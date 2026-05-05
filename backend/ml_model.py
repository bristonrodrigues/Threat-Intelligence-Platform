import joblib
import pandas as pd


# LOAD MODEL

model = joblib.load(
    "../models/phishing_model.pkl"
)


# LOAD SCALER

scaler = joblib.load(
    "../models/scaler.pkl"
)


def predict_url(features):

    # 🔥 Convert DataFrame → dict
    if isinstance(features, pd.DataFrame):
        features = features.iloc[0].to_dict()

    suspicious_score = 0

    if features['nb_hyphens'] > 2:
        suspicious_score += 1

    if features['nb_dots'] > 3:
        suspicious_score += 1

    if features['at_symbol'] == 1:
        suspicious_score += 1

    if features['isHttps'] == 0:
        suspicious_score += 1

    if features['sensitive_words_count'] > 0:
        suspicious_score += 2

    if features['url_length'] > 75:
        suspicious_score += 1

    # 🚨 Rule-based detection
    if suspicious_score >= 3:
        return {
            "prediction": "Phishing",
            "risk_level": "High",
            "threat_score": 90
        }

    # =========================
    # ML PART
    # =========================

    # 🔥 ONLY TRAINED FEATURES
    required_columns = [
        "url_length",
        "valid_url",
        "at_symbol",
        "sensitive_words_count",
        "path_length",
        "isHttps",
        "nb_dots",
        "nb_hyphens",
        "nb_and",
        "nb_or",
        "nb_www",
        "nb_com",
        "nb_underscore"
    ]

    df = pd.DataFrame([features])[required_columns]

    scaled_data = scaler.transform(df)

    prediction = model.predict(scaled_data)

    # Final decision
    if prediction[0] == 0:
        return {
            "prediction": "Phishing",
            "risk_level": "High",
            "threat_score": 80
        }
    else:
        return {
            "prediction": "Safe",
            "risk_level": "Low",
            "threat_score": 20
        }
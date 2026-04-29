import joblib
import pandas as pd


# Load Trained ML Model

model = joblib.load("../models/phishing_model.pkl")


# Load Scaler

scaler = joblib.load("../models/scaler.pkl")


def predict_url(features):

    # Convert features into DataFrame

    df = pd.DataFrame([features])

    # Normalize features

    scaled_features = scaler.transform(df)

    # Predict

    prediction = model.predict(scaled_features)

    # Return Result

    if prediction[0] == 1:

        return {
            "prediction": "Phishing",
            "risk_level": "High"
        }

    else:

        return {
            "prediction": "Safe",
            "risk_level": "Low"
        }
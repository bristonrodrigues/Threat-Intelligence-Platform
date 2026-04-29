import joblib
import numpy as np


# STEP 1 — Load Model

model = joblib.load("../models/phishing_model.pkl")

print("ML Model Loaded Successfully")


# STEP 2 — Load Scaler

scaler = joblib.load("../models/scaler.pkl")

print("Scaler Loaded Successfully")


# STEP 3 — Create Sample Input

sample_data = np.array([
    [
        100,  # url_length
        1,    # valid_url
        0,    # at_symbol
        2,    # sensitive_words_count
        30,   # path_length
        1,    # isHttps
        3,    # nb_dots
        1,    # nb_hyphens
        0,    # nb_and
        0,    # nb_or
        1,    # nb_www
        1,    # nb_com
        0     # nb_underscore
    ]
])


# STEP 4 — Normalize Input

sample_scaled = scaler.transform(sample_data)

print("Input Normalized")


# STEP 5 — Predict

prediction = model.predict(sample_scaled)

print("Prediction:", prediction)


# STEP 6 — Interpret Result

if prediction[0] == 1:
    print("Phishing Website Detected")
else:
    print("Safe Website")
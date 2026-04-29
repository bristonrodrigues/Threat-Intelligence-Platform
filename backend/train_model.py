import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import StandardScaler


# STEP 1 — Load Dataset

data = pd.read_csv("../datasets/phishing.csv")

print("Dataset Loaded Successfully")


# STEP 2 — Remove Null Values

data = data.dropna()

print("Null Values Removed")


# STEP 3 — Separate Features and Target

X = data.drop("target", axis=1)

y = data["target"]

print("Features and Target Separated")


# STEP 4 — Normalize Features

scaler = StandardScaler()

X_scaled = scaler.fit_transform(X)

print("Features Normalized")


# STEP 5 — Split Dataset

X_train, X_test, y_train, y_test = train_test_split(
    X_scaled,
    y,
    test_size=0.2,
    random_state=42
)

print("Dataset Split Completed")


# STEP 6 — Create Random Forest Model

model = RandomForestClassifier()

print("Random Forest Model Created")


# STEP 7 — Train Model

model.fit(X_train, y_train)

print("Model Training Completed")


# STEP 8 — Test Model

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("Model Accuracy:", accuracy)


# STEP 9 — Save ML Model

joblib.dump(model, "../models/phishing_model.pkl")

print("ML Model Saved Successfully")


# STEP 10 — Save Scaler

joblib.dump(scaler, "../models/scaler.pkl")

print("Scaler Saved Successfully")
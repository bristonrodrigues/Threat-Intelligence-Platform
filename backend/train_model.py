import time

from sklearn.metrics import confusion_matrix

from sklearn.metrics import classification_report
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import StandardScaler


# Load Dataset

data = pd.read_csv("../datasets/phishing.csv")

print("Dataset Loaded")


# Remove Null Values

data = data.dropna()

print("Null Values Removed")


# Features and Labels

X = data.drop('target', axis=1)

y = data['target']
print(data['target'].value_counts())

# Normalize Features

scaler = StandardScaler()

X_scaled = scaler.fit_transform(X)

print("Features Normalized")


# Split Dataset

X_train, X_test, y_train, y_test = train_test_split(
    X_scaled,
    y,
    test_size=0.2,
    random_state=42
)

print("Dataset Split Completed")


# Train Model

model = RandomForestClassifier()

model.fit(X_train, y_train)

print("Model Training Completed")


# Test Accuracy
start_time = time.time()
predictions = model.predict(X_test)
end_time = time.time()

prediction_time = end_time - start_time

print(
    "Prediction Time:",
    round(prediction_time, 4),
    "seconds"
)

accuracy = accuracy_score(y_test, predictions)
print(
    "Model Accuracy:",
    round(accuracy * 100, 2),
    "%"
)

print("Accuracy:", round(accuracy * 100, 2), "%")
print("\nClassification Report:\n")

print(
    classification_report(
        y_test,
        predictions
    )
)
print("\nConfusion Matrix:\n")

print(
    confusion_matrix(
        y_test,
        predictions
    )
)


# Save Model

joblib.dump(
    model,
    "../models/phishing_model.pkl"
)

print("Model Saved")


# Save Scaler

joblib.dump(
    scaler,
    "../models/scaler.pkl"
)

print("Scaler Saved")
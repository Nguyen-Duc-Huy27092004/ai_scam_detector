import joblib
from backend.ml.url.feature_extraction import extract_features_from_url

model = joblib.load("models/phishing_detector.pkl")
scaler = joblib.load("models/scaler.pkl")

def predict_url(url: str) -> dict:
    features = extract_features_from_url(url)
    features_scaled = scaler.transform([features])

    prediction = model.predict(features_scaled)[0]
    probability = model.predict_proba(features_scaled)[0].max()

    return {
        "prediction": int(prediction),
        "label": "phishing" if prediction == 1 else "safe",
        "confidence": round(float(probability), 3)
    }

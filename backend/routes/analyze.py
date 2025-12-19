from flask import Blueprint, request, jsonify
import joblib

from backend.ml.url.feature_extraction import extract_features_from_url
from backend.services.risk_level import calculate_risk
from backend.services.advisor import generate_advice
from backend.utils.validators import is_valid_url
from backend.utils.logger import logger

analyze_bp = Blueprint("analyze", __name__)

# Load model and scaler
model = joblib.load("models/phishing_detector.pkl")
scaler = joblib.load("models/scaler.pkl")
logger.info(f"Analyzing URL: {url}")

@analyze_bp.route("/api/predict", methods=["POST"])
def analyze_url():
    try:
        data = request.get_json()
        url = data.get("url", "").strip()

        if not url:
            return jsonify({"error": "URL is required"}), 400

        if not is_valid_url(url):
            return jsonify({
                "error": "Invalid URL format",
                "advice": "Vui lòng nhập URL hợp lệ, ví dụ: https://example.com"
            }), 400

        # Feature extraction
        features = extract_features_from_url(url)

        if len(features) != 48:
            return jsonify({
                "error": "Feature extraction error",
                "details": f"Expected 48 features, got {len(features)}"
            }), 500

        # Prediction
        features_scaled = scaler.transform([features])
        prediction = int(model.predict(features_scaled)[0])
        confidence = float(model.predict_proba(features_scaled)[0][prediction])

        # ===== Risk & advice =====
        risk_level = calculate_risk(prediction, confidence)
        advice = generate_advice(
            url=url,
            prediction=prediction,
            confidence=confidence,
            risk_level=risk_level
        )

        return jsonify({
            "url": url,
            "label": "phishing" if prediction == 1 else "safe",
            "risk_level": risk_level,
            "confidence": round(confidence, 3),
            "advice": advice
        })

    except Exception as e:
        return jsonify({
            "error": "Internal server error",
            "details": str(e)
        }), 500

from flask import Flask, request, jsonify
import joblib
from backend.ml.url.feature_extraction import extract_features_from_url
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  
model = joblib.load("models/phishing_detector.pkl")
scaler = joblib.load("models/scaler.pkl")

@app.route("/", methods=["GET"])
def health_check():
    return jsonify({
        "status": "AI Scam Detector API is running"
    })

@app.route("/api/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()
        url = data.get("url")

        if not url:
            return jsonify({"error": "URL is required"}), 400
        features = extract_features_from_url(url)
        features_scaled = scaler.transform([features])

        prediction = model.predict(features_scaled)[0]

        return jsonify({
            "prediction": int(prediction),
            "label": "phishing" if prediction == 1 else "safe"
        })

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

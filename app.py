from flask import Flask, render_template, request
import joblib
import numpy as np
from feature_extraction import extract_features_from_url

app = Flask(__name__)

# Load mô hình và scaler
model = joblib.load("models/phishing_detector.pkl")
scaler = joblib.load("models/scaler.pkl")

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        url = request.form['url']
        features = extract_features_from_url(url)
        features_scaled = scaler.transform(features)
        prediction = model.predict(features_scaled)[0]

        result = "⚠️ Phishing (Lừa đảo)" if prediction == 1 else "✅ Safe (An toàn)"
        return render_template('index.html', prediction_text=result, url=url)

    except Exception as e:
        return render_template('index.html', prediction_text=f"Lỗi: {str(e)}")

if __name__ == "__main__":
    app.run(debug=True)

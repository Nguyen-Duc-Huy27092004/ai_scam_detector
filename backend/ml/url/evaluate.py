import joblib
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

MODEL_PATH = "models/phishing_detector.pkl"
SCALER_PATH = "models/scaler.pkl"
DATA_PATH = "data/phishing.csv"

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

df = pd.read_csv(DATA_PATH)

X = df.drop(columns=["CLASS_LABEL", "id"], errors="ignore")
y = df["CLASS_LABEL"]

X_scaled = scaler.transform(X)

y_pred = model.predict(X_scaled)

print("📊 Evaluation on full dataset")
print("Accuracy:", accuracy_score(y, y_pred))
print("\nClassification Report:")
print(classification_report(y, y_pred))
print("\nConfusion Matrix:")
print(confusion_matrix(y, y_pred))

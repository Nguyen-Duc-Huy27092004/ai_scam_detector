import joblib
from pathlib import Path

import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

BASE_DIR = Path(__file__).resolve().parent.parent.parent
MODEL_PATH = BASE_DIR / "models" / "phishing_detector.pkl"
SCALER_PATH = BASE_DIR / "models" / "scaler.pkl"
DATA_PATH = BASE_DIR / "data" / "phishing.csv"


def main() -> None:
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


if __name__ == "__main__":
    main()

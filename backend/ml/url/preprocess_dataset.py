import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib
import os

df = pd.read_csv("data/phishing.csv")
print("Tổng số mẫu:", len(df))

if "id" in df.columns:
    df = df.drop(columns=["id"])

X = df.drop(columns=["CLASS_LABEL"])
y = df["CLASS_LABEL"]

print("Số feature:", X.shape[1])

if X.shape[1] != 48:
    raise ValueError(f"Dataset có {X.shape[1]} feature, nhưng model yêu cầu 48")

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

os.makedirs("models", exist_ok=True)
joblib.dump(scaler, "models/scaler.pkl")

print("Preprocess hoàn tất")
print("Train samples:", X_train_scaled.shape[0])
print("Test samples:", X_test_scaled.shape[0])
print("Scaler saved to models/scaler.pkl")

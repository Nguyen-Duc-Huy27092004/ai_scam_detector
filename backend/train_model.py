import pandas as pd
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

df = pd.read_csv("data/phishing.csv")

if "id" in df.columns:
    df = df.drop(columns=["id"])

X = df.drop(columns=["CLASS_LABEL"])
y = df["CLASS_LABEL"]

print("🔢 Số feature:", X.shape[1])

if X.shape[1] != 48:
    raise ValueError(f" Dataset có {X.shape[1]} feature, nhưng hệ thống yêu cầu 48")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

model = RandomForestClassifier(
    n_estimators=200,
    max_depth=12,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

print(" Đang huấn luyện mô hình Random Forest...")
model.fit(X_train_scaled, y_train)
print(" Huấn luyện hoàn tất!")

y_pred = model.predict(X_test_scaled)

acc = accuracy_score(y_test, y_pred)
print(f"\n Accuracy: {acc * 100:.2f}%")

print("\n Classification Report:")
print(classification_report(y_test, y_pred))

print("\n Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

os.makedirs("models", exist_ok=True)

joblib.dump(model, "models/phishing_detector.pkl")
joblib.dump(scaler, "models/scaler.pkl")

print("\n Model & scaler đã được lưu vào thư mục /models/")

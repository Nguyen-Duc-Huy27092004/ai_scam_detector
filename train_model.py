# train_model.py
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# 1️⃣ Đọc dữ liệu
df = pd.read_csv("data/phishing.csv")
df = df.drop(columns=["id"])

# 2️⃣ Xác định X và y
X = df.drop(columns=["CLASS_LABEL"])
y = df["CLASS_LABEL"]

# 3️⃣ Chuẩn hóa dữ liệu
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# 4️⃣ Chia dữ liệu train/test
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42
)

# 5️⃣ Huấn luyện mô hình
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=12,
    random_state=42,
    n_jobs=-1
)

print("🚀 Đang huấn luyện mô hình...")
model.fit(X_train, y_train)
print("✅ Huấn luyện xong!")

# 6️⃣ Đánh giá mô hình
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)

print(f"🎯 Độ chính xác (Accuracy): {acc*100:.2f}%")
print("\n📊 Báo cáo chi tiết:\n", classification_report(y_test, y_pred))
print("\n🔍 Ma trận nhầm lẫn:\n", confusion_matrix(y_test, y_pred))

# 7️⃣ Lưu mô hình & scaler để dùng cho Flask sau này
joblib.dump(model, "models/phishing_detector.pkl")
joblib.dump(scaler, "models/scaler.pkl")

print("\n💾 Mô hình và scaler đã được lưu vào thư mục /models/")

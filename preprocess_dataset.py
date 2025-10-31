import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# 1️⃣ Đọc dữ liệu
df = pd.read_csv("data/phishing.csv")

print("🔹 Số lượng dữ liệu ban đầu:", len(df))

# 2️⃣ Loại bỏ cột 'id' (vì không phải đặc trưng)
df = df.drop(columns=["id"])

# 3️⃣ Xác định đặc trưng (X) và nhãn (y)
X = df.drop(columns=["CLASS_LABEL"])
y = df["CLASS_LABEL"]

# 4️⃣ Chuẩn hóa dữ liệu (scale)
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# 5️⃣ Chia dữ liệu train/test
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42
)

print("✅ Dữ liệu train/test đã sẵn sàng!")
print("Số mẫu train:", X_train.shape[0])
print("Số mẫu test:", X_test.shape[0])

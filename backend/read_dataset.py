import pandas as pd

# ===== Load dataset =====
df = pd.read_csv("data/phishing.csv")

print("5 dòng đầu tiên:")
print(df.head())

print("\nThông tin dataset:")
print(df.info())

print("\n Danh sách cột:")
print(df.columns.tolist())

if "CLASS_LABEL" not in df.columns:
    raise ValueError(" Không tìm thấy cột CLASS_LABEL")

print("\n Phân bố nhãn (CLASS_LABEL):")
print(df["CLASS_LABEL"].value_counts())

# ===== Check missing values =====
print("\nMissing values:")
print(df.isnull().sum().sum())

# ===== Feature count =====
feature_cols = [col for col in df.columns if col not in ["CLASS_LABEL", "id"]]
print("\n🔢 Số feature:", len(feature_cols))

if len(feature_cols) != 48:
    print(" CẢNH BÁO: Số feature ≠ 48 (cần khớp với feature_extraction.py)")
else:
    print(" Số feature KHỚP (48)")

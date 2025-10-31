import pandas as pd

# Đọc dữ liệu phishing
df = pd.read_csv("data/phishing.csv")

print("📊 5 dòng đầu tiên trong dataset:")
print(df.head())

print("\n📈 Thông tin dataset:")
print(df.info())

# Kiểm tra cột nhãn (label)
label_cols = [col for col in df.columns if 'label' in col.lower() or 'class' in col.lower()]
if label_cols:
    label_col = label_cols[0]
    print(f"\n🔍 Phân bố nhãn ({label_col}):")
    print(df[label_col].value_counts())
else:
    print("\n⚠️ Không tìm thấy cột nhãn, cần xem lại cấu trúc dataset.")

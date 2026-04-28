# AI Scam Detector Backend - Refactored

Hệ thống Backend (Flask) cho AI Scam Detector - chuyên phát hiện các URL lừa đảo, hình ảnh độc hại và văn bản scam bằng cách sử dụng các mô hình Machine Learning và các kỹ thuật phân tích chuyên sâu. 

> **Lưu ý về Kiến trúc Hệ thống:** Hệ thống được thiết kế mở và không trạng thái (stateless), không yêu cầu chức năng đăng nhập/đăng xuất (Login/Logout) từ người dùng. Mọi truy vấn phân tích đều có thể thực hiện thông qua API và dữ liệu phân tích được lưu trữ công khai (public history) cho mục đích tra cứu và học máy.

## 🏗️ Kiến trúc Hệ thống

Backend được xây dựng dựa trên nguyên tắc **clean architecture** với sự phân chia rõ ràng về các thành phần:

```
backend/
├── app.py                      # Khởi tạo ứng dụng Flask (App factory)
├── config.py                   # Quản lý cấu hình môi trường
├── routes/                     # Các Endpoints HTTP (Xử lý request/response)
├── services/                   # Logic nghiệp vụ (Business logic) & luồng phân tích
├── ml/                         # Mô hình AI & Xử lý suy luận (Inference)
├── ocr/                        # Trích xuất văn bản từ hình ảnh (OCR)
├── database/                   # Tương tác cơ sở dữ liệu SQLite
└── utils/                      # Các hàm hỗ trợ & xác thực dữ liệu
```

### Luồng Phân Tích (Pipelines)

Hệ thống hiện tại triển khai 3 luồng phân tích chính:

#### 🔗 Luồng Phân Tích URL
1. **ML Prediction** → Phát hiện URL lừa đảo thông qua mô hình Machine Learning.
2. **Domain Intelligence** → Tuổi tên miền, WHOIS, phát hiện các mẫu URL đáng ngờ.
3. **Content Extraction** → Trích xuất HTML/văn bản từ trang web.
4. **Screenshot Capture** → Chụp ảnh màn hình trang web làm bằng chứng.
5. **Content Analysis** → Quét các dấu hiệu lừa đảo trong nội dung website.
6. **Risk Calculation** → Đánh giá tổng hợp và tính điểm rủi ro (Risk Engine).
7. **Advice Generation** → Tạo lời khuyên hành động nhờ LLM/AI.
8. **Database Save** → Lưu lại lịch sử phân tích vào CSDL.

#### 🖼️ Luồng Phân Tích Hình Ảnh
1. **Image ML Prediction** → Ứng dụng Deep Learning để phân loại hình ảnh scam.
2. **OCR Extraction** → Trích xuất văn bản từ ảnh.
3. **OCR Text Analysis** → Phân tích ngôn từ lừa đảo trong nội dung OCR.
4. **Risk Calculation** → Đánh giá tổng hợp điểm rủi ro.
5. **Advice Generation** → Đưa ra khuyến nghị.
6. **Database Save** → Lưu lại lịch sử phân tích.

#### 📝 Luồng Phân Tích Văn Bản
1. **Text Classification** → Nhận diện các từ khóa lừa đảo.
2. **Keyword Extraction** → Trích xuất các cụm từ đáng ngờ.
3. **Risk Calculation** → Đánh giá rủi ro dựa trên trọng số từ khóa.
4. **Advice Generation** → Đưa ra lời khuyên.
5. **Database Save** → Lưu lại lịch sử phân tích.

## 🚀 Các Tính Năng Nổi Bật

### ✅ Đã triển khai
- **Phân tích URL**: Nhận diện phishing, phân tích domain, nội dung web.
- **Phân tích Hình ảnh**: Nhận diện scam, trích xuất OCR, đánh giá rủi ro kết hợp.
- **Phân tích Văn bản**: Nhận diện các ngôn từ lừa đảo.
- **Lưu trữ Lịch sử**: Lưu trữ kết quả bằng SQLite (Lưu ý: Không dùng cơ chế User/Login, mọi dữ liệu được lưu tự động cho hệ thống).
- **Batch Processing**: Hỗ trợ phân tích hàng loạt URL/Image/Text trong một Request.
- **Các mức độ rủi ro**: Phân loại theo Low/Medium/High/Critical.
- **Lời khuyên AI (AI Advice)**: Khuyến nghị theo ngữ cảnh cho người dùng.
- **Logging Toàn diện**: Mọi hoạt động được ghi nhận log đầy đủ.
- **Xử lý Lỗi (Error Handling)**: Tích hợp Fallback an toàn và trả về phản hồi chi tiết.
- **CORS**: Hỗ trợ tích hợp đa Frontend.

### 📊 Các Thành phần Phân Tích
- **Mô hình ML**: Mô hình nhận diện Phishing và phân loại hình ảnh đã được huấn luyện.
- **Feature Extraction**: Trích xuất đặc trưng URL cho ML.
- **Domain Intel**: Whois, tuổi tên miền, kiểm tra mẫu rủi ro.
- **Web Scraping**: BeautifulSoup.
- **Screenshots**: Selenium/Playwright để chụp trang ẩn danh.
- **OCR**: Tesseract để đọc tiếng Anh & tiếng Việt.
- **NLP**: Trích xuất từ khóa, phân tích mẫu (pattern matching).
- **Risk Scoring**: Risk Engine chuyên sâu tích hợp nhiều tín hiệu độc hại.

## 📋 API Endpoints

### Health & Status
- `GET /api/health` - Kiểm tra trạng thái hệ thống.
- `GET /api/version` - Thông tin phiên bản API.

### Phân Tích URL
- `POST /api/url/analyze` - Phân tích một URL
- `POST /api/url/batch-analyze` - Phân tích nhiều URL
- `GET /api/url/features/<url>` - Lấy đặc trưng URL (chế độ debug)

### Phân Tích Hình Ảnh
- `POST /api/image/analyze` - Phân tích một ảnh tải lên
- `POST /api/image/batch-analyze` - Phân tích nhiều ảnh

### Phân Tích Văn Bản
- `POST /api/text/analyze` - Phân tích văn bản
- `POST /api/text/batch-analyze` - Phân tích nhiều văn bản
- `GET /api/text/keywords` - Lấy danh sách từ khóa nguy hiểm

### Lịch Sử & Thống Kê
*(Endpoint lưu trữ nội dung cho toàn hệ thống - không yêu cầu xác thực)*
- `GET /api/history/all` - Lấy tất cả lịch sử phân tích
- `GET /api/history/by-type/<type>` - Lấy theo loại phân tích
- `GET /api/history/by-risk/<level>` - Lấy theo cấp độ rủi ro
- `GET /api/history/record/<id>` - Lấy bản ghi cụ thể
- `GET /api/history/statistics` - Thống kê tổng quan
- `POST /api/history/cleanup` - Xóa bản ghi cũ

## 🔧 Cấu Hình Hệ Thống

### Environment Variables
Tạo file `.env` trong thư mục backend:

```env
# Flask
FLASK_DEBUG=True
FLASK_HOST=0.0.0.0
FLASK_PORT=5000

# CORS
CORS_ORIGINS=http://localhost:3000,http://localhost:8000

# File Upload
MAX_IMAGE_SIZE_MB=10

# Timeouts
SCREENSHOT_TIMEOUT=10
CONTENT_EXTRACTION_TIMEOUT=10
OCR_TIMEOUT=30
ANALYSIS_TIMEOUT=60

# ML Model Thresholds
PHISHING_CONFIDENCE_THRESHOLD=0.5
IMAGE_SCAM_CONFIDENCE_THRESHOLD=0.6
TEXT_SCAM_CONFIDENCE_THRESHOLD=0.5

# Risk Levels
RISK_LEVEL_LOW=0.3
RISK_LEVEL_MEDIUM=0.6

# Logging
LOG_LEVEL=INFO

# Database
DATABASE_TYPE=sqlite

# Rate Limiting
RATE_LIMIT_ENABLED=True
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=3600
```

## 📦 Cài Đặt

### Yêu Cầu Hệ Thống (Prerequisites)
- Python 3.9+
- Tesseract OCR (để trích xuất text từ hình ảnh)
- Chrome/Chromium (để chụp màn hình website)

### Các Bước Cài Đặt

1. **Clone mã nguồn và vào thư mục backend**
```bash
cd backend
```

2. **Cài đặt thư viện**
```bash
pip install -r requirements.txt
```

3. **Cài đặt Tesseract OCR**
```bash
# Ubuntu/Debian
sudo apt-get install tesseract-ocr

# macOS
brew install tesseract

# Windows
# Tải và cài đặt từ: https://github.com/UB-Mannheim/tesseract/wiki
```

4. **Cài đặt Browser cho Playwright** (Tùy chọn, để chụp màn hình)
```bash
playwright install
```

5. **Tạo file cấu hình .env**
```bash
cp .env.example .env
```

6. **Khởi tạo cơ sở dữ liệu**
```bash
python -c "from database.db import get_db; get_db()"
```

7. **Chạy Server**
```bash
# Môi trường Development
python app.py

# Môi trường Production (Sử dụng Gunicorn)
gunicorn -w 4 -b 0.0.0.0:5000 app:create_app()
```

## 📚 Ví Dụ Sử Dụng (Usage)

### Phân Tích URL
```bash
curl -X POST http://localhost:5000/api/url/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### Phân Tích Hình Ảnh
```bash
curl -X POST http://localhost:5000/api/image/analyze \
  -F "image=@/path/to/image.jpg"
```

### Phân Tích Văn Bản
```bash
curl -X POST http://localhost:5000/api/text/analyze \
  -H "Content-Type: application/json" \
  -d '{"text": "Click here to verify your account urgently!"}'
```

## 🧪 Testing

### Chạy Unit Test
```bash
pytest -v
```

### Xuất báo cáo Coverage
```bash
pytest --cov=. --cov-report=html
```

## 🔐 Bảo Mật & Security Features

*(Do hệ thống không sử dụng tính năng Authentication/Login, bảo mật sẽ tập trung vào API, Input, và Infrastructure)*
- ✅ **Input Validation**: Mọi dữ liệu đầu vào đều được kiểm tra an toàn.
- ✅ **Rate Limiting**: Giới hạn số lượng request để chống Spam/DDoS.
- ✅ **File Upload Constraints**: Giới hạn kích thước và định dạng file upload.
- ✅ **Anti-SSRF**: Bảo vệ các luồng scrape nội dung/website tránh tấn công vào mạng nội bộ (Internal Network).
- ✅ **SQL Injection Prevention**: Sử dụng Parametrized Queries trong SQLite.
- ✅ **CORS Management**: Chỉ cho phép các Frontend/Domain hợp lệ gọi API.
- ✅ **Secure Errors**: Ẩn các Stack Trace nhạy cảm khi ở chế độ Production.

## 🐛 Khắc Phục Sự Cố (Troubleshooting)

### Lỗi Tesseract Not Found
```bash
# Thêm đường dẫn cài đặt Tesseract vào file .env hoặc biến môi trường
export TESSERACT_PATH="/usr/bin/tesseract"
```

### Lỗi Không Tìm Thấy Mô Hình ML (Model File Not Found)
Đảm bảo bạn đã có sẵn thư mục `models/` và các file:
- `phishing_detector.pkl`
- `scaler.pkl`
- `image_model/scam_image_model.h5`

### Lỗi Chụp Màn Hình (Screenshot Failures)
Cài đặt browser tương ứng:
```bash
playwright install chromium
```

## 🔄 Cơ Sở Dữ Liệu

Dữ liệu lưu tại `data/analysis_history.db`.
Hệ thống sử dụng SQLite. Việc lưu trữ không liên kết tới người dùng (No Users/Accounts). 

### Schema tham khảo:
```sql
CREATE TABLE analysis_history (
  id INTEGER PRIMARY KEY,
  input_type TEXT,
  input_value TEXT,
  label TEXT,
  risk_level TEXT,
  confidence REAL,
  advice TEXT,
  screenshot_path TEXT,
  ocr_text TEXT,
  evidence_json TEXT,
  model_version TEXT,
  timestamp DATETIME,
  created_at DATETIME,
  updated_at DATETIME
);
```

# AI Scam Detector Backend - Refactored

A production-ready Flask backend for detecting phishing URLs, scam images, and malicious text using machine learning and advanced analysis techniques.

## 🏗️ Architecture

This backend follows **clean architecture principles** with clear separation of concerns:

```
backend/
├── app.py                      # Flask app factory
├── config.py                   # Configuration management
├── routes/                     # HTTP endpoints (request/response only)
├── services/                   # Business logic & pipelines
├── ml/                         # ML models & inference
├── ocr/                        # OCR text extraction
├── database/                   # Database operations
└── utils/                      # Helpers & validators
```

### Pipeline Architecture

The backend implements three main analysis pipelines:

#### 🔗 URL Analysis Pipeline
1. **ML Prediction** → Phishing detection using trained model
2. **Domain Intelligence** → Domain age, WHOIS, suspicious patterns
3. **Content Extraction** → HTML/text extraction from website
4. **Screenshot Capture** → Visual documentation
5. **Content Analysis** → Scam indicators in page content
6. **Risk Calculation** → Weighted risk assessment
7. **Advice Generation** → AI-generated recommendations
8. **Database Save** → Store results for history

#### 🖼️ Image Analysis Pipeline
1. **Image ML Prediction** → Deep learning scam detection
2. **OCR Extraction** → Text extraction from image
3. **OCR Text Analysis** → Scam language detection
4. **Risk Calculation** → Combined risk assessment
5. **Advice Generation** → Recommendations
6. **Database Save** → Store results

#### 📝 Text Analysis Pipeline
1. **Text Classification** → Scam keyword detection
2. **Keyword Extraction** → Suspicious keyword identification
3. **Risk Calculation** → Risk score computation
4. **Advice Generation** → Actionable recommendations
5. **Database Save** → Store results

## 🚀 Features

### ✅ Implemented
- **URL Analysis**: Phishing detection, domain intelligence, content analysis
- **Image Analysis**: Scam detection, OCR text extraction, combined risk scoring
- **Text Analysis**: Scam language detection, keyword identification
- **History Tracking**: SQLite database for analysis persistence
- **Batch Processing**: Process multiple URLs/images/texts in one request
- **Risk Levels**: Low/Medium/High risk classification
- **AI Advice**: Context-aware recommendations for users
- **Comprehensive Logging**: All operations logged with levels
- **Error Handling**: Graceful error handling with detailed responses
- **CORS**: Cross-origin support for frontend integration

### 📊 Analysis Components
- **ML Models**: Pre-trained phishing detector, image classifier
- **Feature Extraction**: URL feature engineering for ML
- **Domain Intel**: Domain age, WHOIS, suspicious patterns detection
- **Web Scraping**: HTML/text extraction with BeautifulSoup
- **Screenshots**: Website visualization with Selenium/Playwright
- **OCR**: Vietnamese + English text extraction with Tesseract
- **NLP**: Pattern matching and keyword analysis
- **Risk Scoring**: Weighted multi-factor risk calculation

## 📋 API Endpoints

### Health & Status
- `GET /api/health` - Service health check
- `GET /api/version` - API version info

### URL Analysis
- `POST /api/url/analyze` - Analyze single URL
- `POST /api/url/batch-analyze` - Analyze multiple URLs
- `GET /api/url/features/<url>` - Get extracted URL features (debug)

### Image Analysis
- `POST /api/image/analyze` - Analyze uploaded image
- `POST /api/image/batch-analyze` - Analyze multiple images

### Text Analysis
- `POST /api/text/analyze` - Analyze text
- `POST /api/text/batch-analyze` - Analyze multiple texts
- `GET /api/text/keywords` - Get suspicious keywords list

### History & Analytics
- `GET /api/history/all` - Get all analysis history
- `GET /api/history/by-type/<type>` - Get history by analysis type
- `GET /api/history/by-risk/<level>` - Get history by risk level
- `GET /api/history/record/<id>` - Get specific record
- `GET /api/history/statistics` - Get analytics summary
- `POST /api/history/cleanup` - Delete old records

## 🔧 Configuration

### Environment Variables
Create `.env` file in backend directory:

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

## 📦 Installation

### Prerequisites
- Python 3.9+
- Tesseract OCR (for text extraction)
- Chrome/Chromium (for screenshots)

### Setup Steps

1. **Clone and navigate to backend**
```bash
cd backend
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Install Tesseract OCR**
```bash
# Ubuntu/Debian
sudo apt-get install tesseract-ocr

# macOS
brew install tesseract

# Windows
Download from: https://github.com/UB-Mannheim/tesseract/wiki
```

4. **Install Playwright browsers** (optional, for screenshots)
```bash
playwright install
```

5. **Create .env file**
```bash
cp .env.example .env
```

6. **Initialize database**
```bash
python -c "from database.db import get_db; get_db()"
```

7. **Run the server**
```bash
# Development
python app.py

# Production with Gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:create_app()
```

## 📚 Usage Examples

### URL Analysis
```bash
curl -X POST http://localhost:5000/api/url/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### Image Analysis
```bash
curl -X POST http://localhost:5000/api/image/analyze \
  -F "image=@/path/to/image.jpg"
```

### Text Analysis
```bash
curl -X POST http://localhost:5000/api/text/analyze \
  -H "Content-Type: application/json" \
  -d '{"text": "Click here to verify your account urgently!"}'
```

### Get History
```bash
curl http://localhost:5000/api/history/all?limit=50&offset=0
```

## 🧪 Testing

### Run tests
```bash
pytest -v
```

### Coverage report
```bash
pytest --cov=. --cov-report=html
```

## 📊 Response Format

### Success Response
```json
{
  "success": true,
  "data": {
    "url": "https://example.com",
    "analysis": {
      "risk_level": "medium",
      "overall_score": 0.65,
      "label": "medium",
      "confidence": 0.78
    },
    "advice": "This URL has some suspicious characteristics...",
    "recommendations": [...],
    "risk_factors": [...],
    "record_id": 123
  },
  "timestamp": "2024-01-26T10:30:45Z"
}
```

### Error Response
```json
{
  "success": false,
  "error": "Invalid URL format",
  "details": {...},
  "timestamp": "2024-01-26T10:30:45Z"
}
```

## 🔐 Security Features

- ✅ Input validation on all endpoints
- ✅ File upload size limits
- ✅ SQL injection prevention (parameterized queries)
- ✅ XSS protection via output encoding
- ✅ CORS configuration
- ✅ Rate limiting ready
- ✅ Secure error messages (no stack traces in production)
- ✅ Logging of all operations
- ✅ No hardcoded credentials

## 📈 Performance Considerations

- **Async Operations**: Screenshots and OCR can be long-running
- **Batch Processing**: Process multiple items in one request
- **Caching**: Model caching to avoid reloading
- **Database Indexing**: Indexed on frequently queried fields
- **Pagination**: History endpoints support pagination

## 🐛 Troubleshooting

### Tesseract not found
```bash
# Set Tesseract path in config or environment
export TESSERACT_PATH="/usr/bin/tesseract"
```

### Model file not found
Ensure trained models are in `models/` directory:
- `phishing_detector.pkl`
- `scaler.pkl`
- `image_model/scam_image_model.h5`

### Screenshot failures
Install required browser:
```bash
playwright install chromium
# or use Chrome with Selenium
```

## 📝 Logging

Logs are stored in `data/app.log` with rotation:
- Max file size: 10 MB
- Backup count: 5 files
- Format: `timestamp - logger - level - message`

## 🔄 Database

SQLite database stored at `data/analysis_history.db`

### Schema
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

## 🚀 Production Deployment

### Using Gunicorn
```bash
gunicorn -w 4 -b 0.0.0.0:5000 \
  --access-logfile - \
  --error-logfile - \
  --log-level info \
  app:create_app()
```

### Using Docker
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:create_app()"]
```

### Environment for Production
```env
FLASK_DEBUG=False
LOG_LEVEL=WARNING
RATE_LIMIT_ENABLED=True
```

## 📄 License

This project is for academic and research purposes.

## 🤝 Contributing

Guidelines for contributing:
1. Follow PEP 8 style guide
2. Add logging for important operations
3. Write tests for new features
4. Update documentation
5. Run code formatting: `black .`

## 📞 Support

For issues or questions:
1. Check logs in `data/app.log`
2. Review error responses
3. Enable debug mode: `FLASK_DEBUG=True`
4. Check configuration in `.env`

"""
Image scam detection predictor.
Combine ML + OCR + heuristic reasoning.
"""

import json
import torch
from torchvision import models, transforms
from PIL import Image
from typing import Dict, Any
from pathlib import Path

from backend.utils.logger import logger
from backend.ml.image.ocr import extract_text_from_image
from config import IMAGE_MODEL_PATH, IMAGE_LABELS_PATH

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")


SCAM_KEYWORDS = {
    "verify": "Yêu cầu xác minh tài khoản",
    "login": "Trang đăng nhập giả mạo",
    "password": "Thu thập mật khẩu",
    "bank": "Giả mạo ngân hàng",
    "transfer": "Yêu cầu chuyển tiền",
    "urgent": "Ngôn từ khẩn cấp",
    "otp": "Đánh cắp mã OTP",
    "reward": "Lừa đảo trúng thưởng",
    "prize": "Giải thưởng giả",
    "lottery": "Lừa đảo trúng số",
}


class ImageScamPredictor:
    _model = None
    _labels = None

    @staticmethod
    def load_model():
        if ImageScamPredictor._model is not None:
            return True

        try:
            if not IMAGE_MODEL_PATH.exists():
                logger.error("image_model_not_found")
                return False

            with open(IMAGE_LABELS_PATH, "r", encoding="utf-8") as f:
                ImageScamPredictor._labels = json.load(f)

            num_classes = len(ImageScamPredictor._labels)
            model = models.resnet18(pretrained=False)
            model.fc = torch.nn.Linear(model.fc.in_features, num_classes)

            model.load_state_dict(torch.load(IMAGE_MODEL_PATH, map_location=device))
            model.to(device)
            model.eval()

            ImageScamPredictor._model = model
            logger.info("image_model_loaded")
            return True

        except Exception as e:
            logger.error("image_model_load_failed | %s", str(e))
            return False

    @staticmethod
    def predict(image_path: str) -> Dict[str, Any]:
        try:
            if not ImageScamPredictor.load_model():
                return {"offer": "Model not available"}

            # ===== ML prediction =====
            transform = transforms.Compose([
                transforms.Resize((224, 224)),
                transforms.ToTensor()
            ])

            img = Image.open(image_path).convert("RGB")
            img_tensor = transform(img).unsqueeze(0).to(device)

            with torch.no_grad():
                outputs = ImageScamPredictor._model(img_tensor)
                probs = torch.softmax(outputs, dim=1)
                conf, pred = torch.max(probs, 1)

            label = ImageScamPredictor._labels.get(str(pred.item()), "unknown")
            confidence = float(conf.item())

            # ===== OCR =====
            ocr_text = extract_text_from_image(image_path).lower()

            evidence = []
            scam_score = confidence

            for key, desc in SCAM_KEYWORDS.items():
                if key in ocr_text:
                    scam_score += 0.1
                    evidence.append({
                        "source": "ocr",
                        "keyword": key,
                        "explanation": desc,
                        "severity": "high",
                        "flag_name": "scam_keyword"
                    })

            scam_score = min(scam_score, 1.0)

            if scam_score >= 0.7:
                risk_level = "high"
                is_scam = True
            elif scam_score >= 0.4:
                risk_level = "medium"
                is_scam = False
            else:
                risk_level = "low"
                is_scam = False

            return {
                "label": label,
                "confidence": confidence,
                "is_scam": is_scam,
                "risk_level": risk_level,
                "scam_score": scam_score,
                "ocr_text_preview": ocr_text[:300],
                "evidence": evidence
            }

        except Exception as e:
            logger.error("image_predict_failed | %s", str(e))
            return {"error": str(e)}


def predict_image(image_path: str) -> Dict[str, Any]:
    return ImageScamPredictor.predict(image_path)
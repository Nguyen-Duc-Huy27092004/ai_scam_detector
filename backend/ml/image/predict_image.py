"""
Image Scam Detector — ML Predictor.

Supports two model formats:
  - PyTorch  (.pth)  — ResNet-18 fine-tuned (preferred)
  - Keras/TF (.h5)   — Legacy Keras model (fallback)

The predictor auto-detects the format from the file extension configured in
`IMAGE_MODEL_PATH`. If neither format is available the pipeline degrades
gracefully to OCR+keyword heuristics only.
"""

import json
import threading
from typing import Dict, Any, Optional
from pathlib import Path

from utils.logger import logger
from utils.config import (
    IMAGE_MODEL_PATH,
    IMAGE_LABELS_PATH,
    IMAGE_SCAM_CONFIDENCE_THRESHOLD,
)

# ---------------------------------------------------------------------------
# OCR helper — centralised in ocr/ocr_engine.py (returns (str, metadata))
# ---------------------------------------------------------------------------
try:
    from ocr.ocr_engine import extract_text_from_image as _ocr_extract
    def _ocr_text(image_path: str) -> str:
        text, _ = _ocr_extract(image_path)
        return (text or "").lower()
except Exception:
    def _ocr_text(image_path: str) -> str:  # type: ignore[misc]
        return ""


def _read_labels_dict(path: Path) -> Optional[Dict[str, str]]:
    try:
        content = path.read_text(encoding="utf-8").strip()
        if not content:
            logger.error("image_labels_empty | path=%s", path)
            return None
        data = json.loads(content)
        if not data:
            logger.error("image_labels_invalid | path=%s", path)
            return None
        return data
    except json.JSONDecodeError as e:
        logger.error("image_labels_json_error | path=%s | %s", path, str(e))
        return None


# ---------------------------------------------------------------------------
# Keyword scoring
# ---------------------------------------------------------------------------

SCAM_KEYWORDS: Dict[str, str] = {
    "verify":   "Yêu cầu xác minh tài khoản",
    "login":    "Trang đăng nhập giả mạo",
    "password": "Thu thập mật khẩu",
    "bank":     "Giả mạo ngân hàng",
    "transfer": "Yêu cầu chuyển tiền",
    "urgent":   "Ngôn từ khẩn cấp",
    "otp":      "Đánh cắp mã OTP",
    "reward":   "Lừa đảo trúng thưởng",
    "prize":    "Giải thưởng giả",
    "lottery":  "Lừa đảo trúng số",
}


# ---------------------------------------------------------------------------
# PyTorch predictor
# ---------------------------------------------------------------------------

class _TorchPredictor:
    _model = None
    _labels: Optional[Dict[str, str]] = None
    _loaded: bool = False
    _load_failed: bool = False
    _load_lock = threading.Lock()

    @classmethod
    def _try_load(cls) -> bool:
        if cls._loaded:
            return True
        if cls._load_failed:
            return False
        with cls._load_lock:
            if cls._loaded:
                return True
            if cls._load_failed:
                return False
            try:
                import torch
                from torchvision import models, transforms  # noqa: F401

                model_path = Path(IMAGE_MODEL_PATH)
                if not model_path.exists():
                    logger.warning("torch_image_model_not_found | path=%s", model_path)
                    cls._load_failed = True
                    return False

                if not IMAGE_LABELS_PATH.exists():
                    logger.warning("image_labels_not_found | path=%s", IMAGE_LABELS_PATH)
                    cls._load_failed = True
                    return False

                labels = _read_labels_dict(Path(IMAGE_LABELS_PATH))
                if labels is None:
                    cls._load_failed = True
                    return False
                cls._labels = labels

                num_classes = len(cls._labels)
                device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

                model = models.resnet18(weights=None)
                model.fc = torch.nn.Linear(model.fc.in_features, num_classes)
                model.load_state_dict(
                    torch.load(str(model_path), map_location=device, weights_only=True)
                )
                model.to(device)
                model.eval()

                cls._model = model
                cls._loaded = True
                logger.info("torch_image_model_loaded | path=%s", model_path)
                return True

            except Exception as e:
                logger.error("torch_image_model_load_failed | %s", str(e))
                cls._load_failed = True
                return False

    @classmethod
    def predict(cls, image_path: str) -> Optional[Dict[str, Any]]:
        if not cls._try_load():
            return None
        try:
            import torch
            from torchvision import transforms
            from PIL import Image

            device = next(cls._model.parameters()).device  # type: ignore[union-attr]
            transform = transforms.Compose([
                transforms.Resize((224, 224)),
                transforms.ToTensor(),
                transforms.Normalize(
                    mean=[0.485, 0.456, 0.406],
                    std=[0.229, 0.224, 0.225],
                ),
            ])

            img = Image.open(image_path).convert("RGB")
            tensor = transform(img).unsqueeze(0).to(device)

            with torch.no_grad():
                outputs = cls._model(tensor)  # type: ignore[misc]
                probs = torch.softmax(outputs, dim=1)
                conf, pred = torch.max(probs, 1)

            label = (cls._labels or {}).get(str(pred.item()), "unknown")
            return {
                "label": label,
                "confidence": float(conf.item()),
                "backend": "pytorch",
            }
        except Exception as e:
            logger.error("torch_predict_failed | %s", str(e))
            return None


# ---------------------------------------------------------------------------
# Keras/TF predictor (legacy .h5)
# ---------------------------------------------------------------------------

class _KerasPredictor:
    _model = None
    _labels: Optional[Dict[str, str]] = None
    _loaded: bool = False
    _load_failed: bool = False
    _load_lock = threading.Lock()

    @classmethod
    def _try_load(cls) -> bool:
        if cls._loaded:
            return True
        if cls._load_failed:
            return False
        with cls._load_lock:
            if cls._loaded:
                return True
            if cls._load_failed:
                return False
            try:
                from tensorflow import keras  # type: ignore[import]

                if not IMAGE_LABELS_PATH.exists():
                    logger.warning("keras_labels_not_found | path=%s", IMAGE_LABELS_PATH)
                    cls._load_failed = True
                    return False

                labels = _read_labels_dict(Path(IMAGE_LABELS_PATH))
                if labels is None:
                    cls._load_failed = True
                    return False
                cls._labels = labels

                # Try .h5 alongside the configured .pth path
                h5_path = Path(IMAGE_MODEL_PATH).with_suffix(".h5")
                if not h5_path.exists():
                    logger.warning("keras_model_not_found | path=%s", h5_path)
                    cls._load_failed = True
                    return False

                try:
                    cls._model = keras.models.load_model(
                        str(h5_path), compile=False, safe_mode=True
                    )
                except TypeError:
                    cls._model = keras.models.load_model(str(h5_path), compile=False)

                cls._loaded = True
                logger.info("keras_image_model_loaded | path=%s", h5_path)
                return True

            except ImportError:
                logger.debug("tensorflow_not_installed — keras predictor unavailable")
                cls._load_failed = True
                return False
            except Exception as e:
                logger.error("keras_image_model_load_failed | %s", str(e))
                cls._load_failed = True
                return False

    @classmethod
    def predict(cls, image_path: str) -> Optional[Dict[str, Any]]:
        if not cls._try_load():
            return None
        try:
            import numpy as np
            from PIL import Image

            img = Image.open(image_path).convert("RGB").resize((224, 224))
            arr = np.expand_dims(np.array(img) / 255.0, axis=0)
            preds = cls._model.predict(arr, verbose=0)  # type: ignore[union-attr]
            idx = int(np.argmax(preds[0]))
            conf = float(preds[0][idx])
            label = (cls._labels or {}).get(str(idx), "unknown")
            return {
                "label": label,
                "confidence": conf,
                "backend": "keras",
            }
        except Exception as e:
            logger.error("keras_predict_failed | %s", str(e))
            return None


# ---------------------------------------------------------------------------
# Public predictor — auto-selects PyTorch → Keras → heuristic
# ---------------------------------------------------------------------------

class ImageScamPredictor:
    """
    Format-agnostic image scam predictor.

    Resolution order:
      1. PyTorch  (.pth) — tried first if IMAGE_MODEL_PATH has .pth extension
      2. Keras/TF (.h5)  — tried if PyTorch fails or extension is .h5
      3. Heuristic only  — OCR + keyword scoring (no ML model)
    """

    @staticmethod
    def predict(image_path: str, ocr_text: Optional[str] = None) -> Dict[str, Any]:
        if ocr_text is None:
            ocr_text = _ocr_text(image_path)
        ocr_lower = (ocr_text or "").lower()

        # --- Try ML backends ---
        ml_result: Optional[Dict[str, Any]] = None

        model_ext = Path(IMAGE_MODEL_PATH).suffix.lower()
        if model_ext == ".pth":
            ml_result = _TorchPredictor.predict(image_path)
            if ml_result is None:
                ml_result = _KerasPredictor.predict(image_path)
        else:
            # .h5 or anything else — try Keras first
            ml_result = _KerasPredictor.predict(image_path)
            if ml_result is None:
                ml_result = _TorchPredictor.predict(image_path)

        label = "unknown"
        confidence = 0.5
        backend = "heuristic"

        if ml_result:
            label = ml_result.get("label", "unknown")
            confidence = ml_result.get("confidence", 0.5)
            backend = ml_result.get("backend", "unknown")

        # --- OCR keyword scoring ---
        evidence = []
        keyword_boost = 0.0

        high_t = float(IMAGE_SCAM_CONFIDENCE_THRESHOLD)
        med_t = high_t * 0.57

        for keyword, description in SCAM_KEYWORDS.items():
            if keyword in ocr_lower:
                keyword_boost += 0.08
                evidence.append({
                    "source": "ocr",
                    "keyword": keyword,
                    "explanation": description,
                    "severity": "high",
                    "flag_name": "scam_keyword",
                })

        scam_score = min(confidence + keyword_boost, 1.0)

        if scam_score >= high_t:
            risk_level = "high"
            is_scam = True
        elif scam_score >= med_t:
            risk_level = "medium"
            is_scam = False
        else:
            risk_level = "low"
            is_scam = False

        logger.info(
            "image_prediction | backend=%s | label=%s | confidence=%.3f | keywords=%d | scam_score=%.3f",
            backend, label, confidence, len(evidence), scam_score,
        )

        return {
            "label": label,
            "confidence": round(confidence, 4),
            "scam_score": round(scam_score, 4),
            "is_scam": is_scam,
            "risk_level": risk_level,
            "evidence": evidence,
            "ocr_text_preview": ocr_lower[:300],
            "backend": backend,
        }


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def predict_image(image_path: str, ocr_text: Optional[str] = None) -> Dict[str, Any]:
    """Analyse a single image for scam signals. Pass ocr_text to avoid duplicate OCR."""
    return ImageScamPredictor.predict(image_path, ocr_text=ocr_text)
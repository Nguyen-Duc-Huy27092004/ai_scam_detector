import joblib
import threading
import warnings
from typing import Dict, Any, List
from pathlib import Path

import numpy as np

from ml.url.feature_extraction import URLFeatureExtractor
from utils.logger import logger
from utils.config import (
    URL_MODEL_PATH,
    URL_SCALER_PATH,
    PHISHING_CONFIDENCE_THRESHOLD,
    MODELS_DIR,
    URL_MODEL_SHA256,
    URL_SCALER_SHA256,
)
from utils.model_integrity import optional_verify_before_load


class URLPhishingPredictor:
    _model = None
    _models = []
    _scaler = None
    _loaded = False
    _load_failed = False
    _feature_size = None
    _load_lock = threading.Lock()

    # ==========================
    # Load models (PRODUCTION SAFE)
    # ==========================
    @staticmethod
    def load_models():
        if URLPhishingPredictor._loaded:
            return
        if URLPhishingPredictor._load_failed:
            return

        with URLPhishingPredictor._load_lock:
            if URLPhishingPredictor._loaded or URLPhishingPredictor._load_failed:
                return

            try:
                warnings.filterwarnings("ignore")

                # The exact number of features expected by the random forest model
                EXPECTED_FEATURE_COUNT = 48

                sample_url = "http://example.com"
                sample_features = URLFeatureExtractor.extract_features(sample_url)
                vector = URLFeatureExtractor.get_feature_vector(sample_features)
                actual_count = len(vector)

                if actual_count != EXPECTED_FEATURE_COUNT:
                    logger.critical(
                        "feature_count_mismatch | expected=%d | got=%d — URL ML disabled",
                        EXPECTED_FEATURE_COUNT,
                        actual_count,
                    )
                    URLPhishingPredictor._load_failed = True
                    return

                URLPhishingPredictor._feature_size = actual_count

                # ===== Primary model =====
                if URL_MODEL_PATH.exists():
                    if optional_verify_before_load(
                        URL_MODEL_PATH, URL_MODEL_SHA256, name="url_model"
                    ):
                        try:
                            URLPhishingPredictor._model = joblib.load(URL_MODEL_PATH)
                            logger.info("url_primary_model_loaded | %s", URL_MODEL_PATH)
                        except Exception as e:
                            logger.error("primary_model_load_failed | %s | %s", URL_MODEL_PATH, str(e))
                    else:
                        logger.critical("url_primary_model_skipped_integrity | %s", URL_MODEL_PATH)
                else:
                    logger.warning("url_model_not_found | %s", URL_MODEL_PATH)

                # ===== Ensemble models =====
                ensemble_paths = ["rf_model.pkl", "xgb_model.pkl", "lgb_model.pkl"]

                for p in ensemble_paths:
                    full_path = Path(MODELS_DIR) / p
                    if full_path.exists():
                        try:
                            if not optional_verify_before_load(full_path, None, name=p):
                                continue
                            m = joblib.load(full_path)
                            URLPhishingPredictor._models.append(m)
                            logger.info("ensemble_model_loaded | %s", full_path)
                        except Exception as e:
                            logger.error("ensemble_model_load_failed | %s | %s", full_path, str(e))

                # ===== Scaler =====
                if URL_SCALER_PATH.exists():
                    if not optional_verify_before_load(
                        URL_SCALER_PATH, URL_SCALER_SHA256, name="scaler"
                    ):
                        URLPhishingPredictor._load_failed = True
                        return
                    try:
                        URLPhishingPredictor._scaler = joblib.load(URL_SCALER_PATH)
                        logger.info("url_scaler_loaded | %s", URL_SCALER_PATH)
                    except Exception as e:
                        logger.error("scaler_load_failed | %s | %s", URL_SCALER_PATH, str(e))
                else:
                    logger.warning("url_scaler_not_found | %s", URL_SCALER_PATH)

                URLPhishingPredictor._loaded = True

            except Exception as e:
                logger.error("model_load_failed | %s", str(e))
                URLPhishingPredictor._load_failed = True

    # ==========================
    # Normalize feature vector
    # ==========================
    @staticmethod
    def _normalize_vector(vector: List[float]) -> np.ndarray:
        try:
            v = np.array(vector, dtype=float)

            if URLPhishingPredictor._feature_size:
                expected = URLPhishingPredictor._feature_size

                if len(v) != expected:
                    logger.warning("feature_size_mismatch | expected=%d | got=%d", expected, len(v))

                    if len(v) > expected:
                        v = v[:expected]
                    else:
                        pad = np.zeros(expected - len(v))
                        v = np.concatenate([v, pad])

            return v.reshape(1, -1)

        except Exception as e:
            logger.error("vector_normalize_failed | %s", str(e))
            return np.zeros((1, URLPhishingPredictor._feature_size or 10))

    # ==========================
    # Prediction
    # ==========================
    @staticmethod
    def predict(url: str, features: Dict[str, Any] = None) -> Dict[str, Any]:
        try:
            URLPhishingPredictor.load_models()

            valid_models = []

            if URLPhishingPredictor._model:
                valid_models.append(URLPhishingPredictor._model)

            valid_models.extend(URLPhishingPredictor._models)

            if URLPhishingPredictor._load_failed:
                return {
                    "prediction": 0,
                    "label": "unknown",
                    "confidence": 0.0,
                    "error": "URL model load failed or feature contract mismatch",
                }

            if not valid_models:
                return {
                    "prediction": 0,
                    "label": "safe",
                    "confidence": 0.5,
                    "error": "Model not loaded"
                }

            # ===== Feature extraction =====
            if features is None:
                features = URLFeatureExtractor.extract_features(url)

            vector = URLFeatureExtractor.get_feature_vector(features)
            X = URLPhishingPredictor._normalize_vector(vector)

            # ===== Scaling =====
            if URLPhishingPredictor._scaler:
                try:
                    X = URLPhishingPredictor._scaler.transform(X)
                except Exception as e:
                    logger.error("scaling_failed | %s", str(e))

            # ===== Prediction =====
            prediction_sum = 0
            confidences = []

            for m in valid_models:
                try:
                    p = int(m.predict(X)[0])
                    prediction_sum += p

                    if hasattr(m, "predict_proba"):
                        proba = m.predict_proba(X)[0]
                        if len(proba) > 1:
                            confidences.append(float(proba[1]))
                        else:
                            confidences.append(0.5)
                    else:
                        confidences.append(0.5)

                except Exception as e:
                    logger.error("model_predict_failed | %s", str(e))

            # ===== Majority voting =====
            prediction = 1 if prediction_sum >= (len(valid_models) / 2.0) else 0

            # ===== Confidence =====
            confidence = (
                sum(confidences) / len(confidences)
                if confidences else 0.5
            )

            label = "phishing" if prediction == 1 else "safe"

            logger.info(
                "url_prediction | url=%s | label=%s | confidence=%.3f | ensemble_size=%d",
                url[:80],
                label,
                confidence,
                len(valid_models)
            )

            return {
                "prediction": prediction,
                "label": label,
                "confidence": round(confidence, 4),
                "threshold": PHISHING_CONFIDENCE_THRESHOLD,
                "model_count": len(valid_models),
            }

        except Exception as e:
            logger.error("prediction_failed | %s", str(e))

            return {
                "prediction": 0,
                "label": "unknown",
                "confidence": 0.0,
                "error": str(e)
            }

    # ==========================
    # Batch prediction
    # ==========================
    @staticmethod
    def predict_batch(urls: List[str]) -> List[Dict[str, Any]]:
        return [URLPhishingPredictor.predict(url) for url in urls]


# ==========================
# Helper functions
# ==========================

def predict_url(url: str, features: Dict[str, Any] = None) -> Dict[str, Any]:
    return URLPhishingPredictor.predict(url, features)


def load_models():
    URLPhishingPredictor.load_models()
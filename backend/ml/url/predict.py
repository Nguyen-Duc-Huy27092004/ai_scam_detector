"""
URL phishing prediction module.

Uses trained ML model to predict phishing URLs.
"""

import joblib
from pathlib import Path
from typing import Dict, Any, Optional
from ml.url.feature_extraction import URLFeatureExtractor
from utils.logger import logger
from config import URL_MODEL_PATH, URL_SCALER_PATH, PHISHING_CONFIDENCE_THRESHOLD


class URLPhishingPredictor:
    """Predict phishing URLs using ML model."""
    
    _model = None
    _scaler = None
    
    @staticmethod
    def load_models():
        """Load trained ML models from disk."""
        try:
            if URLPhishingPredictor._model is None:
                if URL_MODEL_PATH.exists():
                    URLPhishingPredictor._model = joblib.load(str(URL_MODEL_PATH))
                    logger.info("url_model_loaded | path=%s", URL_MODEL_PATH)
                else:
                    logger.warning("url_model_not_found | path=%s", URL_MODEL_PATH)
            
            if URLPhishingPredictor._scaler is None:
                if URL_SCALER_PATH.exists():
                    URLPhishingPredictor._scaler = joblib.load(str(URL_SCALER_PATH))
                    logger.info("url_scaler_loaded | path=%s", URL_SCALER_PATH)
                else:
                    logger.warning("url_scaler_not_found | path=%s", URL_SCALER_PATH)
                    
        except Exception as e:
            logger.error("model_load_failed | error=%s", str(e))
    
    @staticmethod
    def predict(url: str) -> Dict[str, Any]:
        """
        Predict if URL is phishing.
        
        Args:
            url: URL to analyze
            
        Returns:
            dict: Prediction result with label and confidence
        """
        try:
            # Load models if not already loaded
            URLPhishingPredictor.load_models()
            
            if URLPhishingPredictor._model is None:
                logger.warning("model_not_available | using_default_prediction")
                return {
                    'prediction': 0,
                    'label': 'safe',
                    'confidence': 0.5,
                    'error': 'Model not available'
                }
            
            # Extract features
            features = URLFeatureExtractor.extract_features(url)
            feature_vector = URLFeatureExtractor.get_feature_vector(features)
            
            # Reshape for sklearn
            X = [feature_vector]
            
            # Scale features if scaler available
            if URLPhishingPredictor._scaler:
                X = URLPhishingPredictor._scaler.transform(X)
            
            # Make prediction
            prediction = URLPhishingPredictor._model.predict(X)[0]
            confidence = max(URLPhishingPredictor._model.predict_proba(X)[0])
            
            # Determine label
            label = 'phishing' if prediction == 1 else 'safe'
            
            logger.info("url_prediction | label=%s | confidence=%.2f", label, confidence)
            
            return {
                'prediction': int(prediction),
                'label': label,
                'confidence': float(confidence),
                'threshold': PHISHING_CONFIDENCE_THRESHOLD
            }
            
        except Exception as e:
            logger.error("prediction_failed | error=%s", str(e))
            return {
                'prediction': 0,
                'label': 'unknown',
                'confidence': 0.0,
                'error': str(e)
            }
    
    @staticmethod
    def predict_batch(urls: list) -> list:
        """
        Predict multiple URLs.
        
        Args:
            urls: List of URLs
            
        Returns:
            list: List of predictions
        """
        return [URLPhishingPredictor.predict(url) for url in urls]


def predict_url(url: str) -> Dict[str, Any]:
    """
    Convenience function to predict URL.
    
    Args:
        url: URL to analyze
        
    Returns:
        dict: Prediction result
    """
    return URLPhishingPredictor.predict(url)

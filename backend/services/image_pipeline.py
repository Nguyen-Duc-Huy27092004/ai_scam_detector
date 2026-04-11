"""
Image analysis pipeline orchestrator.

Coordinates the complete image analysis workflow.
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional
from utils.logger import logger, log_analysis_result
from ml.image.predict_image import predict_image
from ml.text.text_classifier import classify_text
from ocr.ocr_engine import extract_text_from_image
from services.risk_level import calculate_image_risk
from services.advisor import generate_advice, get_recommendations
from database.analysis_history import AnalysisHistory


class ImageAnalysisPipeline:
    """Complete image analysis pipeline."""
    
    @staticmethod
    def analyze(image_path: str) -> Dict[str, Any]:
        """
        Complete image analysis pipeline.
        
        Args:
            image_path: Path to image file
            
        Returns:
            dict: Complete analysis result
        """
        logger.info("image_analysis_started | image=%s", image_path)
        
        result = {
            'input_type': 'image',
            'input_value': image_path,
            'status': 'analyzing',
            'steps_completed': [],
            'error': None
        }
        
        try:
            # Verify file exists
            if not Path(image_path).exists():
                raise FileNotFoundError(f"Image file not found: {image_path}")
            
            # Step 1: Image ML Prediction
            logger.debug("step_1: image_ml_prediction")
            image_result = predict_image(image_path)
            image_label = image_result.get('label', 'unknown')
            image_confidence = image_result.get('confidence', 0)
            result['steps_completed'].append('image_prediction')
            result['image_prediction'] = image_result
            
            # Step 2: OCR Text Extraction
            logger.debug("step_2: ocr_extraction")
            ocr_text, ocr_metadata = extract_text_from_image(image_path)
            result['steps_completed'].append('ocr_extracted')
            result['ocr_text'] = ocr_text
            result['ocr_metadata'] = ocr_metadata
            
            # Step 3: Analyze OCR Text
            logger.debug("step_3: ocr_text_analysis")
            text_risk_score = 0.0
            if ocr_text and len(ocr_text.strip()) > 0:
                text_result = classify_text(ocr_text)
                text_label = text_result.get('label', 'safe')
                text_risk_score = 1.0 if text_label == 'scam' else text_result.get('confidence', 0)
                result['text_analysis'] = text_result
            result['steps_completed'].append('text_analysis')
            
            # Step 4: Risk Calculation
            logger.debug("step_4: risk_calculation")
            risk_level, overall_score = calculate_image_risk(
                image_confidence=image_confidence,
                ocr_text_risk=text_risk_score
            )
            result['steps_completed'].append('risk_calculation')
            result['risk_level'] = risk_level
            result['overall_score'] = overall_score
            
            # Step 5: Generate Advice
            logger.debug("step_5: advice_generation")
            risk_factors = ImageAnalysisPipeline._gather_risk_factors(
                image_result, result.get('text_analysis', {})
            )
            advice = generate_advice(
                'image', risk_level, risk_factors, image_confidence
            )
            recommendations = get_recommendations(risk_level, 'image')
            result['steps_completed'].append('advice_generated')
            result['advice'] = advice
            result['recommendations'] = recommendations
            result['risk_factors'] = risk_factors
            
            # Step 6: Save to Database
            logger.debug("step_6: database_save")
            evidence_json = json.dumps({
                'image_prediction': image_result,
                'ocr_metadata': ocr_metadata,
                'text_analysis': result.get('text_analysis', {}),
                'risk_factors': risk_factors
            }, default=str)
            
            record_id = AnalysisHistory.create(
                input_type='image',
                input_value=image_path,
                label=image_label,
                risk_level=risk_level,
                confidence=image_confidence,
                advice=advice,
                screenshot_path=image_path,
                ocr_text=ocr_text,
                evidence_json=evidence_json
            )
            result['record_id'] = record_id
            result['steps_completed'].append('database_saved')
            
            # Final result
            result['status'] = 'completed'
            result['label'] = risk_level
            
            log_analysis_result('image', risk_level, image_confidence)
            logger.info("image_analysis_completed | image=%s | risk=%s", image_path, risk_level)
            
            return result
            
        except Exception as e:
            logger.exception("image_analysis_failed | error=%s", str(e))
            result['status'] = 'error'
            result['error'] = str(e)
            return result
    
    @staticmethod
    def _gather_risk_factors(image_result: dict, text_result: dict) -> list:
        """
        Gather all risk factors for reporting.
        
        Args:
            image_result: Image prediction result
            text_result: Text classification result
            
        Returns:
            list: List of risk factors
        """
        factors = []
        
        # Image prediction factors
        image_label = image_result.get('label', 'unknown')
        if image_label in ['scam', 'suspicious']:
            factors.append(f'image_classified_as_{image_label}')
        
        # Text analysis factors
        if text_result:
            text_indicators = text_result.get('indicators', [])
            factors.extend(text_indicators)
            
            keyword_matches = text_result.get('keyword_matches', [])
            if keyword_matches:
                factors.append(f'suspicious_keywords_found')
        
        return factors


def analyze_image(image_path: str) -> Dict[str, Any]:
    """
    Convenience function to analyze image.
    
    Args:
        image_path: Path to image file
        
    Returns:
        dict: Analysis result
    """
    return ImageAnalysisPipeline.analyze(image_path)

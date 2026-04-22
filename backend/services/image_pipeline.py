"""
Image analysis pipeline orchestrator.

Coordinates the complete image analysis workflow.
"""

import json
from pathlib import Path
from typing import Any, Dict

from utils.logger import logger, log_analysis_result
from ml.image.predict_image import predict_image
from ml.text.text_classifier import classify_text
from ocr.ocr_engine import extract_text_from_image
from services.risk_level import calculate_risk
from services.advisor import generate_advice, get_recommendations
from ml.url.db import AnalysisHistory
from llm.llm_explainer import generate_explanation
from utils.config import IMAGE_MODEL_VERSION


def _merge_llm_into_advice_image(advice: Any, llm_exp: Dict[str, Any]) -> Any:
    if "analysis_summary" not in llm_exp:
        return advice
    addendum = (
        f"\n\n🤖 AI NHẬN XÉT:\n{llm_exp['analysis_summary']}"
        f"\n\n👉 KHUYẾN NGHỊ: {llm_exp.get('recommended_action', '')}"
    )
    if isinstance(advice, dict):
        advice = dict(advice)
        existing = advice.get("advice", "")
        if isinstance(existing, list):
            advice["advice"] = list(existing) + [addendum]
        else:
            advice["advice"] = str(existing) + addendum
        return advice
    return str(advice) + addendum


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
            
            # Step 1: OCR first (single pass — shared with ML + text classifier)
            logger.debug("step_1: ocr_extraction")
            ocr_text, ocr_metadata = extract_text_from_image(image_path)
            result['steps_completed'].append('ocr_extracted')
            result['ocr_text'] = ocr_text
            result['ocr_metadata'] = ocr_metadata

            # Step 2: Image ML Prediction (reuse OCR text — no second Tesseract run)
            logger.debug("step_2: image_ml_prediction")
            image_result = predict_image(image_path, ocr_text=ocr_text)
            image_label = image_result.get('label', 'unknown')
            image_confidence = image_result.get('confidence', 0)
            result['steps_completed'].append('image_prediction')
            result['image_prediction'] = image_result
            
            # Step 3: Analyze OCR Text
            logger.debug("step_3: ocr_text_analysis")
            text_risk_score = 0.0
            if ocr_text and len(ocr_text.strip()) > 0:
                text_result = classify_text(ocr_text)
                text_label = text_result.get('label', 'safe')
                text_risk_score = 1.0 if text_label == 'scam' else text_result.get('confidence', 0)
                result['text_analysis'] = text_result
            result['steps_completed'].append('text_analysis')
            
            # Step 4: Risk Calculation (URL ML unused — image + text signals only)
            logger.debug("step_4: risk_calculation")
            risk_level, overall_score, _ = calculate_risk(
                url_ml_confidence=0.0,
                image_risk=image_confidence,
                text_risk=text_risk_score,
                is_https=True,
            )
            risk_level = risk_level.lower()
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

            llm_exp = generate_explanation({
                "overall_score": overall_score,
                "risk_level": risk_level,
                "risk_factors": risk_factors,
                "scam_type": "image_scam",
                "confidence": image_confidence,
                "content_summary": ocr_text[:500] if ocr_text else "",
            })
            result['llm_explanation'] = llm_exp

            if 'analysis_summary' in llm_exp:
                advice = _merge_llm_into_advice_image(advice, llm_exp)

            result['steps_completed'].append('advice_generated')
            result['advice'] = advice
            result['recommendations'] = recommendations
            result['risk_factors'] = risk_factors

            
            # Step 6: Save to Database (truncate OCR — avoid storing full document text)
            logger.debug("step_6: database_save")
            evidence_json = json.dumps({
                'image_prediction': image_result,
                'ocr_metadata': ocr_metadata,
                'text_analysis': result.get('text_analysis', {}),
                'risk_factors': risk_factors
            }, default=str)

            ocr_preview = (ocr_text[:200] + "…") if ocr_text and len(ocr_text) > 200 else (ocr_text or "")

            record_id = AnalysisHistory.create({
                "input_type": "image",
                "input_value": image_path,
                "label": image_label,
                "risk_level": risk_level,
                "confidence": image_confidence,
                "advice": str(advice),
                "screenshot_path": image_path,
                "ocr_text": ocr_preview or None,
                "evidence_json": evidence_json,
                "model_version": IMAGE_MODEL_VERSION,
            })
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
        """
        factors = []
        
        image_label = image_result.get('label', 'unknown')
        if image_label in ['scam', 'suspicious']:
            factors.append(f'image_classified_as_{image_label}')
        
        for ev in image_result.get('evidence', []):
            flag = ev.get('flag_name') or ev.get('keyword')
            if flag and flag not in factors:
                factors.append(flag)

        if text_result:
            for flag in text_result.get('flags', []):
                if flag not in factors:
                    factors.append(flag)
            if text_result.get('flags'):
                factors.append('suspicious_keywords_found')
        
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

"""
Text analysis pipeline orchestrator.
Coordinates text scam analysis workflow.
"""

import json
from typing import Dict, Any

from utils.logger import logger, log_analysis_result
from ml.text.text_classifier import classify_text, TextScamClassifier
from services.risk_level import calculate_text_risk
from services.advisor import generate_advice, get_recommendations
from ml.url.db import AnalysisHistory


class TextAnalysisPipeline:
    """Complete text analysis pipeline."""

    @staticmethod
    def analyze(text: str) -> Dict[str, Any]:
        logger.info("text_analysis_started | length=%d", len(text))

        result = {
            'input_type': 'text',
            'input_value': text,
            'status': 'analyzing',
            'steps_completed': [],
            'error': None
        }

        try:
            # Step 1: Text Classification
            classification = classify_text(text)
            text_label = classification.get('label', 'unknown')
            text_confidence = classification.get('confidence', 0)
            result['classification'] = classification
            result['steps_completed'].append('text_classified')

            # Step 2: Extract Suspicious Keywords
            keywords = TextScamClassifier.extract_suspicious_keywords(text)
            result['keywords'] = keywords
            result['steps_completed'].append('keywords_extracted')

            # Step 3: Risk Calculation
            risk_level, overall_score = calculate_text_risk(text_confidence)
            risk_level = risk_level.lower()

            result['risk_level'] = risk_level
            result['overall_score'] = overall_score
            result['steps_completed'].append('risk_calculated')

            # Step 4: Generate Advice
            risk_factors = TextAnalysisPipeline._gather_risk_factors(classification)
            advice = generate_advice('text', risk_level, risk_factors, text_confidence)
            recommendations = get_recommendations(risk_level, 'text')

            result['advice'] = advice
            result['recommendations'] = recommendations
            result['risk_factors'] = risk_factors
            result['steps_completed'].append('advice_generated')

            # Step 5: Save to Database
            evidence_json = json.dumps({
                'classification': classification,
                'keywords': keywords,
                'risk_factors': risk_factors
            }, default=str)

            record = {
                "input_type": "text",
                "input_value": text[:500],
                "label": text_label,
                "risk_level": risk_level,
                "confidence": text_confidence,
                "advice": advice,
                "screenshot_path": None,
                "ocr_text": text,
                "evidence_json": evidence_json,
                "model_version": "text-v1"
            }

            record_id = AnalysisHistory.create(record)
            result['record_id'] = record_id
            result['steps_completed'].append('database_saved')

            result['status'] = 'completed'
            result['label'] = risk_level

            log_analysis_result('text', risk_level, text_confidence)
            logger.info("text_analysis_completed | risk=%s | keywords=%d", risk_level, len(keywords))

            return result

        except Exception as e:
            logger.exception("text_analysis_failed | error=%s", str(e))
            result['status'] = 'error'
            result['error'] = str(e)
            return result

    @staticmethod
    def _gather_risk_factors(classification: dict) -> list:
        factors = []
        factors.extend(classification.get('flags', []))
        factors.extend(classification.get('patterns', []))
        return factors


def analyze_text(text: str) -> Dict[str, Any]:
    return TextAnalysisPipeline.analyze(text)
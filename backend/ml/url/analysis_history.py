"""
Analysis history database operations.

Handles CRUD operations for analysis records.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from database.db import get_db
from utils.logger import logger


class AnalysisHistory:
    """Database operations for analysis history."""
    
    @staticmethod
    def create(
        input_type: str,
        input_value: str,
        label: str,
        risk_level: str,
        confidence: float,
        advice: str,
        screenshot_path: Optional[str] = None,
        ocr_text: Optional[str] = None,
        evidence_json: Optional[str] = None,
        model_version: str = "1.0"
    ) -> Optional[int]:
        """
        Create a new analysis record.
        
        Args:
            input_type: Type of analysis (url, image, text)
            input_value: The analyzed input
            label: Classification label
            risk_level: Risk level (low, medium, high)
            confidence: Model confidence score
            advice: AI-generated advice
            screenshot_path: Path to screenshot (optional)
            ocr_text: Extracted OCR text (optional)
            evidence_json: JSON evidence string (optional)
            model_version: Model version used
            
        Returns:
            int: ID of created record or None if failed
        """
        try:
            db = get_db()
            query = """
                INSERT INTO analysis_history (
                    input_type, input_value, label, risk_level, confidence,
                    advice, screenshot_path, ocr_text, evidence_json, model_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            record_id = db.execute_update(query, (
                input_type, input_value, label, risk_level, confidence,
                advice, screenshot_path, ocr_text, evidence_json, model_version
            ))
            
            if record_id:
                logger.info("analysis_saved | id=%d | type=%s", record_id, input_type)
            
            return record_id
            
        except Exception as e:
            logger.error("analysis_create_failed | error=%s", str(e))
            return None
    
    @staticmethod
    def get_by_id(record_id: int) -> Optional[Dict[str, Any]]:
        """
        Get analysis record by ID.
        
        Args:
            record_id: Record ID
            
        Returns:
            dict: Analysis record or None
        """
        try:
            db = get_db()
            results = db.execute_query(
                "SELECT * FROM analysis_history WHERE id = ?",
                (record_id,)
            )
            return results[0] if results else None
        except Exception as e:
            logger.error("analysis_get_failed | id=%d | error=%s", record_id, str(e))
            return None
    
    @staticmethod
    def get_by_type(
        analysis_type: str,
        limit: int = 50,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Get analysis records by type with pagination.
        
        Args:
            analysis_type: Type of analysis (url, image, text)
            limit: Maximum records to return
            offset: Records to skip
            
        Returns:
            list: List of analysis records
        """
        try:
            db = get_db()
            query = """
                SELECT * FROM analysis_history
                WHERE input_type = ?
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
            """
            return db.execute_query(query, (analysis_type, limit, offset))
        except Exception as e:
            logger.error("analysis_get_by_type_failed | type=%s | error=%s", analysis_type, str(e))
            return []
    
    @staticmethod
    def get_all(limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Get all analysis records with pagination.
        
        Args:
            limit: Maximum records to return
            offset: Records to skip
            
        Returns:
            list: List of analysis records
        """
        try:
            db = get_db()
            query = """
                SELECT * FROM analysis_history
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
            """
            return db.execute_query(query, (limit, offset))
        except Exception as e:
            logger.error("analysis_get_all_failed | error=%s", str(e))
            return []
    
    @staticmethod
    def get_by_risk_level(
        risk_level: str,
        limit: int = 50,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Get analysis records by risk level.
        
        Args:
            risk_level: Risk level (low, medium, high)
            limit: Maximum records to return
            offset: Records to skip
            
        Returns:
            list: List of analysis records
        """
        try:
            db = get_db()
            query = """
                SELECT * FROM analysis_history
                WHERE risk_level = ?
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
            """
            return db.execute_query(query, (risk_level, limit, offset))
        except Exception as e:
            logger.error("analysis_get_by_risk_failed | risk=%s | error=%s", risk_level, str(e))
            return []
    
    @staticmethod
    def get_stats() -> Dict[str, Any]:
        """
        Get analysis statistics.
        
        Returns:
            dict: Statistics summary
        """
        try:
            db = get_db()
            
            # Total count
            total = db.execute_query("SELECT COUNT(*) as count FROM analysis_history")[0]["count"]
            
            # Count by type
            by_type = db.execute_query("""
                SELECT input_type, COUNT(*) as count 
                FROM analysis_history 
                GROUP BY input_type
            """)
            
            # Count by risk level
            by_risk = db.execute_query("""
                SELECT risk_level, COUNT(*) as count 
                FROM analysis_history 
                GROUP BY risk_level
            """)
            
            return {
                "total_analyses": total,
                "by_type": {item["input_type"]: item["count"] for item in by_type},
                "by_risk_level": {item["risk_level"]: item["count"] for item in by_risk}
            }
            
        except Exception as e:
            logger.error("analysis_stats_failed | error=%s", str(e))
            return {"total_analyses": 0, "by_type": {}, "by_risk_level": {}}
    
    @staticmethod
    def delete_old_records(days: int = 90) -> int:
        """
        Delete records older than specified days.
        
        Args:
            days: Delete records older than this many days
            
        Returns:
            int: Number of deleted records
        """
        try:
            db = get_db()
            query = """
                DELETE FROM analysis_history
                WHERE datetime(timestamp) < datetime('now', '-' || ? || ' days')
            """
            return db.execute_update(query, (days,))
        except Exception as e:
            logger.error("analysis_delete_failed | days=%d | error=%s", days, str(e))
            return 0

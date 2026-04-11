"""
Database initialization and connection management.
Handles SQLite database setup and connection pooling.
"""

import sqlite3
from pathlib import Path
from typing import Optional, List, Dict
from utils.logger import logger
from utils.config import SQLITE_DB_PATH


class DatabaseConnection:
    """Thread-safe SQLite database connection wrapper."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_db()

    def _initialize_db(self):
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS analysis_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    input_type TEXT NOT NULL,
                    input_value TEXT NOT NULL,
                    label TEXT,
                    risk_level TEXT,
                    confidence REAL,
                    advice TEXT,
                    screenshot_path TEXT,
                    ocr_text TEXT,
                    evidence_json TEXT,
                    model_version TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_input_type ON analysis_history(input_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON analysis_history(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_risk_level ON analysis_history(risk_level)")

            conn.commit()
            conn.close()
            logger.info("database_initialized | path=%s", self.db_path)

        except Exception as e:
            logger.error("database_init_failed | error=%s", str(e))
            raise

    def get_connection(self):
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def execute_query(self, query: str, params: tuple = ()):
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute(query, params)
            results = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return results
        except Exception as e:
            logger.error("query_execution_failed | error=%s", str(e))
            return []

    def execute_update(self, query: str, params: tuple = ()):
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            last_id = cursor.lastrowid
            conn.close()
            return last_id
        except Exception as e:
            logger.error("update_execution_failed | error=%s", str(e))
            return None


# Global DB instance
_db_instance: Optional[DatabaseConnection] = None


def get_db() -> DatabaseConnection:
    global _db_instance
    if _db_instance is None:
        _db_instance = DatabaseConnection(SQLITE_DB_PATH)
    return _db_instance


# ============================
# AnalysisHistory model layer
# ============================
class AnalysisHistory:

    @staticmethod
    def create(record: Dict) -> int:
        db = get_db()
        query = """
            INSERT INTO analysis_history
            (input_type, input_value, label, risk_level, confidence, advice,
             screenshot_path, ocr_text, evidence_json, model_version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            record.get("input_type"),
            record.get("input_value"),
            record.get("label"),
            record.get("risk_level", "").lower(),  # normalize casing
            record.get("confidence"),
            record.get("advice"),
            record.get("screenshot_path"),
            record.get("ocr_text"),
            record.get("evidence_json"),
            record.get("model_version"),
        )
        return db.execute_update(query, params)

    @staticmethod
    def get_all(limit=100, offset=0) -> List[Dict]:
        db = get_db()
        query = """
            SELECT * FROM analysis_history
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """
        return db.execute_query(query, (limit, offset))

    @staticmethod
    def get_by_type(input_type: str, limit=100, offset=0) -> List[Dict]:
        db = get_db()
        query = """
            SELECT * FROM analysis_history
            WHERE input_type = ?
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """
        return db.execute_query(query, (input_type, limit, offset))

    @staticmethod
    def get_by_risk_level(risk_level: str, limit=100, offset=0) -> List[Dict]:
        db = get_db()
        query = """
            SELECT * FROM analysis_history
            WHERE risk_level = ?
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """
        return db.execute_query(query, (risk_level.lower(), limit, offset))

    @staticmethod
    def get_by_id(record_id: int) -> Optional[Dict]:
        db = get_db()
        query = "SELECT * FROM analysis_history WHERE id = ?"
        results = db.execute_query(query, (record_id,))
        return results[0] if results else None

    @staticmethod
    def get_stats() -> Dict:
        db = get_db()
        query = """
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN risk_level='high' THEN 1 ELSE 0 END) as high_risk,
                SUM(CASE WHEN risk_level='medium' THEN 1 ELSE 0 END) as medium_risk,
                SUM(CASE WHEN risk_level='low' THEN 1 ELSE 0 END) as low_risk
            FROM analysis_history
        """
        results = db.execute_query(query)
        return results[0] if results else {}

    @staticmethod
    def delete_old_records(days: int) -> int:
        db = get_db()
        query = """
            DELETE FROM analysis_history
            WHERE timestamp < datetime('now', ?)
        """
        return db.execute_update(query, (f"-{days} days",))
"""
db/postgres_logger.py — Log verdicts to PostgreSQL
"""

import logging
import psycopg2
from psycopg2.extras import Json
from datetime import datetime
from typing import Optional

logger = logging.getLogger("postgres_logger")

class PostgresLogger:
    """Saves analysis results to PostgreSQL."""
    
    def __init__(self):
        from config.settings import Settings
        cfg = Settings()
        
        # Check if we have password
        if not cfg.DB_PASSWORD:
            logger.warning("No PostgreSQL password in .env - disabling PostgreSQL")
            self.conn = None
            self.cursor = None
            return
        
        try:
            self.conn = psycopg2.connect(
                host=cfg.DB_HOST,
                port=cfg.DB_PORT,
                user=cfg.DB_USER,
                password=cfg.DB_PASSWORD,  # ← Now has value
                database=cfg.DB_NAME,
            )
            self.cursor = self.conn.cursor()
            self._init_tables()
            logger.info("✅ PostgreSQL connected")
        except Exception as e:
            logger.warning(f"PostgreSQL connection failed: {e}")
            self.conn = None
            self.cursor = None

    def _init_tables(self):
        """Create tables if they don't exist."""
        if not self.conn:
            return
            
        try:
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS verdicts (
                    id SERIAL PRIMARY KEY,
                    uid VARCHAR(255) UNIQUE,
                    sender VARCHAR(255),
                    subject TEXT,
                    verdict VARCHAR(50),
                    score_final FLOAT,
                    scores_json JSONB,
                    reason TEXT,
                    processing_time FLOAT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    alerted BOOLEAN DEFAULT FALSE
                );
                
                CREATE INDEX IF NOT EXISTS idx_sender ON verdicts(sender);
                CREATE INDEX IF NOT EXISTS idx_verdict ON verdicts(verdict);
                CREATE INDEX IF NOT EXISTS idx_created ON verdicts(created_at);
            """)
            self.conn.commit()
            logger.debug("Tables initialized")
        except Exception as e:
            logger.warning(f"Table init failed: {e}")

    def log_result(self, result: dict) -> bool:
        """Save analysis result."""
        if not self.conn:
            logger.debug("PostgreSQL unavailable - skipping log")
            return False
            
        try:
            self.cursor.execute("""
                INSERT INTO verdicts 
                (uid, sender, subject, verdict, score_final, scores_json, reason, processing_time)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (uid) DO UPDATE SET
                    verdict = EXCLUDED.verdict,
                    score_final = EXCLUDED.score_final,
                    scores_json = EXCLUDED.scores_json,
                    reason = EXCLUDED.reason,
                    processing_time = EXCLUDED.processing_time,
                    created_at = CURRENT_TIMESTAMP
            """, (
                result.get('uid'),
                result.get('sender'),
                result.get('subject'),
                result.get('verdict'),
                result.get('score_final'),
                Json(result.get('scores', {})),
                result.get('reason'),
                result.get('processing_time'),
            ))
            self.conn.commit()
            logger.debug(f"Logged uid={result.get('uid')}")
            return True
        except Exception as e:
            logger.warning(f"Log error: {e}")
            return False

    def close(self):
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()
"""config/settings.py — Complete configuration"""
import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    # IMAP
    IMAP_HOST = os.getenv("IMAP_HOST", "imap.gmail.com")
    IMAP_PORT = int(os.getenv("IMAP_PORT", 993))
    IMAP_USER = os.getenv("IMAP_USER")
    IMAP_PASSWORD = os.getenv("IMAP_PASSWORD")
    POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", 30))
    
    # PostgreSQL
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = int(os.getenv("DB_PORT", 5432))
    DB_USER = os.getenv("DB_USER", "postgres")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "azizaziz")  # ← Added default
    DB_NAME = os.getenv("DB_NAME", "ghost_sentry")
    
    # Redis
    REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
    
    # SMTP for alerts
    SMTP_HOST = os.getenv("SMTP_HOST")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
    SMTP_USER = os.getenv("SMTP_USER")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
    ALERT_EMAIL = os.getenv("ALERT_EMAIL", "alerts@ghostsentry.com")  # ← Added default
    ALERT_RECIPIENT = os.getenv("ALERT_RECIPIENT", "admin@ghostsentry.com")  # ← ADD THIS
    
    # Groq LLM
    GROQ_API_KEY = os.getenv("GROQ_API_KEY")
    
    # Scoring
    SCORE_WEIGHTS = {
        "text": 0.20,
        "url": 0.30,
        "rag": 0.20,
        "bert": 0.30,
    }
    SCORE_THRESHOLD = float(os.getenv("SCORE_THRESHOLD", 0.6))
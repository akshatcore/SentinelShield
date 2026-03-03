# config.py
import os

class Config:
    # Database
    DB_NAME = "sentinel.db"
    
    # Security Thresholds
    BLOCK_THRESHOLD = 10  # Risk score needed to block a request
    
    # Rate Limiting
    RATE_LIMIT_WINDOW = 60  # seconds
    MAX_REQUESTS_PER_WINDOW = 20
    
    # Ban Settings
    BAN_DURATION = 300  # 5 minutes
    
    # Secret Key
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'super-secret-sentinel-key'
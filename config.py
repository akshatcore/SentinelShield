# config.py
import os

class Config:
    # Database
    DB_NAME = "sentinel.db"
    
    # Security Thresholds
    BLOCK_THRESHOLD = 10
    
    # Rate Limiting
    RATE_LIMIT_WINDOW = 60
    MAX_REQUESTS_PER_WINDOW = 20
    
    # Ban Settings (Exponential Backoff Base)
    BAN_DURATION = 300  # Initial 5 minutes
    
    # Secrets (Use env vars in production)
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'elite-sentinel-core-secret-key-9988'
    JWT_SECRET = os.environ.get('JWT_SECRET') or 'jwt-secure-token-secret-x77'
    ADMIN_USER = os.environ.get('ADMIN_USER') or 'admin'
    ADMIN_PASS = os.environ.get('ADMIN_PASS') or 'sentinel_elite'
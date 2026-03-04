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
    
    # GeoIP Configuration
    # You must download 'GeoLite2-City.mmdb' and place it in the project root
    GEOIP_DB_PATH = os.path.join(os.getcwd(), 'GeoLite2-City.mmdb')
    
    # Secret Key
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'super-secret-sentinel-key'

    # --- NEW: JWT & Admin Authentication ---
    JWT_SECRET = os.environ.get('JWT_SECRET') or 'elite-soc-jwt-secret-key-change-me'
    JWT_EXPIRATION_HOURS = 12
    
    # Default Admin Credentials (used to seed the DB on first run)
    DEFAULT_ADMIN_USER = os.environ.get('ADMIN_USER') or 'admin'
    DEFAULT_ADMIN_PASS = os.environ.get('ADMIN_PASS') or 'sentinel123'
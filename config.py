# config.py
import os
from dotenv import load_dotenv

# Load the hidden secrets from the .env file
load_dotenv()

class Config:
    # Database
    DB_NAME = "sentinel.db"
    
    # Security Thresholds
    BLOCK_THRESHOLD = 10 
    
    # Rate Limiting
    RATE_LIMIT_WINDOW = 60 
    MAX_REQUESTS_PER_WINDOW = 20
    
    # Ban Settings
    BAN_DURATION = 300 
    
    # GeoIP Configuration
    GEOIP_DB_PATH = os.path.join(os.getcwd(), 'GeoLite2-City.mmdb')
    
    # Secret Key
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'super-secret-sentinel-key'

    # --- JWT & Admin Authentication ---
    JWT_SECRET = os.environ.get('JWT_SECRET') or 'elite-soc-jwt-secret-key-change-me'
    JWT_EXPIRATION_HOURS = 12
    
    # Default Admin Credentials
    DEFAULT_ADMIN_USER = os.environ.get('ADMIN_USER') or 'admin'
    DEFAULT_ADMIN_PASS = os.environ.get('ADMIN_PASS') or 'sentinel123'

    # --- TELEGRAM ALERTS ---
    TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN')

    # --- THREAT INTELLIGENCE (NEW) ---
    ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY')
    ABUSEIPDB_THRESHOLD = 90  # Block if abuse confidence is 90% or higher
    ABUSEIPDB_CACHE_HOURS = 24  # Cache results to prevent API rate limiting

    # --- NEW: DYNAMIC REVERSE PROXY TARGET ---
    # Loads from .env initially, but can now be updated on-the-fly via the Dashboard UI!
    REVERSE_PROXY_URL = os.environ.get('REVERSE_PROXY_URL')

    # --- NEW: CUSTOM WALLPAPER SETTINGS ---
    UPLOAD_FOLDER = os.path.join('static', 'uploads')
    # Limit wallpaper uploads to 5MB to prevent Denial of Service (DoS) attacks
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024
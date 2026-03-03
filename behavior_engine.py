# behavior_engine.py
import time
from collections import defaultdict
from config import Config

# In-memory storage for sliding window
request_history = defaultdict(list)

def check_rate_limit(ip):
    """
    Returns True if rate limit exceeded, False otherwise.
    Implements a sliding window algorithm.
    """
    current_time = time.time()
    
    # Filter out requests older than the window
    request_history[ip] = [t for t in request_history[ip] if current_time - t < Config.RATE_LIMIT_WINDOW]
    
    # Add current request
    request_history[ip].append(current_time)
    
    # Check if threshold exceeded
    if len(request_history[ip]) > Config.MAX_REQUESTS_PER_WINDOW:
        return True
    return False
# behavior_engine.py
import time
from collections import defaultdict
from config import Config

request_history = defaultdict(list)

def check_rate_limit(ip):
    current_time = time.time()
    # Filter old requests
    request_history[ip] = [t for t in request_history[ip] if current_time - t < Config.RATE_LIMIT_WINDOW]
    # Add new request
    request_history[ip].append(current_time)
    
    if len(request_history[ip]) > Config.MAX_REQUESTS_PER_WINDOW:
        return True
    return False
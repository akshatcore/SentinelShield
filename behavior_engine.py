# behavior_engine.py
import time
import re
from collections import defaultdict
from config import Config
from database import suggest_rule

# In-memory storage for sliding window
request_history = defaultdict(list)

# --- NEW: In-memory storage for adaptive learning ---
payload_tracker = defaultdict(int)

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

# --- NEW: ADAPTIVE DEFENSE LOGIC ---
def learn_from_payload(payload, attack_type):
    """
    Analyzes repeated suspicious payloads to suggest new defensive rules.
    """
    if not payload or len(payload) < 5:
        return

    # Normalize payload slightly to group similar automated attacks
    normalized = payload.strip().lower()
    
    payload_tracker[normalized] += 1
    
    # If we see the exact same malicious string 5 times, it's a brute-force or automated scanner
    if payload_tracker[normalized] == 5:
        # Generate a safe regex pattern. Escape special characters to prevent regex crashes.
        # We truncate to 50 chars so we don't create insanely long, slow regexes.
        safe_pattern = re.escape(normalized[:50])
        
        # Suggest the rule to the SOC database with an 85% confidence score
        suggest_rule(safe_pattern, f"Adaptive {attack_type}", 85)
# behavior_engine.py
import time
import re
import urllib.parse
from collections import defaultdict
from config import Config
from database import suggest_rule

# In-memory storage for sliding window
request_history = defaultdict(list)

# In-memory storage for adaptive learning
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

# --- UPGRADED: ADAPTIVE DEFENSE LOGIC ---
def learn_from_payload(payload, attack_type):
    """
    Analyzes repeated suspicious payloads to suggest new defensive rules.
    """
    if not payload or len(payload) < 5:
        return

    # FIX: Correctly extract query string from BOTH full URLs and relative paths
    if "?" in payload:
        payload = payload.split("?", 1)[1]
        
    # Decode URL encoding (so %3C becomes <) and normalize
    normalized = urllib.parse.unquote(payload).strip().lower()
    
    payload_tracker[normalized] += 1
    
    # --- ADDED FLUSH=TRUE TO FORCE VS CODE TO SHOW IT IMMEDIATELY ---
    print(f"🧠 [AI Brain] Tracked payload {payload_tracker[normalized]}/3 times: {normalized[:30]}...", flush=True)
    
    # Using == 3 is aggressive and catches the attack before the rate-limiter bans the IP
    if payload_tracker[normalized] == 3:
        print(f"🚨 [AI Brain] THRESHOLD REACHED! Generating dynamic rule for: {attack_type}", flush=True)
        
        # Generate a safe regex pattern, truncated to 40 chars so it doesn't get crazy
        safe_pattern = re.escape(normalized[:40])
        
        # Suggest the rule to the SOC database with an 85% confidence score
        suggest_rule(safe_pattern, f"AI-Learned: {attack_type}", 85)
        print(f"✅ [AI Brain] Rule successfully pushed to SOC Dashboard!", flush=True)
# behavior_engine.py
import time
import re
import urllib.parse
import math  
from collections import defaultdict, Counter 
from config import Config
from database import suggest_rule

# In-memory storage for sliding window
request_history = defaultdict(list)

# In-memory storage for adaptive learning
payload_tracker = defaultdict(int)

# Memory storage specifically for tracking vulnerability scanners
scanner_history = defaultdict(list)

# A list of honeypot/sensitive paths that normal users shouldn't be rapidly clicking
SENSITIVE_PATHS = [
    '/.env', '/.git', '/wp-admin', '/wp-login.php', '/config.php', 
    '/backup.zip', '/phpmyadmin', '/admin.php', '/eval.php', '/setup.php'
]

def check_rate_limit(ip):
    current_time = time.time()
    request_history[ip] = [t for t in request_history[ip] if current_time - t < Config.RATE_LIMIT_WINDOW]
    request_history[ip].append(current_time)
    if len(request_history[ip]) > Config.MAX_REQUESTS_PER_WINDOW:
        return True
    return False

def check_behavioral_fingerprint(ip, url):
    is_sensitive = any(path in url.lower() for path in SENSITIVE_PATHS)
    if is_sensitive:
        current_time = time.time()
        scanner_history[ip] = [t for t in scanner_history[ip] if current_time - t < 20]
        scanner_history[ip].append(current_time)
        
        if len(scanner_history[ip]) >= 3:
            print(f"🤖 [AI Brain] Behavioral Fingerprint Matched: Vulnerability Scanner detected at {ip}!", flush=True)
            return True
    return False

def learn_from_payload(payload, attack_type):
    if not payload or len(payload) < 5:
        return
    if "?" in payload:
        payload = payload.split("?", 1)[1]
        
    normalized = urllib.parse.unquote(payload).strip().lower()
    payload_tracker[normalized] += 1
    
    print(f"🧠 [AI Brain] Tracked payload {payload_tracker[normalized]}/3 times: {normalized[:30]}...", flush=True)
    
    if payload_tracker[normalized] == 3:
        print(f"🚨 [AI Brain] THRESHOLD REACHED! Auto-generating dynamic rule for: {attack_type}", flush=True)
        safe_pattern = re.escape(normalized[:40])
        suggest_rule(safe_pattern, f"AI-Learned: {attack_type}", 85)
        
        from rules import load_custom_rules
        load_custom_rules()
        print(f"⚡ [AI Brain] Self-Healing Complete: Rule auto-deployed to live memory!", flush=True)

def calculate_entropy(payload):
    if not payload: return 0
    entropy = 0
    char_counts = Counter(payload)
    length = len(payload)
    for count in char_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy

def detect_obfuscation(payload):
    if not payload or len(payload) < 10:
        return False
        
    # Extract purely the query values for accurate math
    if "?" in payload:
        payload = payload.split("?", 1)[1]
    if "=" in payload:
        payload = payload.split("=", 1)[1]
        
    entropy = calculate_entropy(payload)
    
    # 3.5 is the sweet spot for catching Base64/Hex without false positives
    if entropy > 3.5:
        print(f"👁️ [AI Anomaly] High Entropy Detected ({entropy:.2f}): {payload[:30]}...", flush=True)
        return True
        
    return False
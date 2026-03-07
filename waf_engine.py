# waf_engine.py
import requests
import urllib.parse  # NEW: Required to decode %20 into spaces
from rules import PATTERNS
from database import is_ip_banned, log_event, ban_ip, get_cached_reputation, cache_reputation
from behavior_engine import check_rate_limit, learn_from_payload
from config import Config
from alerts import send_telegram_alert

def check_ip_reputation(ip):
    """
    Checks the IP against AbuseIPDB.
    Returns the Abuse Confidence Score (0-100).
    """
    # 1. Skip local/private IPs
    if ip == '127.0.0.1' or ip == 'localhost' or ip.startswith('192.168.') or ip.startswith('10.'):
        return 0
        
    # 2. Check our fast local cache first
    cached_score = get_cached_reputation(ip)
    if cached_score is not None:
        return cached_score
        
    # 3. If not cached, query AbuseIPDB (if configured)
    if not hasattr(Config, 'ABUSEIPDB_API_KEY') or not Config.ABUSEIPDB_API_KEY:
        return 0
        
    try:
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {
            'ipAddress': ip,
            'maxAgeInDays': '90'
        }
        headers = {
            'Accept': 'application/json',
            'Key': Config.ABUSEIPDB_API_KEY
        }
        
        # 2-second timeout so WAF doesn't hang if the API is down
        response = requests.get(url, headers=headers, params=querystring, timeout=2) 
        
        if response.status_code == 200:
            data = response.json()
            score = data['data']['abuseConfidenceScore']
            cache_reputation(ip, score) # Save to our database cache
            return score
    except Exception as e:
        print(f"⚠️ Threat Intel API Error: {e}", flush=True)
        
    return 0


class WAF:
    def inspect_request(self, ip, method, url, headers, body):
        print(f"\n--- 🔍 NEW REQUEST ARRIVED: {url} ---", flush=True)

        # 1. Check if IP is banned locally
        if is_ip_banned(ip):
            print(f"⛔ BLOCKED AT STEP 1: {ip} is already on the Detention List!", flush=True)
            return {"action": "BLOCKED", "reason": "IP Banned"}

        # 2. Rate Limiting
        if check_rate_limit(ip):
            print(f"⛔ BLOCKED AT STEP 2: {ip} hit the Rate Limiter (Too fast)!", flush=True)
            ban_ip(ip, "Rate Limit Exceeded")
            log_event(ip, method, url, headers, body, "Rate Limit Exceeded", 10, "BLOCKED")
            send_telegram_alert(ip, "Rate Limit Exceeded", url, 10)  # TRIGGER ALERT
            return {"action": "BLOCKED", "reason": "Rate Limit Exceeded"}

        # --- 2.5 Global Threat Intelligence ---
        reputation_score = check_ip_reputation(ip)
        if reputation_score >= getattr(Config, 'ABUSEIPDB_THRESHOLD', 90):
            print(f"⛔ BLOCKED AT STEP 2.5: Threat Intel AbuseIPDB Score too high!", flush=True)
            reason = f"Known Malicious IP (AbuseIPDB Score: {reputation_score}%)"
            ban_ip(ip, reason) # Instantly ban them locally
            log_event(ip, method, url, headers, body, "Global Threat Intel Block", reputation_score, "BLOCKED")
            send_telegram_alert(ip, f"Threat Intel (Score: {reputation_score}%)", url, reputation_score)
            return {"action": "BLOCKED", "reason": reason}

        print("✅ Passed early checks. Moving to Deep Payload Inspection...", flush=True)

        # --- 3. Signature Inspection & URL Decoding ---
        
        # Decode the URL and Body to catch obfuscated attacks (like %20 instead of spaces)
        decoded_url = urllib.parse.unquote(url)
        decoded_body = urllib.parse.unquote(body) if body else ""
        
        # We test both raw AND decoded strings to ensure no evasion techniques work
        raw_payloads = [url, decoded_url, body, decoded_body] + list(headers.values())
        
        # Clean the list to remove empty strings and duplicates
        payloads = list(set([p for p in raw_payloads if p and isinstance(p, str)]))

        total_score = 0
        detected_types = set()

        for content in payloads:
            # We loop over a snapshot of items `list(PATTERNS.items())` to prevent
            # "dictionary changed size during iteration" errors when the AI learns mid-scan
            for attack_type, regex_list in list(PATTERNS.items()):
                for pattern in regex_list:
                    if pattern.search(content):
                        print(f"⚠️ REGEX MATCHED: {attack_type} -> Notifying AI Brain!", flush=True)
                        total_score += 10
                        detected_types.add(attack_type)
                        
                        # Trigger Adaptive Defense Learning using the decoded string
                        learn_from_payload(content, attack_type)

        # 4. Decision Making
        if total_score >= Config.BLOCK_THRESHOLD:
            attack_str = ", ".join(detected_types)
            log_event(ip, method, url, headers, body, attack_str, total_score, "BLOCKED")
            send_telegram_alert(ip, attack_str, url, total_score)  # TRIGGER ALERT
            return {"action": "BLOCKED", "reason": f"Malicious Payload: {attack_str}"}
        
        # 5. Log Normal Traffic
        if total_score > 0:
             attack_str = ", ".join(detected_types)
             log_event(ip, method, url, headers, body, attack_str, total_score, "ALLOWED")
        else:
             # Now it will log completely normal traffic too!
             log_event(ip, method, url, headers, body, "Normal", 0, "ALLOWED")

        return {"action": "ALLOWED"}

waf = WAF()
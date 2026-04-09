# waf_engine.py
import requests
import urllib.parse  # Required to decode %20 into spaces
from rules import PATTERNS
from database import is_ip_banned, log_event, ban_ip, get_cached_reputation, cache_reputation
from behavior_engine import check_rate_limit, learn_from_payload, detect_obfuscation, check_behavioral_fingerprint
from config import Config
from alerts import send_telegram_alert
from ml_engine import ml_brain
import urllib.parse

def check_ip_reputation(ip):
    """
    Checks the IP against AbuseIPDB.
    Returns the Abuse Confidence Score (0-100).
    """
    if ip == '127.0.0.1' or ip == 'localhost' or ip.startswith('192.168.') or ip.startswith('10.'):
        return 0
        
    cached_score = get_cached_reputation(ip)
    if cached_score is not None:
        return cached_score
        
    if not hasattr(Config, 'ABUSEIPDB_API_KEY') or not Config.ABUSEIPDB_API_KEY:
        return 0
        
    try:
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {'ipAddress': ip, 'maxAgeInDays': '90'}
        headers = {'Accept': 'application/json', 'Key': Config.ABUSEIPDB_API_KEY}
        
        response = requests.get(url, headers=headers, params=querystring, timeout=2) 
        if response.status_code == 200:
            data = response.json()
            score = data['data']['abuseConfidenceScore']
            cache_reputation(ip, score)
            return score
    except Exception as e:
        print(f"⚠️ Threat Intel API Error: {e}", flush=True)
        
    return 0


class WAF:
    def inspect_request(self, ip, method, url, headers, body):
        
        print(f"\n--- 🔍 NEW REQUEST ARRIVED: {url} ---", flush=True)

        if is_ip_banned(ip):
            print(f"⛔ BLOCKED AT STEP 1: {ip} is already on the Detention List!", flush=True)
            return {"action": "BLOCKED", "reason": "IP Banned"}

        if check_rate_limit(ip):
            print(f"⛔ BLOCKED AT STEP 2: {ip} hit the Rate Limiter (Too fast)!", flush=True)
            ban_ip(ip, "Rate Limit Exceeded")
            log_event(ip, method, url, headers, body, "Rate Limit Exceeded", 10, "BLOCKED")
            send_telegram_alert(ip, "Rate Limit Exceeded", url, 10)
            return {"action": "BLOCKED", "reason": "Rate Limit Exceeded"}

        if check_behavioral_fingerprint(ip, url):
            print(f"⛔ BLOCKED AT STEP 2.2: {ip} exhibits Vulnerability Scanner behavior!", flush=True)
            ban_ip(ip, "Automated Vulnerability Scanner Detected")
            log_event(ip, method, url, headers, body, "Scanner Fingerprint", 100, "BLOCKED")
            send_telegram_alert(ip, "Vulnerability Scanner Detected", url, 100)
            return {"action": "BLOCKED", "reason": "Behavioral Fingerprint: Scanner"}

        reputation_score = check_ip_reputation(ip)
        if reputation_score >= getattr(Config, 'ABUSEIPDB_THRESHOLD', 90):
            print(f"⛔ BLOCKED AT STEP 2.5: Threat Intel AbuseIPDB Score too high!", flush=True)
            reason = f"Known Malicious IP (AbuseIPDB Score: {reputation_score}%)"
            ban_ip(ip, reason)
            log_event(ip, method, url, headers, body, "Global Threat Intel Block", reputation_score, "BLOCKED")
            send_telegram_alert(ip, f"Threat Intel (Score: {reputation_score}%)", url, reputation_score)
            return {"action": "BLOCKED", "reason": reason}

        print("✅ Passed early checks. Moving to Deep Payload Inspection...", flush=True)
        
    
        # --- 3. Signature Inspection & URL Decoding ---
        
        decoded_url = urllib.parse.unquote(url)
        decoded_body = urllib.parse.unquote(body) if body else ""
        
        # AI ONLY scans URL and Body to prevent False Positives on standard browser headers
        ai_raw_payloads = [url, decoded_url, body, decoded_body]
        ai_payloads = list(set([p for p in ai_raw_payloads if p and isinstance(p, str)]))

        # Regex scans EVERYTHING, including HTTP Headers
        all_raw_payloads = ai_raw_payloads + list(headers.values())
        all_payloads = list(set([p for p in all_raw_payloads if p and isinstance(p, str)]))

        total_score = 0
        detected_types = set()

        # --- NEW PHASE 1: MATHEMATICAL ANOMALY DETECTION (ONLY ON AI_PAYLOADS) ---
        for content in ai_payloads:
            if detect_obfuscation(content):
                total_score += 15
                detected_types.add("Evasion / Obfuscation (High Entropy)")
                learn_from_payload(content, "Evasion / Obfuscation (High Entropy)")

        # --- NEW PHASE 3: TRUE MACHINE LEARNING (NLP) (ONLY ON AI_PAYLOADS) ---
        for content in ai_payloads:
            ml_confidence = ml_brain.predict_maliciousness(content)
            if ml_confidence > 65.0:
                print(f"🤖 [ML Brain] Zero-Day Attack Detected! Confidence: {ml_confidence}% -> {content[:30]}", flush=True)
                total_score += 10
                detected_types.add(f"ML Heuristic Anomaly ({ml_confidence}% malicious)")
                learn_from_payload(content, "Zero-Day/ML Detection")

        # --- EXISTING REGEX INSPECTION (ON ALL_PAYLOADS) ---
        for content in all_payloads:
            for attack_type, regex_list in list(PATTERNS.items()):
                for pattern in regex_list:
                    if pattern.search(content):
                        print(f"⚠️ REGEX MATCHED: {attack_type} -> Notifying AI Brain!", flush=True)
                        total_score += 10
                        detected_types.add(attack_type)
                        
                        # 🚨 CRITICAL FIX: Only let the AI learn if the attack was in the URL or Body!
                        if content in ai_payloads:
                            learn_from_payload(content, attack_type)
                        else:
                            print(f"🛡️ [AI Brain] Ignored header learning to prevent false positive.", flush=True)

        # 4. Decision Making
        if total_score >= getattr(Config, 'BLOCK_THRESHOLD', 10):
            attack_str = ", ".join(detected_types)
            log_event(ip, method, url, headers, body, attack_str, total_score, "BLOCKED")
            send_telegram_alert(ip, attack_str, url, total_score)
            return {"action": "BLOCKED", "reason": f"Malicious Payload: {attack_str}"}
        
        # 5. Log Normal Traffic
        if total_score > 0:
             attack_str = ", ".join(detected_types)
             log_event(ip, method, url, headers, body, attack_str, total_score, "ALLOWED")
        else:
             log_event(ip, method, url, headers, body, "Normal", 0, "ALLOWED")

        return {"action": "ALLOWED"}

waf = WAF()
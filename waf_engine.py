# waf_engine.py
from rules import PATTERNS
from database import is_ip_banned, log_event, ban_ip
from behavior_engine import check_rate_limit
from config import Config

class WAF:
    def inspect_request(self, ip, method, url, headers, body):
        # 1. Check if IP is banned
        if is_ip_banned(ip):
            return {"action": "BLOCKED", "reason": "IP Banned"}

        # 2. Rate Limiting
        if check_rate_limit(ip):
            ban_ip(ip, "Rate Limit Exceeded")
            log_event(ip, method, url, headers, body, "Rate Limit Exceeded", 10, "BLOCKED")
            return {"action": "BLOCKED", "reason": "Rate Limit Exceeded"}

        # 3. Signature Inspection (Headers, URL, Body)
        payloads = [url, body] + list(headers.values())
        total_score = 0
        detected_types = set()

        for content in payloads:
            if not content or not isinstance(content, str):
                continue
                
            for attack_type, regex_list in PATTERNS.items():
                for pattern in regex_list:
                    if pattern.search(content):
                        # FIX: Increased from 5 to 10 to ensure immediate blocking against default threshold
                        total_score += 10
                        detected_types.add(attack_type)

        # 4. Decision Making
        if total_score >= Config.BLOCK_THRESHOLD:
            attack_str = ", ".join(detected_types)
            log_event(ip, method, url, headers, body, attack_str, total_score, "BLOCKED")
            return {"action": "BLOCKED", "reason": f"Malicious Payload: {attack_str}"}
        
        # 5. Log Normal Traffic (Optional)
        if total_score > 0:
             attack_str = ", ".join(detected_types)
             log_event(ip, method, url, headers, body, attack_str, total_score, "ALLOWED")
        
        # Uncomment to log ALL traffic:
        log_event(ip, method, url, headers, body, "Normal", 0, "ALLOWED")

        return {"action": "ALLOWED"}

waf = WAF()
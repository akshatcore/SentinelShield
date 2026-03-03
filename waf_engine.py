# waf_engine.py
from rules import PATTERNS
from database import is_ip_banned, log_event, ban_ip_advanced
from behavior_engine import check_rate_limit
from threat_engine import threat_engine
from config import Config

class WAF:
    def inspect_request(self, ip, method, url, headers, body):
        # 1. IP Ban Check
        if is_ip_banned(ip):
            return {"action": "BLOCKED", "reason": "IP Banned"}

        # 2. Rate Limiting
        if check_rate_limit(ip):
            ban_ip_advanced(ip, "Rate Limit Exceeded (DoS Behavior)")
            log_event(ip, method, url, headers, body, "DoS Flood", 20, "BLOCKED", "Critical", 100)
            return {"action": "BLOCKED", "reason": "Rate Limit Exceeded"}

        # 3. Signature Inspection
        payloads = [url, body] + list(headers.values())
        total_score = 0
        detected_types = set()

        for content in payloads:
            if not content or not isinstance(content, str):
                continue
            for attack_type, regex_list in PATTERNS.items():
                for pattern in regex_list:
                    if pattern.search(content):
                        total_score += 5
                        detected_types.add(attack_type)

        # 4. Threat Processing
        attack_str = ", ".join(detected_types) if detected_types else "Normal"
        severity = threat_engine.classify_severity(total_score, attack_str)
        cumulative_threat = threat_engine.analyze_profile(ip, total_score)

        # 5. Decision
        if total_score >= Config.BLOCK_THRESHOLD:
            ban_ip_advanced(ip, f"Malicious Payload: {attack_str}")
            log_event(ip, method, url, headers, body, attack_str, total_score, "BLOCKED", severity, cumulative_threat)
            return {"action": "BLOCKED", "reason": f"Malicious Payload: {attack_str}"}
        
        if total_score > 0:
             log_event(ip, method, url, headers, body, attack_str, total_score, "ALLOWED", "Low", cumulative_threat)

        return {"action": "ALLOWED"}

waf = WAF()
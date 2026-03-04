# alerts.py
import requests
import threading
from config import Config

def send_telegram_alert(ip, attack_type, url, score):
    if not hasattr(Config, 'TELEGRAM_BOT_TOKEN') or not Config.TELEGRAM_BOT_TOKEN:
        return

    def _send():
        message = f"🚨 *SENTINEL SHIELD ALERT* 🚨\n\n" \
                  f"🛑 *Action:* BLOCKED\n" \
                  f"🌐 *Source IP:* `{ip}`\n" \
                  f"⚔️ *Threat Vector:* {attack_type}\n" \
                  f"🎯 *Target URL:* `{url}`\n" \
                  f"📈 *Risk Score:* {score}\n\n" \
                  f"🔒 _Automated defense system engaged._"
        
        api_url = f"https://api.telegram.org/bot{Config.TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": Config.TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "Markdown"
        }
        
        try:
            requests.post(api_url, json=payload, timeout=5)
        except Exception as e:
            print(f"⚠️ Failed to send Telegram alert: {e}")

    # Run in a background thread so WAF speed is not impacted
    threading.Thread(target=_send).start()
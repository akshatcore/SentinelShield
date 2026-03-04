# alerts.py
import requests
import threading
import html
from config import Config
from database import get_all_telegram_chat_ids

def send_telegram_alert(ip, attack_type, url, score):
    if not hasattr(Config, 'TELEGRAM_BOT_TOKEN') or not Config.TELEGRAM_BOT_TOKEN:
        return

    def _send():
        # Escape HTML characters so malicious payloads don't break Telegram's API
        safe_ip = html.escape(str(ip))
        safe_url = html.escape(str(url))
        safe_type = html.escape(str(attack_type))
        
        message = f"🚨 <b>SENTINEL SHIELD ALERT</b> 🚨\n\n" \
                  f"🛑 <b>Action:</b> BLOCKED\n" \
                  f"🌐 <b>Source IP:</b> <code>{safe_ip}</code>\n" \
                  f"⚔️ <b>Threat Vector:</b> {safe_type}\n" \
                  f"🎯 <b>Target URL:</b> <code>{safe_url}</code>\n" \
                  f"📈 <b>Risk Score:</b> {score}\n\n" \
                  f"🔒 <i>Automated defense system engaged.</i>"
        
        # Fetch ALL connected admins from the database
        chat_ids = get_all_telegram_chat_ids()
        
        if not chat_ids:
            return  # Nobody is connected, fail silently

        # Broadcast the alert to every connected admin
        for chat_id in chat_ids:
            api_url = f"https://api.telegram.org/bot{Config.TELEGRAM_BOT_TOKEN}/sendMessage"
            payload = {
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "HTML"
            }
            
            try:
                requests.post(api_url, json=payload, timeout=5)
            except Exception as e:
                pass # Silently fail for one user so we don't break the loop

    # Run in a background thread so WAF speed is not impacted
    threading.Thread(target=_send).start()
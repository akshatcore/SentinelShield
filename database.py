# database.py
import sqlite3
import datetime
from config import Config

def init_db():
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    
    # Logs Table
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        ip_address TEXT,
        method TEXT,
        url TEXT,
        headers TEXT,
        payload TEXT,
        attack_type TEXT,
        risk_score INTEGER,
        action TEXT
    )''')
    
    # IP Bans Table
    c.execute('''CREATE TABLE IF NOT EXISTS bans (
        ip_address TEXT PRIMARY KEY,
        banned_at TEXT,
        expires_at TEXT,
        reason TEXT
    )''')
    
    conn.commit()
    conn.close()

def log_event(ip, method, url, headers, payload, attack_type, score, action):
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO logs (timestamp, ip_address, method, url, headers, payload, attack_type, risk_score, action) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
              (timestamp, ip, method, url, str(headers), str(payload), attack_type, score, action))
    conn.commit()
    conn.close()

def ban_ip(ip, reason):
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    now = datetime.datetime.now()
    expires = now + datetime.timedelta(seconds=Config.BAN_DURATION)
    
    # Upsert ban
    c.execute("INSERT OR REPLACE INTO bans (ip_address, banned_at, expires_at, reason) VALUES (?, ?, ?, ?)",
              (ip, now.strftime("%Y-%m-%d %H:%M:%S"), expires.strftime("%Y-%m-%d %H:%M:%S"), reason))
    conn.commit()
    conn.close()

def is_ip_banned(ip):
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    c.execute("SELECT expires_at FROM bans WHERE ip_address = ?", (ip,))
    result = c.fetchone()
    conn.close()
    
    if result:
        expires_at = datetime.datetime.strptime(result[0], "%Y-%m-%d %H:%M:%S")
        if datetime.datetime.now() < expires_at:
            return True
        else:
            # Clean up expired ban
            unban_ip(ip)
    return False

def unban_ip(ip):
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM bans WHERE ip_address = ?", (ip,))
    conn.commit()
    conn.close()

def get_stats():
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    
    # Total Requests
    c.execute("SELECT COUNT(*) FROM logs")
    total_requests = c.fetchone()[0]
    
    # Blocked Requests
    c.execute("SELECT COUNT(*) FROM logs WHERE action='BLOCKED'")
    blocked_requests = c.fetchone()[0]
    
    # Active Bans
    c.execute("SELECT COUNT(*) FROM bans")
    active_bans = c.fetchone()[0]
    
    # Attack Distribution
    c.execute("SELECT attack_type, COUNT(*) FROM logs WHERE attack_type != 'Normal' GROUP BY attack_type")
    attack_dist = dict(c.fetchall())
    
    # Top IPs
    c.execute("SELECT ip_address, COUNT(*) as count FROM logs WHERE attack_type != 'Normal' GROUP BY ip_address ORDER BY count DESC LIMIT 5")
    top_ips = dict(c.fetchall())

    # Recent Logs
    c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 10")
    recent_logs = c.fetchall()
    
    conn.close()
    
    return {
        "total": total_requests,
        "blocked": blocked_requests,
        "bans": active_bans,
        "attacks": attack_dist,
        "top_ips": top_ips,
        "logs": recent_logs
    }
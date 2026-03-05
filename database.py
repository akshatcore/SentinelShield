# database.py
import sqlite3
import datetime
import csv
import io
import geoip2.database
import bcrypt
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
        action TEXT,
        country TEXT
    )''')
    
    # IP Bans Table
    c.execute('''CREATE TABLE IF NOT EXISTS bans (
        ip_address TEXT PRIMARY KEY,
        banned_at TEXT,
        expires_at TEXT,
        reason TEXT
    )''')

    # Admin Users Table
    c.execute('''CREATE TABLE IF NOT EXISTS admin_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        role TEXT,
        telegram_chat_id TEXT,
        telegram_sync_token TEXT
    )''')

    # IP Reputation Cache Table
    c.execute('''CREATE TABLE IF NOT EXISTS ip_reputation (
        ip_address TEXT PRIMARY KEY,
        score INTEGER,
        last_checked TEXT
    )''')

    # --- Adaptive Defense Rules Table ---
    c.execute('''CREATE TABLE IF NOT EXISTS adaptive_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern TEXT UNIQUE,
        attack_type TEXT,
        confidence INTEGER,
        status TEXT DEFAULT 'pending', -- 'pending', 'approved', 'rejected'
        created_at TEXT
    )''')
    
    # Migrations
    c.execute("PRAGMA table_info(logs)")
    columns = [info[1] for info in c.fetchall()]
    if 'country' not in columns:
        print("⚠️ Migrating database: Adding 'country' column to logs...")
        c.execute("ALTER TABLE logs ADD COLUMN country TEXT DEFAULT 'Unknown'")

    c.execute("PRAGMA table_info(admin_users)")
    admin_columns = [info[1] for info in c.fetchall()]
    if 'telegram_chat_id' not in admin_columns:
        print("⚠️ Migrating database: Adding Telegram columns to admin_users...")
        c.execute("ALTER TABLE admin_users ADD COLUMN telegram_chat_id TEXT")
        c.execute("ALTER TABLE admin_users ADD COLUMN telegram_sync_token TEXT")
    
    # Seed Default Admin
    c.execute("SELECT COUNT(*) FROM admin_users")
    if c.fetchone()[0] == 0:
        print(f"⚠️ Seeding default admin user: {Config.DEFAULT_ADMIN_USER}")
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(Config.DEFAULT_ADMIN_PASS.encode('utf-8'), salt)
        c.execute("INSERT INTO admin_users (username, password_hash, role) VALUES (?, ?, ?)",
                  (Config.DEFAULT_ADMIN_USER, hashed.decode('utf-8'), 'admin'))

    conn.commit()
    conn.close()

# --- ADMIN AUTHENTICATION ---
def verify_admin(username, password):
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    c.execute("SELECT id, username, password_hash, role FROM admin_users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()
    
    if user:
        stored_hash = user[2].encode('utf-8')
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            return {"id": user[0], "username": user[1], "role": user[3]}
    return None

# --- TELEGRAM PAIRING LOGIC ---
def set_telegram_sync_token(username, token):
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    c.execute("UPDATE admin_users SET telegram_sync_token = ? WHERE username = ?", (token, username))
    conn.commit()
    conn.close()

def link_telegram_account(token, chat_id):
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    c.execute("UPDATE admin_users SET telegram_chat_id = ?, telegram_sync_token = NULL WHERE telegram_sync_token = ?", (str(chat_id), token))
    success = conn.total_changes > 0
    conn.commit()
    conn.close()
    return success

def get_telegram_status(username):
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    c.execute("SELECT telegram_chat_id, telegram_sync_token FROM admin_users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if not row: return {"status": "unlinked"}
    if row[0]: return {"status": "linked"}
    if row[1]: return {"status": "pending", "token": row[1]}
    return {"status": "unlinked"}

def get_all_telegram_chat_ids():
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    c.execute("SELECT telegram_chat_id FROM admin_users WHERE telegram_chat_id IS NOT NULL")
    ids = [row[0] for row in c.fetchall()]
    conn.close()
    return ids

# --- DETECT LOCAL IPs ---
def get_country_from_ip(ip):
    if ip == '127.0.0.1' or ip == 'localhost' or ip.startswith('192.168.') or ip.startswith('10.'):
        return 'Local'
    try:
        with geoip2.database.Reader(Config.GEOIP_DB_PATH) as reader:
            response = reader.city(ip)
            return response.country.iso_code or 'Unknown'
    except Exception:
        return 'Unknown'

def log_event(ip, method, url, headers, payload, attack_type, score, action):
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    country = get_country_from_ip(ip)
    
    c.execute("""INSERT INTO logs 
        (timestamp, ip_address, method, url, headers, payload, attack_type, risk_score, action, country) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (timestamp, ip, method, url, str(headers), str(payload), attack_type, score, action, country))
    conn.commit()
    conn.close()

def ban_ip(ip, reason):
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    now = datetime.datetime.now()
    expires = now + datetime.timedelta(seconds=Config.BAN_DURATION)
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
            unban_ip(ip)
    return False

def unban_ip(ip):
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM bans WHERE ip_address = ?", (ip,))
    conn.commit()
    conn.close()

# --- THREAT INTEL REPUTATION CACHING ---
def get_cached_reputation(ip):
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    c.execute("SELECT score, last_checked FROM ip_reputation WHERE ip_address = ?", (ip,))
    row = c.fetchone()
    conn.close()
    if row:
        score, last_checked_str = row
        last_checked = datetime.datetime.strptime(last_checked_str, "%Y-%m-%d %H:%M:%S")
        if datetime.datetime.now() < last_checked + datetime.timedelta(hours=Config.ABUSEIPDB_CACHE_HOURS):
            return score
    return None

def cache_reputation(ip, score):
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT OR REPLACE INTO ip_reputation (ip_address, score, last_checked) VALUES (?, ?, ?)",
              (ip, score, now))
    conn.commit()
    conn.close()

# --- ADAPTIVE DEFENSE LOGIC ---
def suggest_rule(pattern, attack_type, confidence=85):
    """Called by the WAF engine when it spots a highly repetitive attack pattern."""
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        c.execute("INSERT INTO adaptive_rules (pattern, attack_type, confidence, created_at) VALUES (?, ?, ?, ?)",
                  (pattern, attack_type, confidence, now))
        conn.commit()
    except sqlite3.IntegrityError:
        pass # Pattern already suggested or active
    finally:
        conn.close()

def get_suggested_rules():
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    c.execute("SELECT id, pattern, attack_type, confidence, status, created_at FROM adaptive_rules WHERE status = 'pending' ORDER BY confidence DESC")
    rules = c.fetchall()
    conn.close()
    return rules

def get_active_custom_rules():
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    c.execute("SELECT pattern, attack_type FROM adaptive_rules WHERE status = 'approved'")
    rules = c.fetchall()
    conn.close()
    return rules

def approve_suggested_rule(rule_id):
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    c.execute("UPDATE adaptive_rules SET status = 'approved' WHERE id = ?", (rule_id,))
    success = conn.total_changes > 0
    conn.commit()
    conn.close()
    return success

def reject_suggested_rule(rule_id):
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    c.execute("UPDATE adaptive_rules SET status = 'rejected' WHERE id = ?", (rule_id,))
    success = conn.total_changes > 0
    conn.commit()
    conn.close()

# --- DATA FETCHING FOR DASHBOARD ---
def get_all_logs():
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 200")
    logs = c.fetchall()
    conn.close()
    return logs

def get_log_by_id(log_id):
    conn = sqlite3.connect(Config.DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM logs WHERE id = ?", (log_id,))
    row = c.fetchone()
    conn.close()
    if row: return dict(row)
    return None

def get_all_bans():
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM bans ORDER BY banned_at DESC")
    bans = c.fetchall()
    conn.close()
    return bans

def get_stats():
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    
    c.execute("SELECT COUNT(*) FROM logs")
    total_requests = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM logs WHERE action='BLOCKED'")
    blocked_requests = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM bans")
    active_bans = c.fetchone()[0]
    
    c.execute("SELECT attack_type, COUNT(*) FROM logs WHERE attack_type != 'Normal' GROUP BY attack_type")
    attack_dist = dict(c.fetchall())
    
    c.execute("SELECT ip_address, COUNT(*) as count FROM logs WHERE attack_type != 'Normal' GROUP BY ip_address ORDER BY count DESC LIMIT 5")
    top_ips = dict(c.fetchall())

    c.execute("SELECT country, COUNT(*) as count FROM logs WHERE attack_type != 'Normal' GROUP BY country ORDER BY count DESC LIMIT 5")
    top_countries = dict(c.fetchall())

    # --- NEW: THREAT HEATMAP DATA ---
    c.execute("SELECT url, COUNT(*) as count FROM logs WHERE attack_type != 'Normal' GROUP BY url ORDER BY count DESC LIMIT 5")
    top_endpoints = dict(c.fetchall())

    c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 10")
    recent_logs = c.fetchall()
    
    conn.close()
    
    return {
        "total": total_requests,
        "blocked": blocked_requests,
        "bans": active_bans,
        "attacks": attack_dist,
        "top_ips": top_ips,
        "top_countries": top_countries,
        "top_endpoints": top_endpoints, # Added here!
        "logs": recent_logs
    }

# --- MAINTENANCE ---
def clear_database():
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM logs")
    c.execute("DELETE FROM bans")
    c.execute("DELETE FROM ip_reputation") 
    conn.commit()
    conn.close()

def export_logs_csv():
    conn = sqlite3.connect(Config.DB_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY timestamp DESC")
    rows = c.fetchall()
    headers = [description[0] for description in c.description] if c.description else []
    conn.close()
    
    if not rows: return ""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)
    writer.writerows(rows)
    return output.getvalue()
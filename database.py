# database.py
import sqlite3
import datetime
import bcrypt
from config import Config

def get_db():
    conn = sqlite3.connect(Config.DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
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
        severity TEXT DEFAULT 'Low',
        threat_index INTEGER DEFAULT 0
    )''')
    
    # Bans Table
    c.execute('''CREATE TABLE IF NOT EXISTS bans (
        ip_address TEXT PRIMARY KEY,
        banned_at TEXT,
        expires_at TEXT,
        reason TEXT,
        offense_count INTEGER DEFAULT 1
    )''')

    # IP Profiles
    c.execute('''CREATE TABLE IF NOT EXISTS ip_profiles (
        ip_address TEXT PRIMARY KEY,
        first_seen TEXT,
        last_seen TEXT,
        total_violations INTEGER DEFAULT 0,
        reputation_score INTEGER DEFAULT 0,
        risk_level TEXT DEFAULT 'Neutral'
    )''')

    # Admin Users
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT
    )''')
    
    _migrate_schema(c)
    _seed_admin(c)
    
    conn.commit()
    conn.close()

def _migrate_schema(cursor):
    # Ensure columns exist if upgrading from old version
    cursor.execute("PRAGMA table_info(logs)")
    columns = [info[1] for info in cursor.fetchall()]
    if 'severity' not in columns:
        cursor.execute("ALTER TABLE logs ADD COLUMN severity TEXT DEFAULT 'Low'")
    if 'threat_index' not in columns:
        cursor.execute("ALTER TABLE logs ADD COLUMN threat_index INTEGER DEFAULT 0")

    cursor.execute("PRAGMA table_info(bans)")
    columns = [info[1] for info in cursor.fetchall()]
    if 'offense_count' not in columns:
        cursor.execute("ALTER TABLE bans ADD COLUMN offense_count INTEGER DEFAULT 1")

def _seed_admin(cursor):
    cursor.execute("SELECT * FROM users WHERE username = ?", (Config.ADMIN_USER,))
    if not cursor.fetchone():
        hashed = bcrypt.hashpw(Config.ADMIN_PASS.encode('utf-8'), bcrypt.gensalt())
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", 
                      (Config.ADMIN_USER, hashed.decode('utf-8')))

# --- LOGGING ---
def log_event(ip, method, url, headers, payload, attack_type, score, action, severity, threat_index):
    conn = get_db()
    c = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""INSERT INTO logs 
        (timestamp, ip_address, method, url, headers, payload, attack_type, risk_score, action, severity, threat_index) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (timestamp, ip, method, url, str(headers), str(payload), attack_type, score, action, severity, threat_index))
    conn.commit()
    conn.close()

# --- PROFILES ---
def update_ip_profile(ip, score_increase):
    conn = get_db()
    c = conn.cursor()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    c.execute("SELECT * FROM ip_profiles WHERE ip_address = ?", (ip,))
    row = c.fetchone()
    
    if row:
        new_score = row['reputation_score'] + score_increase
        new_count = row['total_violations'] + 1
        risk = 'Critical' if new_score > 50 else ('High' if new_score > 20 else 'Neutral')
        c.execute("UPDATE ip_profiles SET last_seen = ?, total_violations = ?, reputation_score = ?, risk_level = ? WHERE ip_address = ?", 
                  (now, new_count, new_score, risk, ip))
    else:
        c.execute("INSERT INTO ip_profiles (ip_address, first_seen, last_seen, total_violations, reputation_score, risk_level) VALUES (?, ?, ?, ?, ?, ?)", 
                  (ip, now, now, 1, score_increase, 'Neutral'))
    
    conn.commit()
    conn.close()

def get_ip_reputation(ip):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT reputation_score FROM ip_profiles WHERE ip_address = ?", (ip,))
    res = c.fetchone()
    conn.close()
    return res if res else (0,)

# --- BAN LOGIC ---
def ban_ip_advanced(ip, reason):
    conn = get_db()
    c = conn.cursor()
    now = datetime.datetime.now()
    
    c.execute("SELECT offense_count FROM bans WHERE ip_address = ?", (ip,))
    res = c.fetchone()
    offenses = (res[0] if res else 0) + 1
    
    duration = Config.BAN_DURATION * (offenses ** 2) 
    expires = now + datetime.timedelta(seconds=duration)
    
    c.execute("INSERT OR REPLACE INTO bans (ip_address, banned_at, expires_at, reason, offense_count) VALUES (?, ?, ?, ?, ?)", 
              (ip, now.strftime("%Y-%m-%d %H:%M:%S"), expires.strftime("%Y-%m-%d %H:%M:%S"), reason, offenses))
    
    conn.commit()
    conn.close()

# --- STATS FOR DASHBOARD ---
def get_dashboard_stats():
    conn = get_db()
    c = conn.cursor()
    
    c.execute("SELECT COUNT(*) FROM logs WHERE action='BLOCKED'")
    blocked = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM logs")
    total = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM bans")
    active_bans = c.fetchone()[0]
    
    c.execute("SELECT attack_type, COUNT(*) FROM logs WHERE attack_type != 'Normal' GROUP BY attack_type")
    attacks = dict(c.fetchall())
    
    c.execute("SELECT ip_address, COUNT(*) as c FROM logs WHERE attack_type != 'Normal' GROUP BY ip_address ORDER BY c DESC LIMIT 5")
    top_ips = dict(c.fetchall())
    
    c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 10")
    logs = [dict(row) for row in c.fetchall()]

    conn.close()
    return {"blocked": blocked, "total": total, "bans": active_bans, "attacks": attacks, "top_ips": top_ips, "logs": logs}

def get_log_details(log_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM logs WHERE id = ?", (log_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None

def get_all_bans():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM bans ORDER BY banned_at DESC")
    return [dict(row) for row in c.fetchall()]

def unban_ip(ip):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM bans WHERE ip_address = ?", (ip,))
    conn.commit()
    conn.close()

def is_ip_banned(ip):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT expires_at FROM bans WHERE ip_address = ?", (ip,))
    result = c.fetchone()
    conn.close()
    if result:
        expires = datetime.datetime.strptime(result[0], "%Y-%m-%d %H:%M:%S")
        if datetime.datetime.now() < expires:
            return True
        unban_ip(ip) # Expired
    return False
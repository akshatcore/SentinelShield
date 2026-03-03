# app.py
from flask import Flask, request, jsonify, render_template, abort, send_file
from waf_engine import waf
from database import init_db, get_stats, unban_ip, get_all_logs, get_all_bans, clear_database, export_logs_csv
from config import Config
import json
import io

app = Flask(__name__)

# Initialize DB on start
init_db()

# --- WAF MIDDLEWARE ---
@app.before_request
def waf_middleware():
    # WHITELIST: Skip WAF inspection for static resources, dashboard pages, and internal APIs
    if (request.path.startswith('/static') or 
        request.path.startswith('/api') or 
        request.path == '/' or 
        request.path == '/favicon.ico'):
        return

    # Extract request data
    ip = request.remote_addr
    method = request.method
    url = request.url
    headers = dict(request.headers)
    body = request.get_data(as_text=True)

    # Inspect
    decision = waf.inspect_request(ip, method, url, headers, body)

    if decision['action'] == 'BLOCKED':
        return jsonify({
            "error": "Request Blocked by SentinelShield",
            "reason": decision['reason'],
            "ip": ip
        }), 403

# --- VULNERABLE ENDPOINT SIMULATION ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        return "Login Failed (Simulation)", 200
    return "Login Page (Protected)", 200

@app.route('/search')
def search():
    query = request.args.get('q', '')
    return f"Search results for: {query}"

# --- DASHBOARD PAGE ---
@app.route('/')
def index():
    return render_template('dashboard.html')

# --- API ROUTES ---

@app.route('/api/stats')
def api_stats():
    stats = get_stats()
    return jsonify(stats)

@app.route('/api/logs')
def api_logs():
    # Returns full logs for the Logs View
    logs = get_all_logs()
    # Convert tuples to list of dicts
    data = [{"id": r[0], "time": r[1], "ip": r[2], "method": r[3], "url": r[4], "attack": r[7], "score": r[8], "action": r[9]} for r in logs]
    return jsonify(data)

@app.route('/api/bans')
def api_bans():
    # Returns active bans for the Blacklist View
    bans = get_all_bans()
    data = [{"ip": r[0], "banned_at": r[1], "expires": r[2], "reason": r[3]} for r in bans]
    return jsonify(data)

@app.route('/api/unban/<ip>', methods=['POST'])
def api_unban(ip):
    unban_ip(ip)
    return jsonify({"status": "success", "message": f"IP {ip} unbanned"})

@app.route('/api/settings', methods=['GET', 'POST'])
def api_settings():
    if request.method == 'POST':
        data = request.json
        # Dynamically update Config class attributes
        if 'block_threshold' in data: Config.BLOCK_THRESHOLD = int(data['block_threshold'])
        if 'rate_limit' in data: Config.MAX_REQUESTS_PER_WINDOW = int(data['rate_limit'])
        if 'ban_duration' in data: Config.BAN_DURATION = int(data['ban_duration'])
        return jsonify({"status": "updated", "message": "Configuration Saved Successfully", "config": {
            "block_threshold": Config.BLOCK_THRESHOLD,
            "rate_limit": Config.MAX_REQUESTS_PER_WINDOW,
            "ban_duration": Config.BAN_DURATION
        }})
    
    return jsonify({
        "block_threshold": Config.BLOCK_THRESHOLD,
        "rate_limit": Config.MAX_REQUESTS_PER_WINDOW,
        "ban_duration": Config.BAN_DURATION
    })

# --- NEW ENDPOINTS: MAINTENANCE ---

@app.route('/api/database/clear', methods=['POST'])
def api_clear_db():
    clear_database()
    return jsonify({"status": "success", "message": "Database Logs Cleared Successfully"})

@app.route('/api/report/download')
def api_download_report():
    csv_data = export_logs_csv()
    
    # Create a file-like object in memory
    mem = io.BytesIO()
    mem.write(csv_data.encode('utf-8'))
    mem.seek(0)
    
    return send_file(
        mem,
        mimetype='text/csv',
        as_attachment=True,
        download_name='sentinel_security_report.csv'
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
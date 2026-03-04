# app.py
from flask import Flask, request, jsonify, render_template, abort, send_file, make_response, redirect, url_for
from waf_engine import waf
from database import init_db, get_stats, unban_ip, get_all_logs, get_all_bans, clear_database, export_logs_csv, get_log_by_id, verify_admin
from config import Config
import json
import io
import jwt
import datetime
from functools import wraps

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
        request.path.startswith('/admin-login') or
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

# --- AUTH DECORATORS ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('auth_token')
        if not token:
            return jsonify({'message': 'Authentication Token is missing!', 'status': 401}), 401
        try:
            jwt.decode(token, Config.JWT_SECRET, algorithms=["HS256"])
        except:
            return jsonify({'message': 'Token is invalid or expired!', 'status': 401}), 401
        return f(*args, **kwargs)
    return decorated

def admin_page_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('auth_token')
        if not token:
            return redirect(url_for('admin_login_page'))
        try:
            jwt.decode(token, Config.JWT_SECRET, algorithms=["HS256"])
        except:
            return redirect(url_for('admin_login_page'))
        return f(*args, **kwargs)
    return decorated

# --- AUTH ENDPOINTS ---
@app.route('/admin-login', methods=['GET'])
def admin_login_page():
    return render_template('admin_login.html')

@app.route('/api/auth/login', methods=['POST'])
def api_auth_login():
    data = request.json
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing credentials'}), 400
    
    user = verify_admin(data['username'], data['password'])
    if not user:
        return jsonify({'message': 'Invalid credentials'}), 401
        
    token = jwt.encode({
        'user': user['username'],
        'role': user['role'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=Config.JWT_EXPIRATION_HOURS)
    }, Config.JWT_SECRET, algorithm="HS256")
    
    resp = make_response(jsonify({'status': 'success', 'message': 'Logged in successfully'}))
    resp.set_cookie('auth_token', token, httponly=True, samesite='Strict')
    return resp

@app.route('/api/auth/logout', methods=['POST'])
def api_auth_logout():
    resp = make_response(jsonify({'status': 'success'}))
    resp.set_cookie('auth_token', '', expires=0)
    return resp

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
@admin_page_required
def index():
    # Extract the token expiration time to pass to the frontend timer
    token = request.cookies.get('auth_token')
    exp_time = 0
    if token:
        try:
            decoded = jwt.decode(token, Config.JWT_SECRET, algorithms=["HS256"])
            exp_time = decoded.get('exp', 0)
        except Exception:
            pass
            
    return render_template('dashboard.html', exp_time=exp_time)

# --- API ROUTES ---

@app.route('/api/stats')
@token_required
def api_stats():
    stats = get_stats()
    return jsonify(stats)

@app.route('/api/logs')
@token_required
def api_logs():
    logs = get_all_logs()
    data = []
    for r in logs:
        country = r[10] if len(r) > 10 else "Unknown"
        data.append({
            "id": r[0], "time": r[1], "ip": r[2], "method": r[3], 
            "url": r[4], "attack": r[7], "score": r[8], "action": r[9], 
            "country": country
        })
    return jsonify(data)

@app.route('/api/logs/<int:log_id>')
@token_required
def api_log_detail(log_id):
    log = get_log_by_id(log_id)
    if log:
        return jsonify(log)
    return jsonify({'error': 'Log not found'}), 404

@app.route('/api/bans')
@token_required
def api_bans():
    bans = get_all_bans()
    data = [{"ip": r[0], "banned_at": r[1], "expires": r[2], "reason": r[3]} for r in bans]
    return jsonify(data)

@app.route('/api/unban/<ip>', methods=['POST'])
@token_required
def api_unban(ip):
    unban_ip(ip)
    return jsonify({"status": "success", "message": f"IP {ip} unbanned"})

@app.route('/api/settings', methods=['GET', 'POST'])
@token_required
def api_settings():
    if request.method == 'POST':
        data = request.json
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
@token_required
def api_clear_db():
    clear_database()
    return jsonify({"status": "success", "message": "Database Logs Cleared Successfully"})

@app.route('/api/report/download')
@token_required
def api_download_report():
    csv_data = export_logs_csv()
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
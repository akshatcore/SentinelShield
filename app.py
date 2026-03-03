# app.py
from flask import Flask, request, jsonify, render_template, make_response, redirect, url_for
from waf_engine import waf
from database import init_db, get_dashboard_stats, unban_ip, get_all_bans, get_log_details
from auth import generate_token, verify_user, login_required
from config import Config

app = Flask(__name__)
init_db()

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# --- WAF MIDDLEWARE (FIXED) ---
@app.before_request
def waf_middleware():
    # ALLOW: static files, login page, dashboard API, favicon, and root
    allowed_prefixes = ('/static', '/api', '/favicon.ico')
    allowed_routes = ('/', '/login')
    
    if request.path.startswith(allowed_prefixes) or request.path in allowed_routes:
        return

    ip = request.remote_addr
    decision = waf.inspect_request(ip, request.method, request.url, dict(request.headers), request.get_data(as_text=True))

    if decision['action'] == 'BLOCKED':
        return jsonify({"error": "Request Blocked", "reason": decision['reason'], "ip": ip}), 403

# --- AUTH ROUTES ---
@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    if verify_user(data.get('username'), data.get('password')):
        token = generate_token(data.get('username'))
        resp = make_response(jsonify({'token': token, 'status': 'success'}))
        resp.set_cookie('auth_token', token, httponly=True, secure=False)
        return resp
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('login_page')))
    resp.set_cookie('auth_token', '', expires=0)
    return resp

# --- DASHBOARD ROUTES ---
@app.route('/')
@login_required
def index():
    return render_template('dashboard.html')

@app.route('/api/stats')
@login_required
def api_stats():
    return jsonify(get_dashboard_stats())

@app.route('/api/logs/<int:log_id>')
@login_required
def api_log_detail(log_id):
    log = get_log_details(log_id)
    if log: return jsonify(dict(log))
    return jsonify({'error': 'Log not found'}), 404

@app.route('/api/bans')
@login_required
def api_bans():
    return jsonify(get_all_bans())

@app.route('/api/unban/<ip>', methods=['POST'])
@login_required
def api_unban(ip):
    unban_ip(ip)
    return jsonify({"status": "success"})

# --- TEST ROUTE ---
@app.route('/test-attack')
def test_attack():
    return "Protected Route. Try adding ?q=<script>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
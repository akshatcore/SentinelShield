# app.py
from flask import Flask, request, jsonify, render_template, abort
from waf_engine import waf
from database import init_db, get_stats, unban_ip
import json

app = Flask(__name__)

# Initialize DB on start
init_db()

# --- WAF MIDDLEWARE ---
@app.before_request
def waf_middleware():
    # WHITELIST: Skip WAF inspection for static resources, dashboard pages, and internal APIs
    # This prevents the dashboard's auto-refresh from triggering the rate limiter.
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
    # This endpoint simulates a vulnerable login page
    # The WAF sits in front of it.
    if request.method == 'POST':
        return "Login Failed (Simulation)", 200
    return "Login Page (Protected)", 200

@app.route('/search')
def search():
    query = request.args.get('q', '')
    return f"Search results for: {query}"

# --- DASHBOARD ROUTES ---
@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/stats')
def api_stats():
    stats = get_stats()
    return jsonify(stats)

@app.route('/api/unban/<ip>', methods=['POST'])
def api_unban(ip):
    # Admin endpoint to unban IPs
    unban_ip(ip)
    return jsonify({"status": "success", "message": f"IP {ip} unbanned"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
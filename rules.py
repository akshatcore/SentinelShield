# rules.py
import re

# Store the original baseline rules so we can reset and reload safely without duplicating
BASE_PATTERNS = {
    "SQL Injection": [
        # Catch classic ' OR 1=1 or ' AND '1'='1 (Allows normal quotes in text, but catches boolean logic)
        re.compile(r"(?i)(\%27|')\s*(OR|AND)\s*(\%27|'|\d)"),
        # Catch Tautologies like '='
        re.compile(r"(?i)(\%27|')\s*=\s*(\%27|')"),
        # Catch UNION SELECT combinations
        re.compile(r"(?i)UNION(\s|\+)+(ALL(\s|\+)+)?SELECT"),
        # Catch dangerous stored procedures (e.g., exec xp_cmdshell)
        re.compile(r"(?i)EXEC(\s|\+)+(xp_|sp_)\w+"),
        # Catch SQL inline comments used for bypasses (e.g., /*SQL*/ or -- )
        re.compile(r"(?i)(\-\-\s|\/\*.*?\*\/)")
    ],
    "XSS (Cross-Site Scripting)": [
        # Catch highly dangerous executable tags (script, iframe, object, img)
        re.compile(r"(?i)(%3C|<)\/?(script|iframe|body|svg|math|object|embed|img)(%3E|>|\s)"),
        # Catch malicious inline JavaScript event handlers
        re.compile(r"(?i)(onload|onerror|onmouseover|onfocus|onblur)\s*="),
        # Catch javascript URI schemes
        re.compile(r"(?i)javascript:")
    ],
    "Command Injection": [
        re.compile(r";\s*(\/|cat|ls|pwd|whoami|netcat|nc)", re.IGNORECASE),
        re.compile(r"\|\|\s*(\/|cat|ls|pwd|whoami|netcat|nc)", re.IGNORECASE),
        re.compile(r"\$\(.*\)", re.IGNORECASE)
    ],
    "Directory Traversal": [
        re.compile(r"\.\./", re.IGNORECASE),
        re.compile(r"\.\.\\", re.IGNORECASE),
        re.compile(r"/etc/passwd", re.IGNORECASE)
    ],
    "Suspicious User-Agent": [
        # Detect modern & professional security vulnerability scanners
        re.compile(r"(sqlmap|nikto|nmap|curl|python-requests|burpsuite|owasp[\s_-]?zap|zaproxy|masscan|dirbuster|gobuster|wpscan|nuclei|hydra)", re.IGNORECASE)
    ]
}

# This is the active dictionary the WAF engine actually reads
PATTERNS = {}

def load_custom_rules():
    """
    Clears current rules, loads the baseline, and injects approved adaptive rules from the DB.
    """
    global PATTERNS
    
    # Deferred import to prevent circular dependency issues during Flask startup
    from database import get_active_custom_rules
    
    # 1. Reset to baseline
    PATTERNS.clear()
    for attack_type, regex_list in BASE_PATTERNS.items():
        PATTERNS[attack_type] = list(regex_list)
        
    # 2. Fetch approved custom rules from the database
    try:
        custom_rules = get_active_custom_rules()
        for pattern_str, attack_type in custom_rules:
            if attack_type not in PATTERNS:
                PATTERNS[attack_type] = []
            
            try:
                # Compile the dynamically learned regex
                compiled_regex = re.compile(pattern_str, re.IGNORECASE)
                PATTERNS[attack_type].append(compiled_regex)
            except re.error:
                print(f"⚠️ Failed to compile adaptive rule: {pattern_str}")
                
        print(f"🛡️ Loaded {len(custom_rules)} adaptive defense rules into memory.")
    except Exception as e:
        # Failsafe: If DB isn't initialized yet on first boot, just run baseline silently
        pass

# Initialize the rules immediately on server startup
load_custom_rules()
# rules.py
import re

# Store the original baseline rules so we can reset and reload safely without duplicating
BASE_PATTERNS = {
    "SQL Injection": [
        re.compile(r"(\%27)|(\')|(\-\-)|(\%23)|(#)", re.IGNORECASE),
        re.compile(r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))", re.IGNORECASE),
        re.compile(r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))", re.IGNORECASE),
        re.compile(r"exec(\s|\+)+(s|x)p\w+", re.IGNORECASE),
        re.compile(r"UNION(\s|\+)*SELECT", re.IGNORECASE)
    ],
    "XSS (Cross-Site Scripting)": [
        re.compile(r"((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)", re.IGNORECASE),
        re.compile(r"((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)", re.IGNORECASE),
        re.compile(r"javascript:", re.IGNORECASE),
        re.compile(r"onload|onerror|onmouseover", re.IGNORECASE)
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
        # Upgraded to detect modern & professional security scanners
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
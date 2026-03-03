# rules.py
import re

PATTERNS = {
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
        re.compile(r"javascript:", re.IGNORECASE)
    ],
    "Command Injection": [
        re.compile(r";\s*(\/|cat|ls|pwd|whoami|netcat|nc)", re.IGNORECASE),
        re.compile(r"\|\|\s*(\/|cat|ls|pwd|whoami|netcat|nc)", re.IGNORECASE),
        re.compile(r"\$\(.*\)", re.IGNORECASE)
    ],
    "Directory Traversal": [
        re.compile(r"\.\./", re.IGNORECASE),
        re.compile(r"/etc/passwd", re.IGNORECASE)
    ],
    "Suspicious User-Agent": [
        re.compile(r"(sqlmap|nikto|nmap|curl|python-requests)", re.IGNORECASE)
    ]
}
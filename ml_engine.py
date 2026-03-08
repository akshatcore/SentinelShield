# ml_engine.py
import urllib.parse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

class MLEngine:
    def __init__(self):
        # Analyzes character combinations (n-grams) to spot weird hacking syntax
        self.vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 4))
        self.classifier = LogisticRegression(max_iter=1000)
        self.is_trained = False
        self.bootstrap_model()

    def bootstrap_model(self):
        """
        A tiny bootstrap dataset so the AI works immediately. 
        In the future, you can load thousands of logs from your database here!
        """
        # Normal web traffic
        good_payloads = [
            "/login", "?user=admin", "/index.php", "home", "/about-us", 
            "username=john&password=123", "/api/data?id=5", "/styles.css",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Accept-Language: en-US"
        ]
        
        # Classic hacking payloads (SQLi, XSS, Path Traversal, Command Injection)
        bad_payloads = [
            "' OR '1'='1", "<script>alert(1)</script>", "UNION SELECT",
            "../../../../etc/passwd", "eval(base64_decode(", "onload=prompt(1)",
            "EXEC xp_cmdshell", "AND 1=1--", "cat /etc/shadow", "/bin/sh",
            "javascript:alert(document.cookie)", "SELECT * FROM users WHERE",
            "1; DROP TABLE users", "' OR 1=1#"
        ]
        
        X_train = good_payloads + bad_payloads
        # 0 = Safe, 1 = Malicious
        y_train = [0] * len(good_payloads) + [1] * len(bad_payloads)
        
        # Train the neural network
        X_vectorized = self.vectorizer.fit_transform(X_train)
        self.classifier.fit(X_vectorized, y_train)
        self.is_trained = True
        print("🧠 [ML Engine] TF-IDF Neural Network Bootstrapped and Online!", flush=True)

    def predict_maliciousness(self, payload):
        """
        Returns a percentage (0.0 to 100.0) of how confident the AI is that this is an attack.
        """
        if not self.is_trained or not payload or len(payload) < 4:
            return 0.0
        
        decoded = urllib.parse.unquote(payload).lower()
        X_vec = self.vectorizer.transform([decoded])
        
        # Get probability of being malicious (Class 1)
        probability = self.classifier.predict_proba(X_vec)[0][1]
        return round(probability * 100, 2)

# Create a global instance of the brain to be used by the WAF
ml_brain = MLEngine()
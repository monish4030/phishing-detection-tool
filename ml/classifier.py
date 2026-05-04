"""
╔══════════════════════════════════════════════════════════════╗
║              ML PHISHING URL CLASSIFIER                      ║
║                  Made by Monish Paramasivam                  ║
╚══════════════════════════════════════════════════════════════╝

A machine learning model trained on URL features to classify
phishing vs. legitimate URLs.

Algorithm: Random Forest Classifier (ensemble method)
Features: 15 numerical features extracted from URL structure

This module:
1. Defines URL feature extraction
2. Trains the model on embedded sample data (no external file needed)
3. Predicts phishing probability for new URLs
4. Saves/loads trained model using joblib

Note: For a production system, you'd train on large datasets like
PhishTank or the UCI Phishing Dataset. This uses a compact
educational training set for demonstration purposes.
"""

import re
import os
import urllib.parse
from pathlib import Path

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    import numpy as np
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

# ─── Model storage path ────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent.parent
MODEL_PATH = BASE_DIR / "ml" / "phishing_model.pkl"
SCALER_PATH = BASE_DIR / "ml" / "scaler.pkl"


# ─── Training data: [features..., label] ──────────────────────────────────────
# Label: 1 = phishing, 0 = safe
# Each row: [url_length, has_ip, subdomain_count, suspicious_kw_count,
#            has_https, has_@, hyphen_count, dot_count, has_shortener,
#            has_suspicious_tld, digit_count, path_depth,
#            has_brand_in_non_official, special_char_count, entropy_score]
TRAINING_DATA = [
    # ── SAFE URLs ──
    [22, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3.2],  # google.com
    [17, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 2.9],  # github.com
    [21, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3.1],  # amazon.com
    [23, 0, 1, 0, 1, 0, 0, 2, 0, 0, 0, 1, 0, 0, 3.3],  # docs.google.com
    [26, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 2, 0, 0, 3.5],  # stackoverflow.com
    [19, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3.0],  # twitter.com
    [20, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3.1],  # linkedin.com
    [21, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3.0],  # facebook.com
    [22, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3.2],  # instagram.com
    [21, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3.0],  # microsoft.com
    [19, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3.0],  # paypal.com
    [19, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3.1],  # netflix.com
    [24, 0, 1, 0, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 3.2],  # mail.google.com
    [28, 0, 1, 0, 1, 0, 0, 2, 0, 0, 0, 1, 0, 0, 3.4],  # drive.google.com/files
    [25, 0, 0, 0, 1, 0, 1, 2, 0, 0, 0, 1, 0, 0, 3.3],  # go.microsoft.com/docs
    # ── PHISHING URLs ──
    [68, 0, 2, 4, 0, 0, 3, 4, 0, 1, 1, 3, 1, 2, 4.8],  # secure-login-verify.paypal-account.xyz
    [72, 0, 3, 5, 0, 1, 4, 5, 0, 1, 2, 4, 1, 3, 5.1],  # amazon.login.verify.secure.evil.com
    [55, 1, 0, 3, 0, 0, 2, 3, 0, 0, 3, 2, 0, 1, 4.5],  # 192.168.1.1/bank/login/verify
    [48, 0, 1, 3, 0, 0, 3, 2, 0, 0, 0, 3, 1, 2, 4.3],  # secure-paypal-login.verify.net
    [61, 0, 2, 4, 1, 0, 2, 3, 0, 1, 2, 2, 1, 1, 4.7],  # apple-id-account-update.secure.tk
    [80, 0, 3, 6, 0, 1, 5, 6, 0, 1, 1, 5, 1, 4, 5.4],  # microsoft.com.login.verify.update.ru
    [44, 0, 0, 2, 0, 0, 2, 2, 0, 1, 1, 2, 1, 1, 4.2],  # netflix-account-update.xyz
    [38, 0, 0, 2, 0, 0, 1, 2, 0, 1, 0, 1, 0, 0, 3.9],  # amazon-verify.info
    [90, 0, 4, 7, 0, 1, 6, 7, 0, 1, 3, 6, 1, 5, 5.8],  # very-long-phishing-url-secure-login-update.com
    [36, 0, 0, 3, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 4.1],  # paypa1.com/verify
    [51, 1, 0, 2, 0, 0, 1, 3, 0, 0, 2, 3, 0, 1, 4.4],  # 10.0.0.1/banking/login/confirm
    [63, 0, 2, 5, 0, 0, 4, 4, 0, 1, 1, 3, 1, 2, 4.9],  # bank-of-america-secure-login.xyz
    [45, 0, 0, 3, 0, 0, 2, 2, 1, 0, 0, 1, 0, 1, 4.0],  # bit.ly/secure-account-verify
    [58, 0, 1, 4, 0, 0, 3, 3, 0, 1, 2, 2, 1, 2, 4.6],  # google-account-suspended.verify.info
    [70, 0, 3, 5, 0, 0, 4, 5, 0, 1, 1, 4, 1, 3, 5.2],  # chase.bank.login.secure.verify.gq
]

LABELS = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # Safe (15)
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  # Phishing (15)
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "bank",
    "confirm", "password", "billing", "payment", "signin", "sign-in",
    "alert", "suspend", "validate", "recover", "unlock", "reset",
]

SUSPICIOUS_TLDS = [".xyz", ".top", ".tk", ".ml", ".cf", ".gq", ".info", ".biz", ".su", ".ru"]
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"]
BRANDS = ["google", "facebook", "amazon", "apple", "microsoft", "netflix", "paypal", "instagram"]


class PhishingClassifier:
    """
    Random Forest ML classifier for phishing URL detection.

    Usage:
        clf = PhishingClassifier()
        result = clf.predict("http://paypa1-verify.xyz")
    """

    def __init__(self):
        """Initialize classifier — load existing model or train new one."""
        self.model = None
        self.scaler = None

        if ML_AVAILABLE:
            self._load_or_train()

    def predict(self, url: str) -> dict:
        """
        Predict whether a URL is phishing using the trained ML model.

        Args:
            url: URL string to classify

        Returns:
            dict with phishing_probability, prediction, and feature breakdown
        """
        if not ML_AVAILABLE:
            return {
                "available": False,
                "phishing_probability": 0.0,
                "prediction": "UNKNOWN",
                "confidence": 0,
                "error": "scikit-learn not installed (run: pip install scikit-learn)",
                "features": {},
            }

        # Extract numerical features from URL
        features = self._extract_features(url)
        feature_vector = list(features.values())

        # Scale features to match training distribution
        feature_array = np.array([feature_vector])
        feature_scaled = self.scaler.transform(feature_array)

        # Get probability estimate [P(safe), P(phishing)]
        probabilities = self.model.predict_proba(feature_scaled)[0]
        phishing_prob = probabilities[1]

        # Classify based on threshold
        if phishing_prob >= 0.7:
            prediction = "PHISHING"
        elif phishing_prob >= 0.4:
            prediction = "SUSPICIOUS"
        else:
            prediction = "SAFE"

        return {
            "available": True,
            "phishing_probability": round(phishing_prob, 3),
            "prediction": prediction,
            "confidence": round(max(probabilities) * 100, 1),
            "features": features,
            "error": None,
        }

    def _extract_features(self, url: str) -> dict:
        """
        Extract 15 numerical features from a URL for ML classification.

        These features capture the key structural properties that
        differentiate phishing URLs from legitimate ones.

        Args:
            url: URL string to analyze

        Returns:
            dict of feature_name → numerical value
        """
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")
        full_lower = url.lower()
        path = parsed.path.lower()

        # Feature 1: URL total length
        url_length = len(url)

        # Feature 2: IP address in URL (1=yes, 0=no)
        has_ip = 1 if re.search(r"\b(\d{1,3}\.){3}\d{1,3}\b", domain) else 0

        # Feature 3: Subdomain depth count
        subdomain_count = max(0, len(domain.split(".")) - 2)

        # Feature 4: Number of suspicious keywords
        kw_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in full_lower)

        # Feature 5: Uses HTTPS (1=yes, 0=no)
        has_https = 1 if parsed.scheme == "https" else 0

        # Feature 6: Contains @ symbol
        has_at = 1 if "@" in url else 0

        # Feature 7: Hyphen count in domain
        hyphen_count = domain.count("-")

        # Feature 8: Total dot count in domain
        dot_count = domain.count(".")

        # Feature 9: URL shortener detected
        has_shortener = 1 if any(s in domain for s in SHORTENERS) else 0

        # Feature 10: Suspicious TLD used
        has_susp_tld = 1 if any(domain.endswith(t) for t in SUSPICIOUS_TLDS) else 0

        # Feature 11: Digit count in domain
        digit_count = sum(c.isdigit() for c in domain)

        # Feature 12: URL path depth
        path_depth = path.strip("/").count("/") if path else 0

        # Feature 13: Brand name in non-official domain
        has_brand = 0
        for brand in BRANDS:
            if brand in domain:
                official_endings = [f"{brand}.com", f"{brand}.co.", f"{brand}.net"]
                if not any(domain.endswith(e) for e in official_endings) or domain.count(".") > 1:
                    has_brand = 1
                    break

        # Feature 14: Special character count (%, &, =, ~, ^)
        special_chars = sum(url.count(c) for c in ["%", "&", "=", "~", "^", "|"])

        # Feature 15: Shannon entropy of domain (high entropy = randomness = suspicious)
        entropy = self._shannon_entropy(domain)

        return {
            "url_length": url_length,
            "has_ip": has_ip,
            "subdomain_count": subdomain_count,
            "suspicious_kw_count": kw_count,
            "has_https": has_https,
            "has_at_symbol": has_at,
            "hyphen_count": hyphen_count,
            "dot_count": dot_count,
            "has_shortener": has_shortener,
            "has_suspicious_tld": has_susp_tld,
            "digit_count": digit_count,
            "path_depth": path_depth,
            "has_brand_spoofing": has_brand,
            "special_char_count": special_chars,
            "domain_entropy": round(entropy, 2),
        }

    def _shannon_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of a string.
        Higher entropy = more random characters = possibly DGA-generated domain.

        Args:
            text: String to calculate entropy for

        Returns:
            Entropy value (0.0 to ~5.0)
        """
        if not text:
            return 0.0
        import math
        from collections import Counter
        freq = Counter(text)
        length = len(text)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    def _load_or_train(self):
        """
        Load a pre-trained model from disk, or train a new one if not found.
        """
        if MODEL_PATH.exists() and SCALER_PATH.exists():
            try:
                self.model = joblib.load(MODEL_PATH)
                self.scaler = joblib.load(SCALER_PATH)
                return
            except Exception:
                pass  # Fall through to retrain

        # Train a new model
        self._train()

    def _train(self):
        """
        Train the Random Forest classifier on the embedded training data.
        Saves the trained model to disk for future use.
        """
        X = np.array(TRAINING_DATA)
        y = np.array(LABELS)

        # Scale features to zero mean, unit variance
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Train Random Forest with 100 decision trees
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=6,
            random_state=42,
            class_weight="balanced",  # Handle class imbalance
        )
        self.model.fit(X_scaled, y)

        # Save to disk
        os.makedirs(MODEL_PATH.parent, exist_ok=True)
        joblib.dump(self.model, MODEL_PATH)
        joblib.dump(self.scaler, SCALER_PATH)

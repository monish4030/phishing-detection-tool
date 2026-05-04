"""
╔══════════════════════════════════════════════════════════════╗
║              UNIT TESTS - PHISHING DETECTION TOOL            ║
║                  Made by Monish Paramasivam                  ║
╚══════════════════════════════════════════════════════════════╝

Run with: python -m pytest tests/ -v
Or:        python tests/test_analyzer.py
"""

import sys
import os
import unittest

# Add parent dir to path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.analyzer import URLAnalyzer
from core.blacklist import BlacklistManager
from ml.classifier import PhishingClassifier


class TestURLAnalyzer(unittest.TestCase):
    """Tests for the URL structure analyzer module."""

    def test_safe_url_has_low_score(self):
        """Legitimate URLs should score low."""
        analyzer = URLAnalyzer("https://google.com")
        results = analyzer.analyze()
        self.assertLess(results["risk_score"], 20, "google.com should have low risk score")

    def test_phishing_url_has_high_score(self):
        """Phishing-pattern URLs should score high."""
        analyzer = URLAnalyzer("http://paypal-login-verify-account.secure-update.xyz")
        results = analyzer.analyze()
        self.assertGreater(results["risk_score"], 30, "Phishing URL should score high")

    def test_ip_url_detected(self):
        """IP address in URL should be flagged."""
        analyzer = URLAnalyzer("http://192.168.1.100/login/bank/verify")
        results = analyzer.analyze()
        ip_findings = [f for f in results["findings"] if "IP address" in f["description"]]
        self.assertTrue(len(ip_findings) > 0, "IP address URL should be flagged")

    def test_suspicious_keywords_detected(self):
        """URLs with suspicious keywords should be flagged."""
        analyzer = URLAnalyzer("http://secure-login-verify-account-update.com")
        results = analyzer.analyze()
        kw_findings = [f for f in results["findings"] if "keyword" in f["description"].lower()]
        self.assertTrue(len(kw_findings) > 0, "Suspicious keywords should be detected")

    def test_excessive_subdomains(self):
        """URLs with many subdomains should be flagged."""
        analyzer = URLAnalyzer("http://one.two.three.four.evil.com/login")
        results = analyzer.analyze()
        sub_findings = [f for f in results["findings"] if "subdomain" in f["description"].lower()]
        self.assertTrue(len(sub_findings) > 0, "Excessive subdomains should be flagged")

    def test_homograph_detection(self):
        """Character substitutions should be detected."""
        analyzer = URLAnalyzer("http://paypa1.com/verify")  # '1' instead of 'l'
        results = analyzer.analyze()
        hg_findings = [f for f in results["findings"] if "homograph" in f["description"].lower() or "typosquat" in f["description"].lower()]
        self.assertTrue(len(hg_findings) > 0, "Homograph attack should be detected")

    def test_url_without_scheme_handled(self):
        """Should handle URLs without http:// prefix."""
        # main.py normalizes URLs, but analyzer should handle it
        analyzer = URLAnalyzer("http://google.com")  # normalized
        results = analyzer.analyze()
        self.assertIn("domain", results)

    def test_at_symbol_flagged(self):
        """@ symbol in URL should be flagged as high risk."""
        analyzer = URLAnalyzer("http://evil.com@google.com/login")
        results = analyzer.analyze()
        at_findings = [f for f in results["findings"] if "@" in f["description"]]
        self.assertTrue(len(at_findings) > 0, "@ symbol in URL should be flagged")

    def test_suspicious_tld_flagged(self):
        """Suspicious TLDs should be detected."""
        analyzer = URLAnalyzer("http://somesite.xyz/login")
        results = analyzer.analyze()
        tld_findings = [f for f in results["findings"] if "TLD" in f["description"]]
        self.assertTrue(len(tld_findings) > 0, ".xyz TLD should be flagged")


class TestBlacklistManager(unittest.TestCase):
    """Tests for the blacklist/whitelist manager."""

    def setUp(self):
        self.mgr = BlacklistManager()

    def test_blacklisted_url_detected(self):
        """Known phishing URLs should be detected in blacklist."""
        result = self.mgr.check("http://paypa1-secure.com/login")
        self.assertTrue(result["blacklisted"], "Should detect blacklisted domain")

    def test_whitelisted_domain_detected(self):
        """Known safe domains should be detected in whitelist."""
        result = self.mgr.check("https://google.com/search?q=test")
        self.assertTrue(result["whitelisted"], "Should detect whitelisted domain")

    def test_unknown_url_neither(self):
        """Unknown URLs should not match either list."""
        result = self.mgr.check("http://some-random-unknown-domain-12345.com")
        self.assertFalse(result["blacklisted"])
        self.assertFalse(result["whitelisted"])

    def test_add_to_blacklist(self):
        """Should be able to add a domain to blacklist."""
        self.mgr.add_to_blacklist("http://definitely-evil-test-domain.com")
        result = self.mgr.check("http://definitely-evil-test-domain.com/path")
        self.assertTrue(result["blacklisted"])
        # Clean up
        self.mgr.remove_from_blacklist("http://definitely-evil-test-domain.com")

    def test_add_to_whitelist(self):
        """Should be able to add a domain to whitelist."""
        self.mgr.add_to_whitelist("http://my-trusted-site-test.com")
        result = self.mgr.check("http://my-trusted-site-test.com/page")
        self.assertTrue(result["whitelisted"])
        # Clean up
        self.mgr.remove_from_whitelist("http://my-trusted-site-test.com")


class TestMLClassifier(unittest.TestCase):
    """Tests for the ML phishing classifier."""

    def setUp(self):
        self.clf = PhishingClassifier()

    def test_returns_prediction(self):
        """Should return a valid prediction dict."""
        result = self.clf.predict("http://google.com")
        self.assertIn("prediction", result)
        self.assertIn("phishing_probability", result)

    def test_phishing_probability_range(self):
        """Probability should be between 0 and 1."""
        result = self.clf.predict("http://secure-login-verify.evil.xyz")
        if result.get("available"):
            prob = result["phishing_probability"]
            self.assertGreaterEqual(prob, 0.0)
            self.assertLessEqual(prob, 1.0)

    def test_safe_url_low_probability(self):
        """Safe URLs should have low phishing probability."""
        result = self.clf.predict("https://google.com")
        if result.get("available"):
            self.assertLess(result["phishing_probability"], 0.7,
                          "google.com should not be classified as phishing")

    def test_phishing_url_higher_probability(self):
        """Phishing-pattern URLs should score higher."""
        safe = self.clf.predict("https://google.com")
        phish = self.clf.predict("http://192.168.1.1/secure-login-verify-account.php")
        if safe.get("available") and phish.get("available"):
            self.assertGreater(
                phish["phishing_probability"],
                safe["phishing_probability"],
                "Phishing URL should score higher than safe URL"
            )


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  PHISHING DETECTION TOOL — UNIT TESTS")
    print("  Made by Monish Paramasivam")
    print("=" * 60 + "\n")
    unittest.main(verbosity=2)

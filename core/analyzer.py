"""
╔══════════════════════════════════════════════════════════════╗
║              URL STRUCTURE ANALYZER MODULE                   ║
║                  Made by Monish Paramasivam                  ║
╚══════════════════════════════════════════════════════════════╝

Analyzes URL structure for phishing indicators:
- Suspicious keywords
- Typosquatting patterns
- Unusual characters / homograph attacks
- Subdomain depth
- URL length
- IP addresses in URL
- Special character abuse
- Brand impersonation
"""

import re
import urllib.parse
from difflib import SequenceMatcher


# ─── Suspicious keyword list ──────────────────────────────────────────────────
# These words commonly appear in phishing URLs to trick users
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "bank",
    "confirm", "password", "credential", "signin", "sign-in",
    "billing", "payment", "paypal", "invoice", "alert", "suspend",
    "validate", "authenticate", "recover", "unlock", "reset",
    "verification", "support", "helpdesk", "free", "winner",
    "prize", "claim", "urgent", "immediate", "access", "activation",
]

# ─── Well-known legitimate brand names commonly impersonated ──────────────────
TARGETED_BRANDS = [
    "google", "facebook", "amazon", "apple", "microsoft", "netflix",
    "paypal", "instagram", "twitter", "linkedin", "dropbox", "adobe",
    "ebay", "yahoo", "outlook", "office365", "wellsfargo", "chase",
    "bankofamerica", "citibank", "irs", "dmv", "fedex", "ups", "dhl",
]

# ─── Common legitimate TLDs (used to detect unusual TLDs) ────────────────────
SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".click", ".link", ".work", ".party", ".gq",
    ".ml", ".cf", ".tk", ".pw", ".su", ".ru", ".info", ".biz",
    ".cc", ".ws", ".name", ".mobi",
]

# ─── Homograph character substitutions used in typosquatting ─────────────────
HOMOGRAPH_MAP = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "@": "a", "$": "s", "!": "i", "vv": "w", "rn": "m",
}


class URLAnalyzer:
    """
    Performs deep structural analysis of a URL to detect phishing signals.

    Usage:
        analyzer = URLAnalyzer("http://paypa1-login-verify.com")
        results = analyzer.analyze()
    """

    def __init__(self, url: str):
        """
        Initialize analyzer with the target URL.

        Args:
            url: The URL string to analyze (should include http/https)
        """
        self.url = url
        self.parsed = urllib.parse.urlparse(url)
        self.domain = self.parsed.netloc.lower()
        self.path = self.parsed.path.lower()
        self.full_url_lower = url.lower()

        # These will be populated during analysis
        self.findings = []    # List of (severity, description) tuples
        self.risk_score = 0   # Cumulative risk score

    def analyze(self) -> dict:
        """
        Run all URL analysis checks and return aggregated results.

        Returns:
            dict with keys: risk_score, findings, details
        """
        self._check_url_length()
        self._check_ip_in_url()
        self._check_subdomain_depth()
        self._check_suspicious_keywords()
        self._check_brand_impersonation()
        self._check_homograph_attack()
        self._check_special_characters()
        self._check_suspicious_tld()
        self._check_path_depth()
        self._check_hex_encoding()
        self._check_multiple_dots()
        self._check_url_shortener()

        return {
            "url": self.url,
            "domain": self.domain,
            "risk_score": self.risk_score,
            "findings": self.findings,
            "parsed": {
                "scheme": self.parsed.scheme,
                "netloc": self.parsed.netloc,
                "path": self.parsed.path,
                "query": self.parsed.query,
            },
        }

    # ─── Individual Check Methods ─────────────────────────────────────────────

    def _check_url_length(self):
        """
        Phishing URLs tend to be very long to hide their true destination.
        Threshold: >75 chars is suspicious, >100 is high risk.
        """
        length = len(self.url)
        if length > 100:
            self._add_finding("HIGH", f"URL is very long ({length} chars) — common phishing tactic", 12)
        elif length > 75:
            self._add_finding("MEDIUM", f"URL is unusually long ({length} chars)", 6)

    def _check_ip_in_url(self):
        """
        Legitimate sites use domain names, not raw IPs.
        IP-based URLs often indicate a phishing or C2 server.
        """
        # Match IPv4 pattern in the domain portion
        ip_pattern = r"\b(\d{1,3}\.){3}\d{1,3}\b"
        if re.search(ip_pattern, self.domain):
            self._add_finding("HIGH", "IP address used instead of domain name — very suspicious", 15)

    def _check_subdomain_depth(self):
        """
        Attackers add subdomains to make fake domains look legitimate.
        e.g., secure.paypal.com.evil.xyz — 'paypal.com' appears but is just a subdomain.
        """
        # Remove 'www' from count as it's standard
        parts = self.domain.replace("www.", "").split(".")
        subdomain_count = len(parts) - 2  # subtract domain + TLD

        if subdomain_count >= 3:
            self._add_finding("HIGH", f"Excessive subdomains ({subdomain_count}) — brand spoofing tactic", 12)
        elif subdomain_count == 2:
            self._add_finding("MEDIUM", f"Multiple subdomains detected ({subdomain_count})", 5)

    def _check_suspicious_keywords(self):
        """
        Scan the full URL for keywords commonly used in phishing attacks.
        Phishing pages use urgency words to manipulate users emotionally.
        """
        found_keywords = []
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in self.full_url_lower:
                found_keywords.append(keyword)

        if len(found_keywords) >= 3:
            self._add_finding("HIGH", f"Multiple suspicious keywords found: {', '.join(found_keywords)}", 15)
        elif len(found_keywords) >= 1:
            self._add_finding("MEDIUM", f"Suspicious keyword(s) in URL: {', '.join(found_keywords)}", 8)

    def _check_brand_impersonation(self):
        """
        Detect when a known brand name appears in a non-legitimate domain.
        e.g., 'amazon-verify.xyz' or 'paypal-login.com'
        """
        for brand in TARGETED_BRANDS:
            if brand in self.domain:
                # Check if it IS the official domain (e.g., google.com, amazon.com)
                # A real brand domain ends with brand.com or brand.co.xx
                official_patterns = [
                    f"{brand}.com", f"{brand}.co.", f"{brand}.org",
                    f"{brand}.net", f"{brand}.io",
                ]
                is_official = any(self.domain.endswith(p) for p in official_patterns)
                # Also check if domain == "brand.com" exactly
                if not is_official or self.domain.count(".") > 1:
                    # Extra subdomains or non-official TLD
                    simple_domain = self.domain.split(".")
                    if len(simple_domain) > 2 or not is_official:
                        self._add_finding(
                            "HIGH",
                            f"Brand name '{brand}' found in non-official domain — possible impersonation",
                            15,
                        )
                        break

    def _check_homograph_attack(self):
        """
        Detect character substitutions used to mimic legitimate domains.
        e.g., paypa1.com (1 → l), g00gle.com (0 → o)
        """
        normalized = self.domain
        subs_found = []
        for fake_char, real_char in HOMOGRAPH_MAP.items():
            if fake_char in normalized:
                subs_found.append(f"'{fake_char}' → '{real_char}'")
                normalized = normalized.replace(fake_char, real_char)

        if subs_found:
            self._add_finding(
                "HIGH",
                f"Homograph/typosquatting chars detected: {', '.join(subs_found)}",
                18,
            )

    def _check_special_characters(self):
        """
        Detect URL-encoded or raw special characters used to obfuscate.
        e.g., %20, @, or multiple hyphens
        """
        # @ in URL is used for credential passing (user:pass@host)
        if "@" in self.url:
            self._add_finding("HIGH", "'@' symbol in URL — may hide real destination", 10)

        # Double slashes in path (not the scheme's //)
        path_check = self.url.split("://")[-1]
        if "//" in path_check:
            self._add_finding("MEDIUM", "Double slashes in URL path — obfuscation attempt", 5)

        # Percent encoding can be used to bypass keyword filters
        if self.url.count("%") > 3:
            self._add_finding("MEDIUM", f"Excessive URL encoding ({self.url.count('%')} encoded chars)", 6)

        # Too many hyphens in domain (e.g., secure-login-verify-account.com)
        hyphen_count = self.domain.count("-")
        if hyphen_count >= 3:
            self._add_finding("HIGH", f"Excessive hyphens in domain ({hyphen_count}) — keyword stuffing", 10)
        elif hyphen_count == 2:
            self._add_finding("MEDIUM", f"Multiple hyphens in domain ({hyphen_count})", 4)

    def _check_suspicious_tld(self):
        """
        Check if the domain uses a TLD commonly associated with phishing.
        Legitimate businesses rarely use .xyz, .tk, .gq, etc.
        """
        for tld in SUSPICIOUS_TLDS:
            if self.domain.endswith(tld):
                self._add_finding("MEDIUM", f"Suspicious TLD used: '{tld}'", 8)
                break

    def _check_path_depth(self):
        """
        Phishing URLs often have deep paths to mimic legitimate navigation.
        e.g., /account/login/verify/reset/confirm
        """
        path_depth = self.path.strip("/").count("/")
        if path_depth >= 5:
            self._add_finding("MEDIUM", f"Deep URL path ({path_depth} levels) — may be obfuscating structure", 5)

    def _check_hex_encoding(self):
        """
        Detect hex-encoded URLs — a tactic to bypass simple URL filters.
        e.g., using %68%74%74%70 to encode 'http'
        """
        hex_matches = re.findall(r"%[0-9a-fA-F]{2}", self.url)
        if len(hex_matches) > 5:
            self._add_finding("MEDIUM", f"Heavy hex encoding in URL ({len(hex_matches)} sequences)", 7)

    def _check_multiple_dots(self):
        """
        Detect excessive dots in the domain — obfuscation or subdomain abuse.
        """
        dot_count = self.domain.count(".")
        if dot_count >= 4:
            self._add_finding("HIGH", f"Too many dots in domain ({dot_count}) — suspicious structure", 10)

    def _check_url_shortener(self):
        """
        Detect known URL shortening services that can hide real destination.
        Attackers use shorteners to disguise malicious URLs.
        """
        shorteners = [
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
            "is.gd", "buff.ly", "adf.ly", "short.link", "cutt.ly",
        ]
        for shortener in shorteners:
            if shortener in self.domain:
                self._add_finding("MEDIUM", f"URL shortener detected ({shortener}) — real destination hidden", 8)
                break

    # ─── Helper Methods ───────────────────────────────────────────────────────

    def _add_finding(self, severity: str, description: str, points: int):
        """
        Record a phishing indicator finding and add to risk score.

        Args:
            severity: "LOW", "MEDIUM", or "HIGH"
            description: Human-readable explanation
            points: Risk points to add to the score
        """
        self.findings.append({
            "severity": severity,
            "description": description,
            "points": points,
        })
        self.risk_score += points

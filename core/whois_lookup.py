"""
╔══════════════════════════════════════════════════════════════╗
║                   WHOIS LOOKUP MODULE                        ║
║                  Made by Monish Paramasivam                  ║
╚══════════════════════════════════════════════════════════════╝

Retrieves and analyzes WHOIS / domain registration data:
- Domain registration date (age)
- Registrant name / organization
- Registrar name
- Expiry date
- Privacy protection status

Why this matters:
  Phishing domains are often newly registered (days or weeks old).
  Legitimate businesses typically have domains that are years old.
"""

import urllib.parse
from datetime import datetime, timezone

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


class WHOISLookup:
    """
    Performs WHOIS lookup on the domain from a given URL.

    Usage:
        lookup = WHOISLookup("https://suspicious-domain.xyz")
        results = lookup.lookup()
    """

    def __init__(self, url: str):
        """
        Initialize with the target URL.

        Args:
            url: Full URL string to extract domain from
        """
        self.url = url
        parsed = urllib.parse.urlparse(url)
        # Extract just the domain, removing www. prefix
        netloc = parsed.netloc or url
        self.domain = netloc.replace("www.", "").split(":")[0]

    def lookup(self) -> dict:
        """
        Perform WHOIS lookup and analyze domain metadata.

        Returns:
            dict with domain info and risk indicators
        """
        results = {
            "domain": self.domain,
            "registrar": None,
            "creation_date": None,
            "expiry_date": None,
            "domain_age_days": None,
            "newly_registered": False,
            "hidden_registrant": False,
            "registrant_org": None,
            "findings": [],
            "error": None,
        }

        if not WHOIS_AVAILABLE:
            results["error"] = "python-whois not installed (run: pip install python-whois)"
            results["findings"].append({
                "severity": "INFO",
                "description": "WHOIS check skipped — install python-whois for domain age analysis",
            })
            return results

        try:
            w = whois.whois(self.domain)

            # ─── Extract registrar name ────────────────────────────────────
            results["registrar"] = str(w.registrar) if w.registrar else "Unknown"

            # ─── Extract creation date ─────────────────────────────────────
            # whois can return a list of dates or a single datetime
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]  # Use first date if multiple

            if creation:
                # Normalize to timezone-naive for comparison
                if hasattr(creation, "tzinfo") and creation.tzinfo:
                    creation = creation.replace(tzinfo=None)
                results["creation_date"] = creation.strftime("%Y-%m-%d")

                # Calculate domain age in days
                age_days = (datetime.utcnow() - creation).days
                results["domain_age_days"] = age_days

                # Newly registered = less than 180 days old (6 months)
                if age_days < 180:
                    results["newly_registered"] = True
                    results["findings"].append({
                        "severity": "HIGH",
                        "description": f"Domain is only {age_days} days old — newly registered domains are high-risk",
                    })
                elif age_days < 365:
                    results["findings"].append({
                        "severity": "MEDIUM",
                        "description": f"Domain is relatively young ({age_days} days old)",
                    })

            # ─── Extract expiry date ───────────────────────────────────────
            expiry = w.expiration_date
            if isinstance(expiry, list):
                expiry = expiry[0]
            if expiry:
                if hasattr(expiry, "tzinfo") and expiry.tzinfo:
                    expiry = expiry.replace(tzinfo=None)
                results["expiry_date"] = expiry.strftime("%Y-%m-%d")

            # ─── Check registrant privacy ──────────────────────────────────
            # Privacy-protected WHOIS hides registrant info
            # While privacy is legitimate, it's common in phishing setups
            registrant = str(w.org or w.registrant_name or "")
            privacy_keywords = ["privacy", "proxy", "whoisguard", "protect", "redacted", "private"]

            if not registrant or any(kw in registrant.lower() for kw in privacy_keywords):
                results["hidden_registrant"] = True
                results["findings"].append({
                    "severity": "MEDIUM",
                    "description": "Registrant information is hidden behind privacy protection",
                })
            else:
                results["registrant_org"] = registrant

        except Exception as e:
            # WHOIS lookup can fail due to rate limiting, network issues, or unsupported TLDs
            results["error"] = str(e)
            results["findings"].append({
                "severity": "INFO",
                "description": f"WHOIS lookup failed (may be rate-limited or unsupported TLD): {str(e)[:60]}",
            })

        return results

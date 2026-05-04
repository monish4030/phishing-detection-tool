"""
╔══════════════════════════════════════════════════════════════╗
║              BLACKLIST / WHITELIST MANAGER                   ║
║                  Made by Monish Paramasivam                  ║
╚══════════════════════════════════════════════════════════════╝

Manages custom URL/domain blacklists and whitelists stored as JSON.
- Blacklist: known phishing/malicious URLs
- Whitelist: known safe/trusted domains

Lists are persisted to JSON files in the data/ folder.
"""

import json
import os
import urllib.parse
from pathlib import Path


# ─── Default file paths ────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent.parent  # Project root
BLACKLIST_FILE = BASE_DIR / "data" / "blacklist.json"
WHITELIST_FILE = BASE_DIR / "data" / "whitelist.json"


# ─── Pre-seeded known phishing domains (for demonstration) ────────────────────
DEFAULT_BLACKLIST = [
    "paypa1-secure.com",
    "amazon-login-verify.xyz",
    "secure-paypal-account.info",
    "netflix-billing-update.com",
    "apple-id-verify.net",
    "microsoft-account-suspended.com",
    "bank0famerica-secure.com",
    "gogle.com",
    "faceb00k-login.com",
    "amazon-prime-cancel.xyz",
]

# ─── Pre-seeded trusted domains (for demonstration) ───────────────────────────
DEFAULT_WHITELIST = [
    "google.com",
    "github.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "stackoverflow.com",
    "wikipedia.org",
    "linkedin.com",
    "youtube.com",
    "twitter.com",
    "reddit.com",
    "facebook.com",
    "instagram.com",
    "netflix.com",
    "paypal.com",
]


class BlacklistManager:
    """
    Manages blacklist and whitelist files for URL classification.

    Usage:
        mgr = BlacklistManager()
        result = mgr.check("http://paypa1-secure.com/login")
    """

    def __init__(self):
        """Initialize and load/create list files."""
        # Ensure data directory exists
        os.makedirs(BASE_DIR / "data", exist_ok=True)

        self.blacklist = self._load_list(BLACKLIST_FILE, DEFAULT_BLACKLIST)
        self.whitelist = self._load_list(WHITELIST_FILE, DEFAULT_WHITELIST)

    def check(self, url: str) -> dict:
        """
        Check if a URL/domain matches any entry in blacklist or whitelist.

        Domain matching is done on the base domain (strips subdomains and path).

        Args:
            url: Full URL to check

        Returns:
            dict with blacklisted, whitelisted, and matched_entry keys
        """
        domain = self._extract_domain(url)
        url_lower = url.lower()

        # ─── Check blacklist ───────────────────────────────────────────────
        for entry in self.blacklist:
            entry_lower = entry.lower().strip()
            if entry_lower in url_lower or entry_lower in domain:
                return {
                    "blacklisted": True,
                    "whitelisted": False,
                    "matched_entry": entry,
                    "list_type": "blacklist",
                    "findings": [{
                        "severity": "CRITICAL",
                        "description": f"URL matches known phishing entry in blacklist: '{entry}'",
                    }],
                }

        # ─── Check whitelist ───────────────────────────────────────────────
        for entry in self.whitelist:
            entry_lower = entry.lower().strip()
            if domain == entry_lower or domain.endswith("." + entry_lower):
                return {
                    "blacklisted": False,
                    "whitelisted": True,
                    "matched_entry": entry,
                    "list_type": "whitelist",
                    "findings": [{
                        "severity": "SAFE",
                        "description": f"Domain matches trusted whitelist entry: '{entry}'",
                    }],
                }

        # ─── Not in either list ────────────────────────────────────────────
        return {
            "blacklisted": False,
            "whitelisted": False,
            "matched_entry": None,
            "list_type": None,
            "findings": [],
        }

    def add_to_blacklist(self, url: str):
        """Add a URL or domain to the blacklist and save."""
        domain = self._extract_domain(url)
        if domain not in self.blacklist:
            self.blacklist.append(domain)
            self._save_list(BLACKLIST_FILE, self.blacklist)

    def add_to_whitelist(self, url: str):
        """Add a URL or domain to the whitelist and save."""
        domain = self._extract_domain(url)
        if domain not in self.whitelist:
            self.whitelist.append(domain)
            self._save_list(WHITELIST_FILE, self.whitelist)

    def remove_from_blacklist(self, url: str):
        """Remove a URL or domain from the blacklist."""
        domain = self._extract_domain(url)
        if domain in self.blacklist:
            self.blacklist.remove(domain)
            self._save_list(BLACKLIST_FILE, self.blacklist)

    def remove_from_whitelist(self, url: str):
        """Remove a URL or domain from the whitelist."""
        domain = self._extract_domain(url)
        if domain in self.whitelist:
            self.whitelist.remove(domain)
            self._save_list(WHITELIST_FILE, self.whitelist)

    def get_blacklist(self) -> list:
        """Return current blacklist entries."""
        return self.blacklist

    def get_whitelist(self) -> list:
        """Return current whitelist entries."""
        return self.whitelist

    # ─── Private helpers ──────────────────────────────────────────────────────

    def _extract_domain(self, url: str) -> str:
        """
        Extract base domain from a URL string.
        'https://secure.paypal.com/login' → 'paypal.com' ... actually returns netloc.
        We keep www-stripped netloc for matching flexibility.
        """
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        parsed = urllib.parse.urlparse(url.lower())
        domain = parsed.netloc.replace("www.", "").split(":")[0]
        return domain

    def _load_list(self, filepath: Path, defaults: list) -> list:
        """
        Load a list from a JSON file. Create with defaults if not found.

        Args:
            filepath: Path to the JSON file
            defaults: Default list to use if file doesn't exist

        Returns:
            list of entries
        """
        if filepath.exists():
            try:
                with open(filepath, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass  # Fall through to defaults

        # File doesn't exist or is corrupted — create it with defaults
        self._save_list(filepath, defaults)
        return defaults.copy()

    def _save_list(self, filepath: Path, data: list):
        """
        Save a list to a JSON file.

        Args:
            filepath: Path to write to
            data: List to serialize
        """
        os.makedirs(filepath.parent, exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

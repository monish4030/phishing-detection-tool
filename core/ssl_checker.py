"""
╔══════════════════════════════════════════════════════════════╗
║                 SSL / HTTPS CHECKER MODULE                   ║
║                  Made by Monish Paramasivam                  ║
╚══════════════════════════════════════════════════════════════╝

Validates HTTPS usage and SSL certificate details:
- Is the site using HTTPS?
- Is the SSL certificate valid?
- Is it self-signed?
- What is the certificate expiry date?
- Who issued the certificate?
"""

import ssl
import socket
import urllib.parse
from datetime import datetime


class SSLChecker:
    """
    Checks SSL/TLS configuration of a given URL.

    Phishing sites often:
    - Use plain HTTP (no encryption)
    - Have expired or self-signed certificates
    - Use free CAs with no domain verification

    Usage:
        checker = SSLChecker("https://google.com")
        results = checker.check()
    """

    def __init__(self, url: str):
        """
        Initialize with the target URL.

        Args:
            url: Full URL string (e.g., "https://example.com/path")
        """
        self.url = url
        self.parsed = urllib.parse.urlparse(url)
        self.hostname = self.parsed.netloc.split(":")[0]  # Strip port if present
        self.scheme = self.parsed.scheme.lower()

    def check(self) -> dict:
        """
        Perform all SSL/HTTPS checks and return results.

        Returns:
            dict with keys: https, cert_valid, cert_error, self_signed,
                            issuer, expiry, days_until_expiry, details
        """
        results = {
            "https": self.scheme == "https",
            "cert_valid": False,
            "cert_error": None,
            "self_signed": False,
            "issuer": None,
            "subject": None,
            "expiry": None,
            "days_until_expiry": None,
            "findings": [],
        }

        # If not HTTPS, flag immediately and skip cert checks
        if not results["https"]:
            results["findings"].append({
                "severity": "HIGH",
                "description": "Site uses HTTP — no encryption, data is transmitted in plaintext",
            })
            return results

        # Try to retrieve and analyze the SSL certificate
        try:
            cert_info = self._get_certificate()
            results.update(cert_info)

        except ssl.SSLCertVerificationError as e:
            # Certificate failed validation (expired, wrong domain, untrusted CA)
            results["cert_error"] = str(e)
            results["findings"].append({
                "severity": "HIGH",
                "description": f"SSL certificate verification failed: {str(e)[:80]}",
            })

        except ssl.SSLError as e:
            results["cert_error"] = str(e)
            results["findings"].append({
                "severity": "MEDIUM",
                "description": f"SSL error encountered: {str(e)[:80]}",
            })

        except socket.timeout:
            results["cert_error"] = "Connection timed out"
            results["findings"].append({
                "severity": "MEDIUM",
                "description": "Connection timed out while checking SSL",
            })

        except ConnectionRefusedError:
            results["cert_error"] = "Connection refused"
            results["findings"].append({
                "severity": "MEDIUM",
                "description": "Connection refused — server may be down or blocking",
            })

        except Exception as e:
            # Catch-all for network errors (DNS failure, etc.)
            results["cert_error"] = str(e)
            results["findings"].append({
                "severity": "MEDIUM",
                "description": f"Could not connect to verify SSL: {str(e)[:80]}",
            })

        return results

    def _get_certificate(self) -> dict:
        """
        Connect to the server via TLS and extract certificate information.

        Returns:
            dict with certificate details
        """
        context = ssl.create_default_context()
        info = {}

        # Connect with a 5 second timeout to avoid hanging
        with socket.create_connection((self.hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                cert = ssock.getpeercert()

        # ─── Parse certificate fields ──────────────────────────────────────
        # Extract issuer (who signed the cert)
        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
        issuer_org = issuer_dict.get("organizationName", "Unknown")
        info["issuer"] = issuer_org

        # Extract subject (who the cert is issued to)
        subject_dict = dict(x[0] for x in cert.get("subject", []))
        info["subject"] = subject_dict.get("commonName", self.hostname)

        # ─── Check expiry date ─────────────────────────────────────────────
        expiry_str = cert.get("notAfter", "")
        if expiry_str:
            expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
            info["expiry"] = expiry_date.strftime("%Y-%m-%d")
            days_left = (expiry_date - datetime.utcnow()).days
            info["days_until_expiry"] = days_left
        else:
            info["expiry"] = None
            info["days_until_expiry"] = None

        # ─── Check for self-signed certificate ────────────────────────────
        # A self-signed cert has the same issuer and subject
        issuer_cn = issuer_dict.get("commonName", "")
        subject_cn = subject_dict.get("commonName", "")
        info["self_signed"] = (issuer_cn == subject_cn or issuer_org in ["", "Unknown"])

        # ─── Mark cert as valid if we got here without exception ──────────
        info["cert_valid"] = True
        info["findings"] = []

        # ─── Additional findings ───────────────────────────────────────────
        if info.get("self_signed"):
            info["findings"].append({
                "severity": "HIGH",
                "description": "Certificate appears to be self-signed — not issued by a trusted CA",
            })

        if info.get("days_until_expiry") is not None:
            if info["days_until_expiry"] < 0:
                info["findings"].append({
                    "severity": "HIGH",
                    "description": f"SSL certificate has EXPIRED ({abs(info['days_until_expiry'])} days ago)",
                })
            elif info["days_until_expiry"] < 7:
                info["findings"].append({
                    "severity": "MEDIUM",
                    "description": f"SSL certificate expires very soon ({info['days_until_expiry']} days)",
                })

        return info

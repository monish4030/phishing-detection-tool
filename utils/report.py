"""
╔══════════════════════════════════════════════════════════════╗
║                  REPORT GENERATOR MODULE                     ║
║                  Made by Monish Paramasivam                  ║
╚══════════════════════════════════════════════════════════════╝

Saves phishing analysis results to a text report file.
Reports are saved to the reports/ directory with a timestamp.
"""

import os
import json
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).parent.parent
REPORTS_DIR = BASE_DIR / "reports"


class ReportGenerator:
    """
    Generates and saves text-based analysis reports.

    Usage:
        gen = ReportGenerator()
        filepath = gen.save(all_results)
    """

    def save(self, results: dict) -> str:
        """
        Save full analysis results to a text report file.

        Args:
            results: Combined dict from all analysis modules

        Returns:
            str: Path to saved report file
        """
        os.makedirs(REPORTS_DIR, exist_ok=True)

        # Create timestamped filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Sanitize URL for filename
        url_slug = results["url"].replace("https://", "").replace("http://", "")
        url_slug = "".join(c if c.isalnum() or c in "-_." else "_" for c in url_slug)[:30]
        filename = f"report_{url_slug}_{timestamp}.txt"
        filepath = REPORTS_DIR / filename

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self._build_report(results))

        return str(filepath)

    def _build_report(self, results: dict) -> str:
        """Build the full report as a string."""
        lines = []
        sep = "=" * 65

        lines.append(sep)
        lines.append("  PHISHING DETECTION TOOL — ANALYSIS REPORT")
        lines.append("  Made by Monish Paramasivam")
        lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(sep)

        # Target URL
        lines.append(f"\nTARGET URL:\n  {results['url']}")

        # Risk Score
        score = results["final_score"]
        lines.append(f"\nRISK ASSESSMENT:")
        lines.append(f"  Risk Level : {score['label']}")
        lines.append(f"  Risk Score : {score['score']} / 100")

        # Score breakdown
        if score.get("breakdown"):
            lines.append("\nSCORE BREAKDOWN:")
            for item in score["breakdown"]:
                lines.append(f"  • {item}")

        # URL Analysis
        url_data = results["url_analysis"]
        lines.append("\nURL STRUCTURE ANALYSIS:")
        lines.append(f"  Domain : {url_data.get('domain')}")
        lines.append(f"  Scheme : {url_data['parsed']['scheme'].upper()}")
        findings = url_data.get("findings", [])
        if findings:
            for f in findings:
                lines.append(f"  [{f['severity']}] {f['description']}")
        else:
            lines.append("  No suspicious URL patterns found.")

        # SSL
        ssl_data = results["ssl"]
        lines.append("\nSSL / HTTPS:")
        lines.append(f"  HTTPS     : {'Yes' if ssl_data.get('https') else 'No'}")
        lines.append(f"  Cert Valid: {'Yes' if ssl_data.get('cert_valid') else 'No'}")
        if ssl_data.get("issuer"):
            lines.append(f"  Issuer    : {ssl_data['issuer']}")
        if ssl_data.get("expiry"):
            lines.append(f"  Expiry    : {ssl_data['expiry']}")
        if ssl_data.get("cert_error"):
            lines.append(f"  Error     : {ssl_data['cert_error']}")

        # WHOIS
        whois_data = results["whois"]
        lines.append("\nDOMAIN / WHOIS:")
        if whois_data.get("creation_date"):
            lines.append(f"  Registered : {whois_data['creation_date']} ({whois_data.get('domain_age_days', '?')} days ago)")
        if whois_data.get("registrar"):
            lines.append(f"  Registrar  : {whois_data['registrar']}")
        for f in whois_data.get("findings", []):
            lines.append(f"  [{f['severity']}] {f['description']}")

        # List check
        list_data = results["list_check"]
        lines.append("\nBLACKLIST / WHITELIST:")
        if list_data.get("blacklisted"):
            lines.append(f"  STATUS: BLACKLISTED (matched: {list_data['matched_entry']})")
        elif list_data.get("whitelisted"):
            lines.append(f"  STATUS: WHITELISTED (matched: {list_data['matched_entry']})")
        else:
            lines.append("  STATUS: Not found in either list")

        # ML
        ml_data = results["ml"]
        lines.append("\nML CLASSIFIER:")
        if ml_data.get("available"):
            lines.append(f"  Prediction        : {ml_data['prediction']}")
            lines.append(f"  Phishing Prob     : {ml_data['phishing_probability']:.1%}")
            lines.append(f"  Model Confidence  : {ml_data['confidence']}%")
        else:
            lines.append(f"  Unavailable: {ml_data.get('error')}")

        lines.append("\n" + sep)
        lines.append("  DISCLAIMER: For educational and ethical use only.")
        lines.append("  Made by Monish Paramasivam | Phishing Detection Tool v1.0")
        lines.append(sep)

        return "\n".join(lines)

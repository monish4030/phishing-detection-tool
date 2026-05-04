"""
╔══════════════════════════════════════════════════════════════╗
║                TERMINAL DISPLAY UTILITY                      ║
║                  Made by Monish Paramasivam                  ║
╚══════════════════════════════════════════════════════════════╝

Handles all formatted terminal output for the phishing analysis report.
Uses ANSI color codes for visual clarity and severity highlighting.
"""


class Display:
    """
    Renders analysis results as a formatted, color-coded terminal report.

    Usage:
        display = Display()
        display.show_full_report(all_results)
    """

    # ─── ANSI Color codes ──────────────────────────────────────────────────────
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    def show_full_report(self, results: dict):
        """
        Render the complete phishing analysis report to terminal.

        Args:
            results: Combined dict from all analysis modules
        """
        print("\n" + self.GRAY + "═" * 65 + self.RESET)
        print(f"{self.BOLD}{self.CYAN}  PHISHING ANALYSIS REPORT{self.RESET}")
        print(f"{self.GRAY}  Made by Monish Paramasivam{self.RESET}")
        print(self.GRAY + "═" * 65 + self.RESET)

        # ─── URL Info ──────────────────────────────────────────────────────
        print(f"\n{self.CYAN}[TARGET URL]{self.RESET}")
        print(f"  {self.WHITE}{results['url']}{self.RESET}")

        # ─── Final Risk Score Banner ───────────────────────────────────────
        self._show_risk_banner(results["final_score"])

        # ─── Score Breakdown ───────────────────────────────────────────────
        self._show_score_breakdown(results["final_score"])

        # ─── URL Structure Analysis ────────────────────────────────────────
        self._show_url_analysis(results["url_analysis"])

        # ─── SSL / HTTPS Status ────────────────────────────────────────────
        self._show_ssl_results(results["ssl"])

        # ─── WHOIS / Domain Info ───────────────────────────────────────────
        self._show_whois_results(results["whois"])

        # ─── Blacklist / Whitelist ─────────────────────────────────────────
        self._show_list_results(results["list_check"])

        # ─── ML Classifier ────────────────────────────────────────────────
        self._show_ml_results(results["ml"])

        # ─── Footer ───────────────────────────────────────────────────────
        print("\n" + self.GRAY + "─" * 65)
        print(f"  ⚠  This tool is for educational purposes only.")
        print(f"  🛡  Made by Monish Paramasivam | Phishing Detection Tool v1.0")
        print("─" * 65 + self.RESET + "\n")

    def _show_risk_banner(self, score_data: dict):
        """Display the large risk level banner."""
        score = score_data["score"]
        label = score_data["label"]
        emoji = score_data["emoji"]
        color = score_data["color"]

        # Choose border character based on risk
        border_char = "█" if label == "HIGH" else ("▓" if label == "MEDIUM" else "░")

        print(f"\n{self.GRAY}{'─' * 65}{self.RESET}")
        print(f"{color}{border_char * 65}{self.RESET}")
        print(f"{color}{border_char}{'':^63}{border_char}{self.RESET}")
        print(f"{color}{border_char}{f'{emoji}  RISK LEVEL: {label}  |  SCORE: {score}/100':^63}{border_char}{self.RESET}")
        print(f"{color}{border_char}{'':^63}{border_char}{self.RESET}")
        print(f"{color}{border_char * 65}{self.RESET}")

    def _show_score_breakdown(self, score_data: dict):
        """Display what contributed to the risk score."""
        breakdown = score_data.get("breakdown", [])
        if not breakdown:
            return

        print(f"\n{self.CYAN}[SCORE BREAKDOWN]{self.RESET}")
        for item in breakdown:
            print(f"  {self.GRAY}•{self.RESET} {item}")

    def _show_url_analysis(self, url_data: dict):
        """Display URL structure analysis results."""
        print(f"\n{self.CYAN}[1] URL STRUCTURE ANALYSIS{self.RESET}")
        print(f"  {self.GRAY}Domain:{self.RESET} {url_data.get('domain', 'N/A')}")
        print(f"  {self.GRAY}Scheme:{self.RESET} {url_data['parsed']['scheme'].upper()}")

        path = url_data['parsed']['path']
        if path and path != "/":
            print(f"  {self.GRAY}Path:{self.RESET}   {path}")

        findings = url_data.get("findings", [])
        if findings:
            print(f"\n  {self.YELLOW}Findings ({len(findings)}):{self.RESET}")
            for f in findings:
                color = self._severity_color(f["severity"])
                icon = self._severity_icon(f["severity"])
                print(f"  {color}{icon} [{f['severity']}]{self.RESET} {f['description']}")
        else:
            print(f"  {self.GREEN}✓ No suspicious URL patterns detected{self.RESET}")

    def _show_ssl_results(self, ssl_data: dict):
        """Display SSL/HTTPS check results."""
        print(f"\n{self.CYAN}[2] SSL / HTTPS STATUS{self.RESET}")

        https_icon = f"{self.GREEN}✓ HTTPS" if ssl_data.get("https") else f"{self.RED}✗ HTTP (insecure)"
        print(f"  Protocol:    {https_icon}{self.RESET}")

        if ssl_data.get("cert_valid"):
            print(f"  Certificate: {self.GREEN}✓ Valid{self.RESET}")
        if ssl_data.get("issuer"):
            print(f"  Issuer:      {ssl_data['issuer']}")
        if ssl_data.get("expiry"):
            days = ssl_data.get("days_until_expiry", "?")
            days_color = self.GREEN if (isinstance(days, int) and days > 30) else self.YELLOW
            print(f"  Expiry:      {ssl_data['expiry']} ({days_color}{days} days remaining{self.RESET})")
        if ssl_data.get("cert_error"):
            print(f"  Error:       {self.RED}{ssl_data['cert_error'][:70]}{self.RESET}")

        findings = ssl_data.get("findings", [])
        for f in findings:
            color = self._severity_color(f["severity"])
            icon = self._severity_icon(f["severity"])
            print(f"  {color}{icon} [{f['severity']}]{self.RESET} {f['description']}")

    def _show_whois_results(self, whois_data: dict):
        """Display WHOIS domain information."""
        print(f"\n{self.CYAN}[3] DOMAIN / WHOIS INFO{self.RESET}")

        if whois_data.get("error") and not whois_data.get("creation_date"):
            print(f"  {self.YELLOW}⚠ {whois_data['error']}{self.RESET}")
            return

        if whois_data.get("registrar"):
            print(f"  Registrar:  {whois_data['registrar']}")
        if whois_data.get("creation_date"):
            age = whois_data.get("domain_age_days", "?")
            age_color = self.RED if whois_data.get("newly_registered") else self.GREEN
            print(f"  Registered: {whois_data['creation_date']} ({age_color}{age} days ago{self.RESET})")
        if whois_data.get("expiry_date"):
            print(f"  Expires:    {whois_data['expiry_date']}")
        if whois_data.get("registrant_org"):
            print(f"  Registrant: {whois_data['registrant_org']}")

        findings = whois_data.get("findings", [])
        for f in findings:
            color = self._severity_color(f["severity"])
            icon = self._severity_icon(f["severity"])
            print(f"  {color}{icon} [{f['severity']}]{self.RESET} {f['description']}")

    def _show_list_results(self, list_data: dict):
        """Display blacklist/whitelist match results."""
        print(f"\n{self.CYAN}[4] BLACKLIST / WHITELIST{self.RESET}")

        if list_data.get("blacklisted"):
            print(f"  {self.RED}🚫 BLACKLISTED — Matched: '{list_data['matched_entry']}'{self.RESET}")
        elif list_data.get("whitelisted"):
            print(f"  {self.GREEN}✅ WHITELISTED — Trusted: '{list_data['matched_entry']}'{self.RESET}")
        else:
            print(f"  {self.GRAY}— Not found in either list{self.RESET}")

    def _show_ml_results(self, ml_data: dict):
        """Display machine learning classifier results."""
        print(f"\n{self.CYAN}[5] ML CLASSIFIER RESULT{self.RESET}")

        if not ml_data.get("available"):
            print(f"  {self.YELLOW}⚠ {ml_data.get('error', 'ML not available')}{self.RESET}")
            return

        prob = ml_data.get("phishing_probability", 0)
        pred = ml_data.get("prediction", "UNKNOWN")
        conf = ml_data.get("confidence", 0)

        pred_color = self.RED if pred == "PHISHING" else (self.YELLOW if pred == "SUSPICIOUS" else self.GREEN)
        print(f"  Prediction:       {pred_color}{pred}{self.RESET}")
        print(f"  Phishing Prob:    {self._probability_bar(prob)} {prob:.1%}")
        print(f"  Model Confidence: {conf}%")

        # Show top contributing features
        features = ml_data.get("features", {})
        if features:
            print(f"\n  {self.GRAY}Key Features:{self.RESET}")
            notable = {
                "url_length": ("URL Length", features.get("url_length", 0), ">75 is suspicious"),
                "subdomain_count": ("Subdomains", features.get("subdomain_count", 0), ">2 is suspicious"),
                "suspicious_kw_count": ("Suspicious Keywords", features.get("suspicious_kw_count", 0), ">2 is risky"),
                "hyphen_count": ("Hyphens in Domain", features.get("hyphen_count", 0), ">2 is risky"),
                "has_ip": ("IP in URL", features.get("has_ip", 0), "1=yes"),
                "domain_entropy": ("Domain Entropy", features.get("domain_entropy", 0), ">4.5 is suspicious"),
            }
            for key, (label, val, hint) in notable.items():
                val_color = self.GRAY if val == 0 else self.YELLOW
                print(f"  {self.GRAY}  {label:<22}{self.RESET} {val_color}{val}{self.RESET} {self.GRAY}({hint}){self.RESET}")

    def _probability_bar(self, prob: float, width: int = 20) -> str:
        """
        Render a colored ASCII progress bar for phishing probability.

        Args:
            prob: Float between 0.0 and 1.0
            width: Character width of the bar

        Returns:
            Colored bar string
        """
        filled = int(prob * width)
        empty = width - filled

        if prob >= 0.7:
            bar_color = self.RED
        elif prob >= 0.4:
            bar_color = self.YELLOW
        else:
            bar_color = self.GREEN

        bar = f"{bar_color}{'█' * filled}{'░' * empty}{self.RESET}"
        return f"[{bar}]"

    def _severity_color(self, severity: str) -> str:
        """Map severity string to ANSI color code."""
        return {
            "CRITICAL": self.RED,
            "HIGH": self.RED,
            "MEDIUM": self.YELLOW,
            "LOW": self.GREEN,
            "SAFE": self.GREEN,
            "INFO": self.GRAY,
        }.get(severity.upper(), self.WHITE)

    def _severity_icon(self, severity: str) -> str:
        """Map severity string to an icon character."""
        return {
            "CRITICAL": "🚨",
            "HIGH": "⛔",
            "MEDIUM": "⚠️ ",
            "LOW": "ℹ️ ",
            "SAFE": "✅",
            "INFO": "ℹ️ ",
        }.get(severity.upper(), "•")

#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║           PHISHING DETECTION TOOL - MAIN ENTRY POINT        ║
║                  Made by Monish Paramasivam                  ║
║            For Educational & Ethical Use Only                ║
╚══════════════════════════════════════════════════════════════╝

This is the main CLI interface for the Phishing Detection Tool.
It provides a menu-driven experience for analyzing URLs.
"""

import sys
import os
from core.analyzer import URLAnalyzer
from core.ssl_checker import SSLChecker
from core.whois_lookup import WHOISLookup
from core.blacklist import BlacklistManager
from ml.classifier import PhishingClassifier
from utils.display import Display
from utils.report import ReportGenerator


def print_banner():
    """Print the tool banner with author credit."""
    banner = """
\033[91m
 ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗███╗   ██╗ ██████╗
 ██╔══██╗██║  ██║██║██╔════╝██║  ██║██║████╗  ██║██╔════╝
 ██████╔╝███████║██║███████╗███████║██║██╔██╗ ██║██║  ███╗
 ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║██║╚██╗██║██║   ██║
 ██║     ██║  ██║██║███████║██║  ██║██║██║ ╚████║╚██████╔╝
 ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝
\033[0m
\033[93m ██████╗ ███████╗████████╗███████╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗
 ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║
 ██║  ██║█████╗     ██║   █████╗  ██║        ██║   ██║██║   ██║██╔██╗ ██║
 ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   ██║██║   ██║██║╚██╗██║
 ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   ██║╚██████╔╝██║ ╚████║
 ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝\033[0m

\033[96m ████████╗ ██████╗  ██████╗ ██╗
 ╚══██╔══╝██╔═══██╗██╔═══██╗██║
    ██║   ██║   ██║██║   ██║██║
    ██║   ██║   ██║██║   ██║██║
    ██║   ╚██████╔╝╚██████╔╝███████╗
    ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝\033[0m

\033[90m{'─'*60}\033[0m
\033[92m  ★  Made by Monish Paramasivam  ★  v1.0.0  ★  Educational Use\033[0m
\033[90m{'─'*60}\033[0m
"""
    print(banner)


def print_menu():
    """Print the main menu."""
    print("\n\033[96m┌─────────────────────────────────────────┐\033[0m")
    print("\033[96m│           MAIN MENU                     │\033[0m")
    print("\033[96m├─────────────────────────────────────────┤\033[0m")
    print("\033[96m│\033[0m  \033[93m[1]\033[0m Analyze a Single URL               \033[96m│\033[0m")
    print("\033[96m│\033[0m  \033[93m[2]\033[0m Analyze Multiple URLs (Batch)      \033[96m│\033[0m")
    print("\033[96m│\033[0m  \033[93m[3]\033[0m Manage Blacklist / Whitelist        \033[96m│\033[0m")
    print("\033[96m│\033[0m  \033[93m[4]\033[0m View Sample Test URLs              \033[96m│\033[0m")
    print("\033[96m│\033[0m  \033[93m[5]\033[0m About This Tool                    \033[96m│\033[0m")
    print("\033[96m│\033[0m  \033[93m[0]\033[0m Exit                               \033[96m│\033[0m")
    print("\033[96m└─────────────────────────────────────────┘\033[0m")


def analyze_url_flow(url=None):
    """
    Run the full phishing analysis pipeline on a single URL.
    This is the core workflow of the tool.
    """
    display = Display()

    if not url:
        url = input("\n\033[96m[?] Enter URL to analyze: \033[0m").strip()

    if not url:
        print("\033[91m[!] No URL provided.\033[0m")
        return

    # Normalize URL - add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    print(f"\n\033[93m[*] Starting analysis for: {url}\033[0m")
    print("\033[90m" + "─" * 60 + "\033[0m")

    # --- Step 1: URL Structure Analysis ---
    print("\033[96m[1/5] Analyzing URL structure...\033[0m")
    analyzer = URLAnalyzer(url)
    url_results = analyzer.analyze()

    # --- Step 2: SSL Certificate Check ---
    print("\033[96m[2/5] Checking SSL/HTTPS...\033[0m")
    ssl_checker = SSLChecker(url)
    ssl_results = ssl_checker.check()

    # --- Step 3: WHOIS / Domain Info ---
    print("\033[96m[3/5] Fetching domain information...\033[0m")
    whois_lookup = WHOISLookup(url)
    whois_results = whois_lookup.lookup()

    # --- Step 4: Blacklist / Whitelist Check ---
    print("\033[96m[4/5] Checking blacklist/whitelist...\033[0m")
    blacklist_mgr = BlacklistManager()
    list_results = blacklist_mgr.check(url)

    # --- Step 5: ML Classification ---
    print("\033[96m[5/5] Running ML classifier...\033[0m")
    classifier = PhishingClassifier()
    ml_results = classifier.predict(url)

    # --- Aggregate Results & Compute Final Score ---
    all_results = {
        "url": url,
        "url_analysis": url_results,
        "ssl": ssl_results,
        "whois": whois_results,
        "list_check": list_results,
        "ml": ml_results,
    }

    final_score = compute_final_score(all_results)
    all_results["final_score"] = final_score

    # --- Display Results ---
    display.show_full_report(all_results)

    # --- Optional: Save Report ---
    save = input("\n\033[96m[?] Save report to file? (y/n): \033[0m").strip().lower()
    if save == "y":
        report_gen = ReportGenerator()
        filepath = report_gen.save(all_results)
        print(f"\033[92m[✓] Report saved to: {filepath}\033[0m")


def compute_final_score(results):
    """
    Compute aggregate phishing risk score from all analysis modules.

    Scoring system:
    - URL analysis findings: up to 40 points
    - SSL issues: up to 20 points
    - WHOIS red flags: up to 15 points
    - Blacklist match: 30 points instantly
    - ML classifier: up to 25 points
    Max possible: 100+ (capped at 100)

    Returns:
        dict with score (0-100), label (Low/Medium/High), and breakdown
    """
    score = 0
    breakdown = []

    # URL structure score
    url_score = results["url_analysis"].get("risk_score", 0)
    score += min(url_score, 40)
    if url_score > 0:
        breakdown.append(f"URL structure issues: +{min(url_score, 40)} pts")

    # SSL score
    ssl_data = results["ssl"]
    if not ssl_data.get("https"):
        score += 15
        breakdown.append("No HTTPS: +15 pts")
    if ssl_data.get("cert_error"):
        score += 10
        breakdown.append("SSL cert error: +10 pts")
    if ssl_data.get("self_signed"):
        score += 5
        breakdown.append("Self-signed cert: +5 pts")

    # WHOIS score
    whois_data = results["whois"]
    if whois_data.get("newly_registered"):
        score += 10
        breakdown.append("Domain <6 months old: +10 pts")
    if whois_data.get("hidden_registrant"):
        score += 5
        breakdown.append("Registrant hidden: +5 pts")

    # Blacklist score
    list_data = results["list_check"]
    if list_data.get("blacklisted"):
        score += 30
        breakdown.append("URL is BLACKLISTED: +30 pts")
    if list_data.get("whitelisted"):
        score -= 20
        breakdown.append("URL is WHITELISTED: -20 pts")

    # ML classifier score
    ml_data = results["ml"]
    ml_contribution = int(ml_data.get("phishing_probability", 0) * 25)
    score += ml_contribution
    if ml_contribution > 0:
        breakdown.append(f"ML classifier risk: +{ml_contribution} pts")

    # Clamp score between 0 and 100
    score = max(0, min(100, score))

    # Determine risk label
    if score <= 30:
        label = "LOW"
        color = "\033[92m"  # Green
        emoji = "✅"
    elif score <= 65:
        label = "MEDIUM"
        color = "\033[93m"  # Yellow
        emoji = "⚠️"
    else:
        label = "HIGH"
        color = "\033[91m"  # Red
        emoji = "🚨"

    return {
        "score": score,
        "label": label,
        "color": color,
        "emoji": emoji,
        "breakdown": breakdown,
    }


def batch_analyze():
    """Analyze multiple URLs from user input or a text file."""
    print("\n\033[96m[?] Enter URLs (one per line). Type 'done' when finished:\033[0m")
    urls = []
    while True:
        line = input("    URL: ").strip()
        if line.lower() == "done":
            break
        if line:
            urls.append(line)

    if not urls:
        print("\033[91m[!] No URLs entered.\033[0m")
        return

    print(f"\n\033[93m[*] Analyzing {len(urls)} URL(s)...\033[0m\n")
    for i, url in enumerate(urls, 1):
        print(f"\033[90m{'═'*60}\033[0m")
        print(f"\033[93m[URL {i}/{len(urls)}]\033[0m")
        analyze_url_flow(url)


def manage_lists():
    """Menu for managing blacklist and whitelist."""
    mgr = BlacklistManager()
    print("\n\033[96m┌─────────────────────────────────┐\033[0m")
    print("\033[96m│    BLACKLIST / WHITELIST MENU   │\033[0m")
    print("\033[96m├─────────────────────────────────┤\033[0m")
    print("\033[96m│\033[0m  \033[93m[1]\033[0m Add to Blacklist           \033[96m│\033[0m")
    print("\033[96m│\033[0m  \033[93m[2]\033[0m Add to Whitelist           \033[96m│\033[0m")
    print("\033[96m│\033[0m  \033[93m[3]\033[0m View Blacklist             \033[96m│\033[0m")
    print("\033[96m│\033[0m  \033[93m[4]\033[0m View Whitelist             \033[96m│\033[0m")
    print("\033[96m│\033[0m  \033[93m[5]\033[0m Remove from Blacklist      \033[96m│\033[0m")
    print("\033[96m│\033[0m  \033[93m[6]\033[0m Remove from Whitelist      \033[96m│\033[0m")
    print("\033[96m│\033[0m  \033[93m[0]\033[0m Back to Main Menu          \033[96m│\033[0m")
    print("\033[96m└─────────────────────────────────┘\033[0m")

    choice = input("\n\033[96m[?] Choose option: \033[0m").strip()

    if choice == "1":
        url = input("  Enter URL/domain to blacklist: ").strip()
        mgr.add_to_blacklist(url)
        print(f"\033[92m[✓] Added '{url}' to blacklist.\033[0m")
    elif choice == "2":
        url = input("  Enter URL/domain to whitelist: ").strip()
        mgr.add_to_whitelist(url)
        print(f"\033[92m[✓] Added '{url}' to whitelist.\033[0m")
    elif choice == "3":
        items = mgr.get_blacklist()
        print(f"\n\033[91m[BLACKLIST] ({len(items)} entries):\033[0m")
        for item in items:
            print(f"  - {item}")
    elif choice == "4":
        items = mgr.get_whitelist()
        print(f"\n\033[92m[WHITELIST] ({len(items)} entries):\033[0m")
        for item in items:
            print(f"  - {item}")
    elif choice == "5":
        url = input("  Enter URL/domain to remove from blacklist: ").strip()
        mgr.remove_from_blacklist(url)
        print(f"\033[92m[✓] Removed '{url}' from blacklist.\033[0m")
    elif choice == "6":
        url = input("  Enter URL/domain to remove from whitelist: ").strip()
        mgr.remove_from_whitelist(url)
        print(f"\033[92m[✓] Removed '{url}' from whitelist.\033[0m")


def show_sample_urls():
    """Display sample test URLs for demonstration."""
    print("\n\033[93m[SAMPLE TEST URLS]\033[0m")
    print("\033[90m" + "─" * 60 + "\033[0m")

    samples = [
        ("https://google.com", "SAFE - Legitimate trusted site"),
        ("https://github.com", "SAFE - Well-known dev platform"),
        ("http://paypa1-secure-login.com", "HIGH RISK - Typosquatting + no HTTPS"),
        ("http://secure-login-update.amazon-verify.xyz", "HIGH RISK - Keyword stuffing"),
        ("https://g00gle.com/login/verify", "HIGH RISK - Homograph attack"),
        ("http://192.168.1.1/bank/login", "MEDIUM - Raw IP with login path"),
        ("https://netflix-account-update.info", "HIGH RISK - Brand impersonation"),
        ("http://bit.ly/freeiphone2024", "MEDIUM - URL shortener (unknown dest)"),
        ("https://microsoft.com.login.evil.ru", "HIGH RISK - Fake subdomain"),
        ("https://stackoverflow.com", "SAFE - Trusted developer resource"),
    ]

    for url, label in samples:
        if "SAFE" in label:
            color = "\033[92m"
        elif "HIGH" in label:
            color = "\033[91m"
        else:
            color = "\033[93m"
        print(f"  {color}[{label}]\033[0m")
        print(f"    → {url}")
        print()

    print("\033[90mTip: Copy any URL above and use option [1] to analyze it.\033[0m")


def show_about():
    """Display information about the tool."""
    about = """
\033[96m╔══════════════════════════════════════════════════════════════╗\033[0m
\033[96m║                    ABOUT THIS TOOL                          ║\033[0m
\033[96m╚══════════════════════════════════════════════════════════════╝\033[0m

\033[92m  Name    :\033[0m  Phishing Detection Tool
\033[92m  Version :\033[0m  1.0.0
\033[92m  Author  :\033[0m  Monish Paramasivam
\033[92m  Purpose :\033[0m  Educational Cybersecurity Portfolio Project

\033[93m  DISCLAIMER:\033[0m
  This tool is built strictly for ethical hacking education
  and cybersecurity awareness. It must NOT be used to conduct
  any unauthorized or illegal activities.

\033[96m  HOW IT WORKS:\033[0m
  1. URL Structure Analysis  - Detects typosquatting, suspicious
                               patterns, keyword stuffing
  2. SSL/HTTPS Check         - Validates encryption and cert validity
  3. WHOIS Lookup            - Checks domain age and registrant info
  4. Blacklist/Whitelist     - Custom list management
  5. ML Classifier           - Machine learning-based URL classification

\033[96m  TECH STACK:\033[0m
  - Python 3.8+
  - scikit-learn (ML classifier)
  - python-whois (domain info)
  - requests (HTTP checks)
  - colorama (colored terminal output)

\033[90m  "Security is not a product, but a process." – Bruce Schneier\033[0m
"""
    print(about)


def main():
    """Main program loop."""
    print_banner()

    while True:
        print_menu()
        choice = input("\n\033[96m[?] Select option: \033[0m").strip()

        if choice == "1":
            analyze_url_flow()
        elif choice == "2":
            batch_analyze()
        elif choice == "3":
            manage_lists()
        elif choice == "4":
            show_sample_urls()
        elif choice == "5":
            show_about()
        elif choice == "0":
            print("\n\033[92m[✓] Thank you for using Phishing Detection Tool.")
            print("    Made by Monish Paramasivam | Stay Ethical! 🛡️\033[0m\n")
            sys.exit(0)
        else:
            print("\033[91m[!] Invalid option. Please choose 0-5.\033[0m")


if __name__ == "__main__":
    main()

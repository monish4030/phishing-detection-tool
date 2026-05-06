# 🛡️ Phishing Detection Tool

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Purpose](https://img.shields.io/badge/Purpose-Educational-orange?style=for-the-badge)
![ML](https://img.shields.io/badge/ML-Random%20Forest-purple?style=for-the-badge&logo=scikit-learn)

**A comprehensive, CLI-based URL phishing analyzer built for cybersecurity education.**

*Made by [Monish Paramasivam](https://github.com/monishparamasivam)*

</div>

---

## 📌 Overview

The **Phishing Detection Tool** is a Python-based command-line application designed to analyze URLs for phishing indicators using multiple detection techniques — including URL structure analysis, SSL validation, WHOIS domain intelligence, blacklist matching, and a machine learning classifier.

> ⚠️ **Disclaimer**: This tool is built strictly for **educational and ethical use only**. It is a cybersecurity portfolio project intended to demonstrate phishing detection concepts. Do NOT use it for any unauthorized or illegal activities.

---

## 🚀 Features

### Core Detection
| Feature | Description |
|---|---|
| 🔍 **URL Structure Analysis** | Detects typosquatting, homograph attacks, keyword stuffing, suspicious TLDs, IP addresses, @-symbol abuse, and more |
| 🔒 **SSL / HTTPS Validation** | Checks for HTTPS, validates certificate, detects self-signed or expired certs |
| 🌐 **WHOIS Domain Intelligence** | Retrieves domain age, registrar, registrant info — newly registered domains raise red flags |
| 📋 **Blacklist / Whitelist** | Custom lists for known phishing domains and trusted sites, persisted as JSON |
| 🤖 **ML Classifier** | Random Forest model trained on 15 URL features to predict phishing probability |
| 📊 **Risk Scoring** | Aggregated 0–100 risk score with Low / Medium / High classification |
| 💾 **Report Saving** | Save full analysis reports to timestamped `.txt` files |

### Advanced Features
- **Batch URL analysis** — analyze multiple URLs in one session
- **Probability bar** — visual indicator of phishing likelihood
- **Feature breakdown** — see which ML features contributed most
- **Color-coded terminal UI** — intuitive, severity-highlighted output
- **Persistent custom lists** — blacklist/whitelist saved between sessions

---

## 📁 Project Structure

```
phishing-detection-tool/
│
├── main.py                    # CLI entry point, menu system
│
├── core/                      # Core analysis modules
│   ├── __init__.py
│   ├── analyzer.py            # URL structure analysis (12+ checks)
│   ├── ssl_checker.py         # SSL/HTTPS certificate validation
│   ├── whois_lookup.py        # WHOIS / domain age lookup
│   └── blacklist.py           # Blacklist & whitelist management
│
├── ml/                        # Machine learning module
│   ├── __init__.py
│   ├── classifier.py          # Random Forest phishing classifier
│   ├── phishing_model.pkl     # Saved trained model (auto-generated)
│   └── scaler.pkl             # Feature scaler (auto-generated)
│
├── utils/                     # Utility modules
│   ├── __init__.py
│   ├── display.py             # Colored terminal report renderer
│   └── report.py              # Report file generator
│
├── data/                      # Persistent data
│   ├── blacklist.json         # Custom blacklist (auto-created)
│   └── whitelist.json         # Custom whitelist (auto-created)
│
├── tests/                     # Unit tests
│   ├── __init__.py
│   └── test_analyzer.py       # Test suite (pytest-compatible)
│
├── reports/                   # Saved analysis reports (auto-created)
│
├── sample_urls.txt            # Test URLs for demonstration
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

---

## ⚙️ Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/monishparamasivam/phishing-detection-tool.git
cd phishing-detection-tool

# 2. (Recommended) Create a virtual environment
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the tool
python main.py
```

---

## 🖥️ Usage

### Starting the Tool
```bash
python main.py
```

### Main Menu Options

```
┌─────────────────────────────────────────┐
│           MAIN MENU                     │
├─────────────────────────────────────────┤
│  [1] Analyze a Single URL               │
│  [2] Analyze Multiple URLs (Batch)      │
│  [3] Manage Blacklist / Whitelist       │
│  [4] View Sample Test URLs              │
│  [5] About This Tool                    │
│  [0] Exit                               │
└─────────────────────────────────────────┘
```

### Single URL Analysis Example

```
[?] Enter URL to analyze: http://paypa1-secure-login.com/verify

[1/5] Analyzing URL structure...
[2/5] Checking SSL/HTTPS...
[3/5] Fetching domain information...
[4/5] Checking blacklist/whitelist...
[5/5] Running ML classifier...

═══════════════════════════════════════════════════════════════════
  PHISHING ANALYSIS REPORT
═══════════════════════════════════════════════════════════════════

[TARGET URL]
  http://paypa1-secure-login.com/verify

████████████████████████████████████████████████████████████████
█                                                              █
█    🚨  RISK LEVEL: HIGH  |  SCORE: 87/100                   █
█                                                              █
████████████████████████████████████████████████████████████████

[SCORE BREAKDOWN]
  • URL structure issues: +35 pts
  • No HTTPS: +15 pts
  • ML classifier risk: +22 pts
  • Domain is only 12 days old: +10 pts
  ...
```

### Run Unit Tests
```bash
# Using pytest
pytest tests/ -v

# Or directly
python tests/test_analyzer.py
```

---

## 🔬 How It Works

### Detection Pipeline

```
URL Input
    │
    ├──▶ [1] URL Analyzer      — 12+ structural checks
    │         • Length, IP, subdomains, keywords, homographs,
    │           special chars, TLD, brand impersonation...
    │
    ├──▶ [2] SSL Checker       — HTTPS & certificate validation
    │         • Protocol check, cert validity, expiry, issuer,
    │           self-signed detection...
    │
    ├──▶ [3] WHOIS Lookup      — Domain intelligence
    │         • Registration date, domain age, registrar,
    │           privacy protection...
    │
    ├──▶ [4] Blacklist Check   — List-based matching
    │         • Custom blacklist, custom whitelist,
    │           domain normalization...
    │
    ├──▶ [5] ML Classifier     — Random Forest prediction
    │         • 15 engineered features, probability score,
    │           confidence level...
    │
    └──▶ Final Aggregation → Risk Score (0-100) → LOW / MEDIUM / HIGH
```

### Risk Score Calculation

| Score Range | Risk Level | Action |
|---|---|---|
| 0 – 30 | ✅ LOW | Generally safe |
| 31 – 65 | ⚠️ MEDIUM | Exercise caution |
| 66 – 100 | 🚨 HIGH | Likely phishing |

### ML Features Used
The classifier uses 15 engineered features:
1. URL total length
2. IP address in URL
3. Subdomain depth count
4. Suspicious keyword count
5. HTTPS presence
6. @ symbol presence
7. Hyphen count in domain
8. Dot count in domain
9. URL shortener presence
10. Suspicious TLD usage
11. Digit count in domain
12. URL path depth
13. Brand name spoofing indicator
14. Special character count
15. Domain Shannon entropy

---

## 📦 Dependencies

| Package | Purpose |
|---|---|
| `requests` | HTTP connection for SSL checks |
| `python-whois` | WHOIS domain data retrieval |
| `scikit-learn` | Random Forest ML classifier |
| `numpy` | Numerical feature processing |
| `joblib` | Model serialization |
| `colorama` | Cross-platform colored CLI output |
| `pytest` | Unit test framework |

---

## 🧪 Sample Test URLs

| URL | Expected Result |
|---|---|
| `https://google.com` | ✅ LOW risk |
| `https://github.com` | ✅ LOW risk |
| `http://paypa1-secure-login.com` | 🚨 HIGH risk |
| `http://192.168.1.1/bank/login` | 🚨 HIGH risk |
| `https://microsoft.com.login.evil.ru` | 🚨 HIGH risk |
| `http://bit.ly/free-offer` | ⚠️ MEDIUM risk |

See [`sample_urls.txt`](sample_urls.txt) for the full test list.

---

## 🔐 Ethical Use Statement

This tool was developed for:
- Learning phishing detection techniques
- Cybersecurity portfolio demonstration
- Understanding URL analysis and threat intelligence
- Educational research into social engineering defenses

**This tool must NOT be used to:**
- Target real individuals or organizations
- Conduct unauthorized security testing
- Facilitate any form of cybercrime

---

## 🤝 Contributing

Contributions are welcome for educational improvements:

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/add-virustotal-api`)
3. Commit changes (`git commit -m 'Add VirusTotal API integration'`)
4. Push to branch (`git push origin feature/add-virustotal-api`)
5. Open a Pull Request

### Ideas for Extension
- [ ] VirusTotal API integration
- [ ] Google Safe Browsing API check
- [ ] Web scraping for page content analysis
- [ ] Browser extension version
- [ ] REST API wrapper (Flask/FastAPI)
- [ ] GUI interface (Tkinter or PyQt)
- [ ] Train on larger datasets (PhishTank, UCI)

---

## 📄 License

![License](https://img.shields.io/badge/License-CC%20BY--ND%204.0-red?style=for-the-badge)

---

## 👨‍💻 Author

**Monish Paramasivam**
- Cybersecurity Enthusiast & Python Developer
- Portfolio Project — Phishing Detection Tool v1.0

---

<div align="center">

*"Security is not a product, but a process." — Bruce Schneier*

**⭐ Star this repo if it helped your learning journey!**

</div>

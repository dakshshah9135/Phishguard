# 🎣 PhishGuard — Phishing Detection Engine

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Security](https://img.shields.io/badge/Domain-Cybersecurity-red)
![Checks](https://img.shields.io/badge/Checks-19%2B-orange)

A Python-based phishing detection engine that analyzes URLs and emails using **19+ heuristic checks** to detect phishing attempts — no external API required. Generates professional HTML threat reports with risk scores and remediation guidance.

> ⚠️ **For educational and authorized security testing only.**

---

## 📸 Features

- 🔍 **URL Analysis** — 12 independent checks: IP addresses, suspicious TLDs, brand impersonation, URL shorteners, hex encoding, redirect tricks, and more
- 📧 **Email Analysis** — 7 checks: phishing language detection, urgency analysis, sender domain mismatch, generic greetings, suspicious attachments
- 🎯 **Batch Scanning** — Analyze hundreds of URLs at once from a text file
- 📊 **Risk Scoring** — 0–100 phishing score with 5-level classification (SAFE → CRITICAL)
- 📄 **HTML Reports** — Professional dark-themed reports for URL/email/batch analysis
- 🇮🇳 **India-aware** — Includes Indian brand database (SBI, HDFC, ICICI, Paytm, IRCTC, UPI, Aadhaar)
- ⚡ **No Dependencies** — Pure Python standard library, zero pip installs required

---

## 🚀 Quick Start

```bash
git clone https://github.com/daksh-shah9135/phishguard.git
cd phishguard
```

### Analyze a URL
```bash
python phishguard.py url https://suspicious-site.tk/verify/account
python phishguard.py url https://google.com
```

### Analyze an Email
```bash
python phishguard.py email \
  --subject "URGENT: Verify Your Account Immediately" \
  --sender "noreply@paypal-secure.tk" \
  --body email_body.txt
```

### Batch Scan (Multiple URLs)
```bash
python phishguard.py batch urls.txt
```

---

## 📊 Detection Checks

### URL Checks (12)
| Check | What It Detects |
|-------|----------------|
| IP Address as Host | URLs using raw IPs instead of domain names |
| High-Risk TLD | .tk, .ml, .xyz, .top, .click and 25 more |
| Brand Impersonation | 'paypal.evil.com' style subdomain spoofing |
| URL Shortener | bit.ly, tinyurl, and 18 other shorteners |
| Excessive Subdomains | 5+ level domain nesting |
| Phishing Keywords | 40+ keywords: login, verify, kyc, otp, confirm |
| HTTP (No Encryption) | Missing HTTPS on credential pages |
| Abnormally Long URL | URLs over 100 characters |
| Suspicious Characters | @ tricks, excessive hyphens, hex encoding |
| Non-Standard Port | Custom ports like :8080, :9090 |
| Double-Slash Redirect | Open redirect tricks |
| Excessive Hex Encoding | Obfuscated domain names |

### Email Checks (7)
| Check | What It Detects |
|-------|----------------|
| Phishing Language | 40+ phrases: "urgent action required", "account suspended" |
| Subject Urgency | Fear/urgency words in subject line |
| No-Reply Sender | Prevents victim from replying to report fraud |
| Sender Domain Mismatch | Claims to be PayPal but comes from evil.com |
| High URL Count | Many links to increase click probability |
| Generic Greeting | "Dear Customer" instead of your real name |
| Suspicious Attachments | .exe, .xlsm, .zip, .vbs, .js mentions |

---

## 🎯 Risk Levels

| Level | Score | Meaning |
|-------|-------|---------|
| 🟢 SAFE | 0–20 | No significant indicators detected |
| 🟡 LOW | 21–40 | Minor indicators — verify before clicking |
| 🟠 MEDIUM | 41–60 | Multiple indicators — do not enter credentials |
| 🔴 HIGH | 61–80 | High-confidence phishing — do not click |
| 🚨 CRITICAL | 81–100 | Near-certain phishing — report immediately |

---

## 📁 Project Structure

```
PhishGuard/
├── phishguard.py            # Main CLI entry point (3 modes: url, email, batch)
├── requirements.txt         # No dependencies — pure stdlib
├── sample_urls.txt          # 10 test URLs (mix of phishing + legitimate)
├── sample_email.txt         # Sample phishing email body for testing
├── README.md
├── core/
│   ├── url_analyzer.py      # 12-check URL heuristic engine
│   ├── email_analyzer.py    # 7-check email analysis + URL extraction
│   ├── reporter.py          # HTML report generator (URL / Email / Batch)
│   └── utils.py             # Terminal colors, progress display
├── config/
│   └── phish_db.json        # Intelligence database (TLDs, keywords, brands)
└── reports/                 # Generated HTML reports saved here
```

---

## 🧪 Sample Output

```
Target URL : http://hdfc-bank-verify-kyc.tk/login?session=abc
Domain     : hdfc-bank-verify-kyc.tk
Risk Score : 59/100
Risk Level : MEDIUM
Verdict    : 🟠 Multiple phishing indicators detected. Do not enter any personal information.

Triggered Checks (3):
  ⚠ High-Risk Top-Level Domain (+20 pts)
  ⚠ Phishing Keywords in URL (+24 pts) — login, verify, kyc
  ⚠ HTTPS Not Used (+15 pts)
```

---

## 🔮 Planned Features

- [ ] VirusTotal API integration for real-time URL reputation
- [ ] WHOIS domain age checking (new domains = higher risk)
- [ ] Chrome extension for real-time URL scanning
- [ ] Email .eml file parsing
- [ ] Machine learning classifier trained on phishing datasets

---

## 👤 Author

**Daksh Shah** — B.Tech Cybersecurity, SAKEC Mumbai

[![LinkedIn](https://img.shields.io/badge/LinkedIn-daksh--shah9135-blue?logo=linkedin)](https://linkedin.com/in/daksh-shah9135)

---

## ⚖️ License

MIT License — For educational and authorized security testing only.

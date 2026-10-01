"""
PhishGuard | core/url_analyzer.py
Deep URL heuristic analysis engine.
Checks 15+ indicators to detect phishing URLs without any external API.
"""

import re
import json
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


_DB_PATH = Path(__file__).parent.parent / "config" / "phish_db.json"
with open(_DB_PATH) as f:
    DB = json.load(f)


# ── Result container ──────────────────────────────────────────────────────────

@dataclass
class URLFinding:
    check_name:      str
    triggered:       bool
    detail:          str
    risk_points:     int
    recommendation:  str


@dataclass
class URLAnalysisResult:
    url:             str
    total_score:     int
    risk_level:      str
    findings:        list[URLFinding] = field(default_factory=list)
    is_trusted:      bool = False
    parsed_domain:   str = ""
    final_verdict:   str = ""

    @property
    def triggered_findings(self):
        return [f for f in self.findings if f.triggered]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_domain(url: str) -> tuple[str, str, str]:
    """Returns (scheme, full_host, registered_domain)."""
    try:
        if not url.startswith(("http://", "https://", "ftp://")):
            url = "http://" + url
        parsed  = urllib.parse.urlparse(url)
        host    = parsed.hostname or ""
        scheme  = parsed.scheme or ""
        # Registered domain = last two parts (e.g. "evil.com" from "login.evil.com")
        parts   = host.split(".")
        reg_dom = ".".join(parts[-2:]) if len(parts) >= 2 else host
        return scheme, host, reg_dom
    except Exception:
        return "", url, url


def _score_to_level(score: int) -> str:
    for level, (lo, hi) in DB["risk_levels"].items():
        if lo <= score <= hi:
            return level
    return "CRITICAL"


# ── Individual checks ─────────────────────────────────────────────────────────

def _check_ip_address(url: str) -> URLFinding:
    ip_pattern = re.compile(
        r"https?://(\d{1,3}\.){3}\d{1,3}"
    )
    triggered = bool(ip_pattern.search(url))
    return URLFinding(
        check_name="IP Address Used as Host",
        triggered=triggered,
        detail="URL uses a raw IP address instead of a domain name — common phishing technique to avoid brand checks.",
        risk_points=DB["risk_weights"]["is_ip_address"],
        recommendation="Legitimate services never use raw IP addresses in user-facing URLs. Avoid."
    )


def _check_suspicious_tld(host: str) -> URLFinding:
    triggered = any(host.endswith(tld) for tld in DB["suspicious_tlds"])
    matched   = next((tld for tld in DB["suspicious_tlds"] if host.endswith(tld)), "")
    return URLFinding(
        check_name="High-Risk Top-Level Domain",
        triggered=triggered,
        detail=f"Domain uses '{matched}' TLD — a free or low-cost domain extension frequently abused by phishers." if triggered else "TLD appears normal.",
        risk_points=DB["risk_weights"]["suspicious_tld"],
        recommendation="Verify the legitimacy of the website before interacting. Free TLDs are heavily abused."
    )


def _check_brand_impersonation(host: str, url: str) -> URLFinding:
    url_lower  = url.lower()
    host_lower = host.lower()
    for brand in DB["legitimate_brands"]:
        # Brand in subdomain but not as the registered domain
        if brand in host_lower:
            parts    = host_lower.split(".")
            reg_dom  = ".".join(parts[-2:]) if len(parts) >= 2 else host_lower
            # If brand appears in subdomain/path but real domain is different
            if brand not in reg_dom and brand in ".".join(parts[:-2]):
                return URLFinding(
                    check_name="Brand Name in Subdomain (Impersonation)",
                    triggered=True,
                    detail=f"'{brand}' appears in the subdomain but the actual registered domain is '{reg_dom}'. Classic impersonation pattern.",
                    risk_points=DB["risk_weights"]["brand_impersonation"],
                    recommendation=f"The real {brand} website would be at {brand}.com or {brand}.in — not as a subdomain of another domain."
                )
    return URLFinding(
        check_name="Brand Name in Subdomain (Impersonation)",
        triggered=False,
        detail="No brand impersonation pattern detected in subdomains.",
        risk_points=DB["risk_weights"]["brand_impersonation"],
        recommendation=""
    )


def _check_url_shortener(host: str) -> URLFinding:
    triggered = any(s in host for s in DB["url_shorteners"])
    matched   = next((s for s in DB["url_shorteners"] if s in host), "")
    return URLFinding(
        check_name="URL Shortener Detected",
        triggered=triggered,
        detail=f"URL uses shortener '{matched}' — hides the real destination." if triggered else "No URL shortener detected.",
        risk_points=DB["risk_weights"]["url_shortener"],
        recommendation="Expand the URL using a service like checkshorturl.com before clicking."
    )


def _check_excessive_subdomains(host: str) -> URLFinding:
    parts     = host.split(".")
    count     = len(parts)
    triggered = count > 4
    return URLFinding(
        check_name="Excessive Subdomains",
        triggered=triggered,
        detail=f"Domain has {count} levels: '{host}'. Legitimate sites rarely need more than 3 levels." if triggered else f"Domain depth ({count} levels) is normal.",
        risk_points=DB["risk_weights"]["excessive_subdomains"],
        recommendation="Deeply nested subdomains are used to confuse users into thinking they're on a trusted site."
    )


def _check_phishing_keywords(url: str) -> URLFinding:
    url_lower = url.lower()
    matched   = [kw for kw in DB["phishing_keywords_url"] if kw in url_lower]
    triggered = len(matched) >= 2
    return URLFinding(
        check_name="Phishing Keywords in URL",
        triggered=triggered,
        detail=f"URL contains {len(matched)} phishing-associated keyword(s): {', '.join(matched[:5])}." if triggered else f"Found {len(matched)} keyword(s) — below threshold.",
        risk_points=DB["risk_weights"]["phishing_keyword_url"] * min(len(matched), 4),
        recommendation="URLs with multiple security/urgency keywords are engineered to create panic and prompt clicks."
    )


def _check_https(scheme: str) -> URLFinding:
    triggered = scheme != "https"
    return URLFinding(
        check_name="HTTPS Not Used",
        triggered=triggered,
        detail="URL uses HTTP — connection is unencrypted. Credentials submitted here can be intercepted." if triggered else "HTTPS is in use — connection is encrypted.",
        risk_points=DB["risk_weights"]["https_missing"],
        recommendation="Never enter passwords or personal data on HTTP (non-padlock) websites."
    )


def _check_long_url(url: str) -> URLFinding:
    length    = len(url)
    triggered = length > 100
    return URLFinding(
        check_name="Abnormally Long URL",
        triggered=triggered,
        detail=f"URL is {length} characters long. Phishing URLs are often deliberately long to obscure the real destination." if triggered else f"URL length ({length} chars) is normal.",
        risk_points=DB["risk_weights"]["long_url"],
        recommendation="Be suspicious of very long URLs with many parameters — they are designed to confuse you."
    )


def _check_special_chars(url: str) -> URLFinding:
    # @ symbol in URL, or %20, or multiple dashes
    triggers = []
    if "@" in url:
        triggers.append("'@' symbol — everything before @ is ignored by browsers, used to confuse users")
    if url.count("-") > 4:
        triggers.append(f"excessive hyphens ({url.count('-')}) — often used in fake domains")
    if re.search(r"%[0-9a-fA-F]{2}", url):
        triggers.append("URL-encoded characters — used to hide domain name from quick inspection")
    triggered = len(triggers) > 0
    return URLFinding(
        check_name="Suspicious Characters in URL",
        triggered=triggered,
        detail=" | ".join(triggers) if triggered else "No suspicious character patterns found.",
        risk_points=DB["risk_weights"]["special_chars_url"] if triggered else 0,
        recommendation="The '@' trick in URLs is specifically used to make a malicious URL look like it goes to a trusted site."
    )


def _check_port_in_url(url: str) -> URLFinding:
    port_pattern = re.compile(r"https?://[^/]+:(\d{2,5})")
    match        = port_pattern.search(url)
    triggered    = match is not None and match.group(1) not in ("80", "443")
    return URLFinding(
        check_name="Non-Standard Port in URL",
        triggered=triggered,
        detail=f"URL specifies port :{match.group(1)} — legitimate websites do not expose custom ports to end users." if triggered else "No non-standard port detected.",
        risk_points=DB["risk_weights"]["port_in_url"],
        recommendation="Custom port numbers in user-facing URLs indicate a non-production or malicious server."
    )


def _check_double_slash_redirect(url: str) -> URLFinding:
    # e.g. http://legit.com//evil.com
    triggered = bool(re.search(r"https?://[^/]+//.+", url))
    return URLFinding(
        check_name="Double-Slash Redirect Trick",
        triggered=triggered,
        detail="URL contains '//' after the path start — may be used for open redirect attacks.",
        risk_points=DB["risk_weights"]["double_slash_redirect"],
        recommendation="This pattern can redirect browsers to a completely different domain after appearing to start legitimately."
    )


def _check_hex_encoding(url: str) -> URLFinding:
    hex_count = len(re.findall(r"%[0-9a-fA-F]{2}", url))
    triggered = hex_count > 5
    return URLFinding(
        check_name="Excessive Hex Encoding",
        triggered=triggered,
        detail=f"URL contains {hex_count} hex-encoded characters — often used to bypass keyword filters and confuse users.",
        risk_points=DB["risk_weights"]["hex_encoded_url"],
        recommendation="Attackers encode URLs to hide phishing keywords from automated scanners and human eyes."
    )


def _check_trusted_domain(host: str, reg_dom: str) -> bool:
    return reg_dom in DB["trusted_domains"] or host in DB["trusted_domains"]


# ── Main URL analyzer ─────────────────────────────────────────────────────────

def analyze_url(url: str) -> URLAnalysisResult:
    url         = url.strip()
    scheme, host, reg_dom = _extract_domain(url)

    result = URLAnalysisResult(
        url=url,
        total_score=0,
        risk_level="SAFE",
        parsed_domain=host
    )

    # Trusted domain shortcut
    if _check_trusted_domain(host, reg_dom):
        result.is_trusted   = True
        result.risk_level   = "SAFE"
        result.final_verdict = f"✅ '{reg_dom}' is a known legitimate domain. Still verify you're on the correct exact domain."
        return result

    # Run all checks
    checks = [
        _check_ip_address(url),
        _check_suspicious_tld(host),
        _check_brand_impersonation(host, url),
        _check_url_shortener(host),
        _check_excessive_subdomains(host),
        _check_phishing_keywords(url),
        _check_https(scheme),
        _check_long_url(url),
        _check_special_chars(url),
        _check_port_in_url(url),
        _check_double_slash_redirect(url),
        _check_hex_encoding(url),
    ]

    total = 0
    for check in checks:
        if check.triggered:
            total += check.risk_points
        result.findings.append(check)

    result.total_score = min(total, 100)
    result.risk_level  = _score_to_level(result.total_score)

    verdicts = {
        "SAFE":     "✅ No significant phishing indicators detected. Exercise standard caution.",
        "LOW":      "🟡 Minor indicators found. Verify this URL before entering any credentials.",
        "MEDIUM":   "🟠 Multiple phishing indicators detected. Do not enter any personal information.",
        "HIGH":     "🔴 High-confidence phishing URL. This link is very likely malicious. Do not click.",
        "CRITICAL": "🚨 CRITICAL: Extremely high phishing confidence. This URL should be reported and blocked."
    }
    result.final_verdict = verdicts.get(result.risk_level, "Unknown")
    return result

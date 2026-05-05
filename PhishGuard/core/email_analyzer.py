"""
PhishGuard | core/email_analyzer.py
Email phishing analysis — parses raw email text/headers and scores
for phishing indicators without requiring any external service.
"""

import re
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from core.url_analyzer import analyze_url, URLAnalysisResult

_DB_PATH = Path(__file__).parent.parent / "config" / "phish_db.json"
with open(_DB_PATH) as f:
    DB = json.load(f)


# ── Result containers ─────────────────────────────────────────────────────────

@dataclass
class EmailFinding:
    check_name:     str
    triggered:      bool
    detail:         str
    risk_points:    int
    recommendation: str


@dataclass
class EmailAnalysisResult:
    subject:          str
    sender:           str
    total_score:      int
    risk_level:       str
    findings:         list[EmailFinding]        = field(default_factory=list)
    url_results:      list[URLAnalysisResult]   = field(default_factory=list)
    extracted_urls:   list[str]                 = field(default_factory=list)
    final_verdict:    str                       = ""

    @property
    def triggered_findings(self):
        return [f for f in self.findings if f.triggered]


# ── URL extraction ─────────────────────────────────────────────────────────────

def _extract_urls(text: str) -> list[str]:
    pattern = re.compile(
        r"https?://[^\s<>\"']{4,}"
        r"|www\.[^\s<>\"']{4,}"
    )
    return list(set(pattern.findall(text)))


# ── Email checks ──────────────────────────────────────────────────────────────

def _check_phishing_keywords_body(body: str) -> EmailFinding:
    body_lower = body.lower()
    matched    = [kw for kw in DB["phishing_keywords_email"] if kw in body_lower]
    triggered  = len(matched) >= 2
    return EmailFinding(
        check_name="Phishing Language in Email Body",
        triggered=triggered,
        detail=f"Body contains {len(matched)} phishing phrase(s): {'; '.join(matched[:4])}{'...' if len(matched)>4 else ''}." if triggered else f"Only {len(matched)} phishing phrase(s) found — below alert threshold.",
        risk_points=DB["risk_weights"]["email_phishing_keyword"] * min(len(matched), 6),
        recommendation="Urgency and fear language ('your account will be suspended', 'act now') are the primary tools of phishing. Slow down and verify through official channels."
    )


def _check_subject_urgency(subject: str) -> EmailFinding:
    urgency_words = [
        "urgent", "immediate", "action required", "important", "alert",
        "warning", "suspended", "locked", "verify", "confirm", "critical",
        "final notice", "last chance", "expires", "limited time", "act now",
        "security notice", "unusual activity", "password", "compromised"
    ]
    subject_lower = subject.lower()
    matched       = [w for w in urgency_words if w in subject_lower]
    triggered     = len(matched) >= 1
    return EmailFinding(
        check_name="Urgency/Fear Language in Subject Line",
        triggered=triggered,
        detail=f"Subject triggers urgency with: {', '.join(matched)}." if triggered else "Subject line does not contain high-urgency language.",
        risk_points=DB["risk_weights"]["urgency_language"] * len(matched),
        recommendation="Phishing emails are deliberately designed to trigger panic responses. Real companies give you time to act."
    )


def _check_no_reply_sender(sender: str) -> EmailFinding:
    suspicious = ["noreply@", "no-reply@", "donotreply@", "notification@", "mailer@", "auto@"]
    triggered  = any(s in sender.lower() for s in suspicious)
    return EmailFinding(
        check_name="No-Reply Sender Address",
        triggered=triggered,
        detail=f"Sender '{sender}' uses a no-reply address — prevents you from replying to report fraud.",
        risk_points=DB["risk_weights"]["no_reply_sender"],
        recommendation="While some legitimate emails use no-reply addresses, combined with other indicators it's a red flag."
    )


def _check_sender_domain_mismatch(sender: str, body: str) -> EmailFinding:
    sender_domain = ""
    match = re.search(r"@([\w\.-]+)", sender)
    if match:
        sender_domain = match.group(1).lower()

    brand_in_body = None
    body_lower    = body.lower()
    for brand in DB["legitimate_brands"]:
        if brand in body_lower:
            brand_in_body = brand
            break

    if brand_in_body and sender_domain:
        # Check if brand is mentioned in body but sender domain doesn't match
        if brand_in_body not in sender_domain:
            return EmailFinding(
                check_name="Sender Domain Mismatch",
                triggered=True,
                detail=f"Email claims to be from '{brand_in_body}' but sender domain is '{sender_domain}'. Classic impersonation.",
                risk_points=DB["risk_weights"]["sender_domain_mismatch"],
                recommendation=f"Real emails from {brand_in_body} come from @{brand_in_body}.com or their official domain — not '{sender_domain}'."
            )

    return EmailFinding(
        check_name="Sender Domain Mismatch",
        triggered=False,
        detail="No brand/sender domain mismatch detected.",
        risk_points=0,
        recommendation=""
    )


def _check_url_count(urls: list[str]) -> EmailFinding:
    count     = len(urls)
    triggered = count > 5
    return EmailFinding(
        check_name="High Number of URLs",
        triggered=triggered,
        detail=f"Email contains {count} URLs — high URL count is used to overwhelm recipients and increase click probability.",
        risk_points=DB["risk_weights"]["url_count_high"] * min(count - 5, 5) if triggered else 0,
        recommendation="Be selective about which links you click. Check each URL before interacting."
    )


def _check_generic_greeting(body: str) -> EmailFinding:
    generic   = ["dear customer", "dear user", "dear account holder", "dear member",
                 "dear client", "hello customer", "valued customer", "dear sir", "dear madam"]
    body_low  = body.lower()
    matched   = [g for g in generic if g in body_low]
    triggered = len(matched) > 0
    return EmailFinding(
        check_name="Generic / Impersonal Greeting",
        triggered=triggered,
        detail=f"Email uses generic greeting: '{matched[0]}' — legitimate companies address you by name." if triggered else "Email appears to use a personalized greeting.",
        risk_points=8,
        recommendation="Your bank, PayPal, Netflix etc. know your name and always use it. Generic greetings are a phishing signal."
    )


def _check_suspicious_attachments(body: str) -> EmailFinding:
    suspicious_exts = [".exe", ".zip", ".rar", ".js", ".vbs", ".bat", ".cmd",
                       ".ps1", ".macro", ".xlsm", ".docm", ".jar", ".apk"]
    body_lower      = body.lower()
    matched         = [e for e in suspicious_exts if e in body_lower]
    triggered       = len(matched) > 0
    return EmailFinding(
        check_name="Suspicious Attachment Type Mentioned",
        triggered=triggered,
        detail=f"Email mentions potentially dangerous file type(s): {', '.join(matched)}." if triggered else "No dangerous attachment types detected in email text.",
        risk_points=DB["risk_weights"]["attachment_suspicious"] if triggered else 0,
        recommendation="Never open .exe, .zip, .js, .vbs, or macro-enabled Office files from unexpected emails. This is the #1 malware delivery vector."
    )


# ── Score → Level ─────────────────────────────────────────────────────────────

def _score_to_level(score: int) -> str:
    for level, (lo, hi) in DB["risk_levels"].items():
        if lo <= score <= hi:
            return level
    return "CRITICAL"


# ── Main email analyzer ───────────────────────────────────────────────────────

def analyze_email(subject: str, sender: str, body: str) -> EmailAnalysisResult:
    result = EmailAnalysisResult(
        subject=subject,
        sender=sender,
        total_score=0,
        risk_level="SAFE"
    )

    # Extract and analyze all URLs from the body
    urls = _extract_urls(body)
    result.extracted_urls = urls
    url_score_bonus = 0
    for url in urls[:10]:   # analyze up to 10 URLs per email
        url_result = analyze_url(url)
        result.url_results.append(url_result)
        if url_result.risk_level in ("HIGH", "CRITICAL"):
            url_score_bonus += 25
        elif url_result.risk_level == "MEDIUM":
            url_score_bonus += 12
        elif url_result.risk_level == "LOW":
            url_score_bonus += 5

    # Run email-level checks
    checks = [
        _check_phishing_keywords_body(body),
        _check_subject_urgency(subject),
        _check_no_reply_sender(sender),
        _check_sender_domain_mismatch(sender, body),
        _check_url_count(urls),
        _check_generic_greeting(body),
        _check_suspicious_attachments(body),
    ]

    total = url_score_bonus
    for check in checks:
        if check.triggered:
            total += check.risk_points
        result.findings.append(check)

    result.total_score = min(total, 100)
    result.risk_level  = _score_to_level(result.total_score)

    verdicts = {
        "SAFE":     "✅ Email appears legitimate. No significant phishing indicators detected.",
        "LOW":      "🟡 Minor phishing signals found. Verify sender before clicking any links.",
        "MEDIUM":   "🟠 Multiple phishing indicators. Do not click links or provide any information.",
        "HIGH":     "🔴 High-confidence phishing email. Delete immediately. Report to your IT team.",
        "CRITICAL": "🚨 CRITICAL: This is almost certainly a phishing attack. Report and block the sender."
    }
    result.final_verdict = verdicts.get(result.risk_level, "Unknown")
    return result

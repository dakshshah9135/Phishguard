#!/usr/bin/env python3
"""
PhishGuard v1.0  —  Phishing Detection Engine
Author : Daksh Shah
GitHub : https://github.com/daksh-shah9135/phishguard

Usage:
  python phishguard.py url   https://suspicious-site.com
  python phishguard.py email --subject "Urgent" --sender "no-reply@fake.com" --body email.txt
  python phishguard.py batch urls.txt
"""

import argparse, sys, os, datetime
from pathlib import Path

from core.url_analyzer    import analyze_url
from core.email_analyzer  import analyze_email
from core.reporter        import generate_url_report, generate_email_report
from core.utils           import (print_banner, print_section,
                                   print_url_result, print_email_result, C)


# ── Argument parser ───────────────────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog="phishguard",
        description="PhishGuard — Phishing URL & Email Detection Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python phishguard.py url https://paypa1-login.tk/secure/verify
  python phishguard.py url https://google.com
  python phishguard.py email --subject "Urgent: Verify Account" --sender "noreply@secure-paypal.xyz" --body body.txt
  python phishguard.py batch sample_urls.txt
        """
    )
    sub = p.add_subparsers(dest="mode", required=True)

    # ── URL mode ──
    url_p = sub.add_parser("url", help="Analyze a single URL")
    url_p.add_argument("target", help="URL to analyze")
    url_p.add_argument("--output", default=None, help="Custom HTML report filename")
    url_p.add_argument("--no-report", action="store_true", help="Skip HTML report")

    # ── Email mode ──
    em_p = sub.add_parser("email", help="Analyze an email for phishing")
    em_p.add_argument("--subject", required=True, help="Email subject line")
    em_p.add_argument("--sender",  required=True, help="Sender email address")
    em_p.add_argument("--body",    required=True, help="Path to a .txt file containing the email body")
    em_p.add_argument("--output",  default=None,  help="Custom HTML report filename")
    em_p.add_argument("--no-report", action="store_true")

    # ── Batch mode ──
    batch_p = sub.add_parser("batch", help="Analyze multiple URLs from a text file (one per line)")
    batch_p.add_argument("file",    help="Text file with one URL per line")
    batch_p.add_argument("--output", default=None)

    return p


# ── Modes ─────────────────────────────────────────────────────────────────────

def run_url(args):
    print_section("URL Analysis")
    result = analyze_url(args.target)
    print_url_result(result)

    if not args.no_report:
        os.makedirs("reports", exist_ok=True)
        if args.output:
            out = args.output
        else:
            ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            safe = args.target.replace("https://","").replace("http://","").replace("/","_")[:30]
            out  = f"reports/phishguard_url_{safe}_{ts}.html"
        generate_url_report(result, out)
        print(f"\n  {C.GREEN}✓ HTML report:{C.RESET} {C.BOLD}{out}{C.RESET}")


def run_email(args):
    print_section("Email Analysis")
    body_path = Path(args.body)
    if not body_path.exists():
        print(f"{C.RED}Error: body file '{args.body}' not found.{C.RESET}")
        sys.exit(1)
    body = body_path.read_text(encoding="utf-8", errors="replace")
    result = analyze_email(args.subject, args.sender, body)
    print_email_result(result)

    if not args.no_report:
        os.makedirs("reports", exist_ok=True)
        out = args.output or f"reports/phishguard_email_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        generate_email_report(result, out)
        print(f"\n  {C.GREEN}✓ HTML report:{C.RESET} {C.BOLD}{out}{C.RESET}")


def run_batch(args):
    print_section(f"Batch URL Analysis — {args.file}")
    urls_file = Path(args.file)
    if not urls_file.exists():
        print(f"{C.RED}Error: file '{args.file}' not found.{C.RESET}")
        sys.exit(1)

    urls    = [u.strip() for u in urls_file.read_text().splitlines() if u.strip() and not u.startswith("#")]
    results = []
    print(f"  Analyzing {len(urls)} URL(s)...\n")

    for i, url in enumerate(urls, 1):
        result = analyze_url(url)
        results.append(result)
        level_c = {"SAFE": C.GREEN, "LOW": C.YELLOW, "MEDIUM": C.ORANGE,
                   "HIGH": C.RED, "CRITICAL": C.PURPLE}.get(result.risk_level, C.WHITE)
        print(f"  [{i:>2}] {level_c}{result.risk_level:8}{C.RESET} {result.total_score:>3}/100  {url[:65]}")

    # Summary
    from collections import Counter
    counts = Counter(r.risk_level for r in results)
    print(f"\n  {C.BOLD}Summary:{C.RESET}")
    for level in ["CRITICAL","HIGH","MEDIUM","LOW","SAFE"]:
        if counts[level]:
            lc = {"SAFE":C.GREEN,"LOW":C.YELLOW,"MEDIUM":C.ORANGE,"HIGH":C.RED,"CRITICAL":C.PURPLE}.get(level,C.WHITE)
            print(f"    {lc}{level:8}{C.RESET} : {counts[level]}")

    # Export combined report
    os.makedirs("reports", exist_ok=True)
    ts  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = args.output or f"reports/phishguard_batch_{ts}.html"

    # Build combined batch HTML
    rows = ""
    for r in results:
        c = {"SAFE":"#16a34a","LOW":"#ca8a04","MEDIUM":"#ea580c","HIGH":"#dc2626","CRITICAL":"#7c3aed"}.get(r.risk_level,"#6b7280")
        badge = f'<span style="background:{c};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;">{r.risk_level}</span>'
        rows += f"""<tr>
          <td style="padding:8px 12px;font-family:monospace;font-size:12px;word-break:break-all;">{r.url}</td>
          <td style="padding:8px 12px;">{r.parsed_domain}</td>
          <td style="padding:8px 12px;text-align:center;">{badge}</td>
          <td style="padding:8px 12px;text-align:center;font-weight:700;color:{c};">{r.total_score}</td>
          <td style="padding:8px 12px;font-size:12px;color:#4b5563;">{r.final_verdict.split(' ',1)[-1][:60]}</td>
        </tr>"""

    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"/><title>PhishGuard Batch Report</title>
    <style>body{{font-family:'Segoe UI',sans-serif;background:#f3f4f6;margin:0;padding:2rem;color:#111827}}
    .wrap{{background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)}}
    .hd{{background:linear-gradient(135deg,#0f172a,#1e3a5f);color:#fff;padding:2rem 2.5rem}}
    .ttl{{font-size:1.4rem;font-weight:800}}table{{width:100%;border-collapse:collapse;font-size:13px}}
    th{{background:#f1f5f9;padding:10px 12px;text-align:left;font-size:11px;text-transform:uppercase;color:#475569;font-weight:600}}
    td{{border-bottom:1px solid #f1f5f9}}tr:hover td{{background:#f8fafc}}
    footer{{text-align:center;padding:1rem;font-size:12px;color:#9ca3af}}</style></head>
    <body><div class="wrap"><div class="hd"><div style="font-size:20px;margin-bottom:4px;">🎣 PhishGuard</div>
    <div class="ttl">Batch URL Analysis Report</div>
    <div style="font-size:13px;color:#94a3b8;margin-top:8px;">{len(urls)} URLs analyzed &nbsp;|&nbsp; {ts}</div></div>
    <div style="padding:1.5rem 2.5rem"><table><thead><tr><th>URL</th><th>Domain</th><th>Risk</th><th>Score</th><th>Verdict</th></tr></thead>
    <tbody>{rows}</tbody></table></div>
    <footer>PhishGuard v1.0 | Built by Daksh Shah | github.com/daksh-shah9135/phishguard</footer></div></body></html>"""

    Path(out).write_text(html, encoding="utf-8")
    print(f"\n  {C.GREEN}✓ Batch report:{C.RESET} {C.BOLD}{out}{C.RESET}")


# ── Entry ─────────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args   = parser.parse_args()
    print_banner()

    if   args.mode == "url":   run_url(args)
    elif args.mode == "email": run_email(args)
    elif args.mode == "batch": run_batch(args)

    print(f"\n{C.GRAY}  PhishGuard complete. For educational and authorized use only.{C.RESET}\n")


if __name__ == "__main__":
    main()

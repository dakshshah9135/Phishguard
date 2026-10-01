"""PhishGuard | core/utils.py — Terminal display helpers."""

import sys, os

USE_COLOR = sys.stdout.isatty() or os.environ.get("FORCE_COLOR")

class C:
    RESET  = "\033[0m"  if USE_COLOR else ""
    BOLD   = "\033[1m"  if USE_COLOR else ""
    RED    = "\033[91m" if USE_COLOR else ""
    ORANGE = "\033[33m" if USE_COLOR else ""
    YELLOW = "\033[93m" if USE_COLOR else ""
    GREEN  = "\033[92m" if USE_COLOR else ""
    BLUE   = "\033[94m" if USE_COLOR else ""
    CYAN   = "\033[96m" if USE_COLOR else ""
    GRAY   = "\033[90m" if USE_COLOR else ""
    PURPLE = "\033[95m" if USE_COLOR else ""
    WHITE  = "\033[97m" if USE_COLOR else ""

RISK_C = {
    "SAFE":     C.GREEN,
    "LOW":      C.YELLOW,
    "MEDIUM":   C.ORANGE,
    "HIGH":     C.RED,
    "CRITICAL": C.PURPLE,
}

def risk_str(level: str) -> str:
    return f"{RISK_C.get(level, C.WHITE)}{C.BOLD}{level:8}{C.RESET}"


def print_banner():
    print(f"""
{C.BLUE}{C.BOLD}
  ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██████╔╝███████║██║███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ██║     ██║  ██║██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
{C.RESET}{C.GRAY}  Phishing Detection Engine  |  URL & Email Analyzer  |  v1.0  |  by Daksh Shah{C.RESET}
{C.GRAY}  For educational and authorized use only.{C.RESET}
""")


def print_section(title: str):
    print(f"\n{C.BOLD}{C.WHITE}{'─'*62}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  {title}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}{'─'*62}{C.RESET}")


def print_url_result(result):
    print(f"\n  {C.BOLD}Target URL :{C.RESET} {C.CYAN}{result.url}{C.RESET}")
    print(f"  {C.BOLD}Domain     :{C.RESET} {result.parsed_domain}")
    print(f"  {C.BOLD}Risk Score :{C.RESET} {RISK_C.get(result.risk_level,C.WHITE)}{C.BOLD}{result.total_score}/100{C.RESET}")
    print(f"  {C.BOLD}Risk Level :{C.RESET} {risk_str(result.risk_level)}")
    print(f"  {C.BOLD}Verdict    :{C.RESET} {result.final_verdict}")

    triggered = result.triggered_findings
    if triggered:
        print(f"\n  {C.BOLD}{C.RED}Triggered Checks ({len(triggered)}):{C.RESET}")
        for f in triggered:
            print(f"    {C.RED}⚠ {f.check_name}{C.RESET} (+{f.risk_points} pts)")
            print(f"      {C.GRAY}{f.detail}{C.RESET}")
            if f.recommendation:
                print(f"      {C.BLUE}→ {f.recommendation}{C.RESET}")
    else:
        print(f"\n  {C.GREEN}No phishing indicators triggered.{C.RESET}")


def print_email_result(result):
    print(f"\n  {C.BOLD}From       :{C.RESET} {C.CYAN}{result.sender}{C.RESET}")
    print(f"  {C.BOLD}Subject    :{C.RESET} {result.subject}")
    print(f"  {C.BOLD}URLs Found :{C.RESET} {len(result.extracted_urls)}")
    print(f"  {C.BOLD}Risk Score :{C.RESET} {RISK_C.get(result.risk_level,C.WHITE)}{C.BOLD}{result.total_score}/100{C.RESET}")
    print(f"  {C.BOLD}Risk Level :{C.RESET} {risk_str(result.risk_level)}")
    print(f"  {C.BOLD}Verdict    :{C.RESET} {result.final_verdict}")

    triggered = result.triggered_findings
    if triggered:
        print(f"\n  {C.BOLD}{C.RED}Triggered Checks ({len(triggered)}):{C.RESET}")
        for f in triggered:
            print(f"    {C.RED}⚠ {f.check_name}{C.RESET} (+{f.risk_points} pts)")
            print(f"      {C.GRAY}{f.detail}{C.RESET}")
            if f.recommendation:
                print(f"      {C.BLUE}→ {f.recommendation}{C.RESET}")

    if result.url_results:
        print(f"\n  {C.BOLD}URLs Analyzed:{C.RESET}")
        for ur in result.url_results:
            print(f"    {risk_str(ur.risk_level)} {C.GRAY}{ur.url[:70]}{'...' if len(ur.url)>70 else ''}{C.RESET}")

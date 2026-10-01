"""
PhishGuard | core/reporter.py
Generates a professional HTML phishing analysis report.
"""

import datetime
from pathlib import Path
from core.url_analyzer  import URLAnalysisResult
from core.email_analyzer import EmailAnalysisResult

RISK_COLORS = {
    "SAFE":     "#16a34a",
    "LOW":      "#ca8a04",
    "MEDIUM":   "#ea580c",
    "HIGH":     "#dc2626",
    "CRITICAL": "#7c3aed",
}

RISK_BG = {
    "SAFE":     "#f0fdf4",
    "LOW":      "#fefce8",
    "MEDIUM":   "#fff7ed",
    "HIGH":     "#fef2f2",
    "CRITICAL": "#f5f3ff",
}

def _badge(risk: str) -> str:
    c = RISK_COLORS.get(risk, "#6b7280")
    return f'<span style="background:{c};color:#fff;padding:3px 10px;border-radius:5px;font-size:12px;font-weight:700;">{risk}</span>'


def _score_ring(score: int, risk: str) -> str:
    color    = RISK_COLORS.get(risk, "#6b7280")
    pct      = score
    dash     = 2 * 3.14159 * 45
    fill     = dash * pct / 100
    empty    = dash - fill
    return f"""
    <svg width="120" height="120" viewBox="0 0 120 120">
      <circle cx="60" cy="60" r="45" fill="none" stroke="#e5e7eb" stroke-width="10"/>
      <circle cx="60" cy="60" r="45" fill="none" stroke="{color}" stroke-width="10"
              stroke-dasharray="{fill:.1f} {empty:.1f}"
              stroke-dashoffset="{dash/4:.1f}"
              stroke-linecap="round"/>
      <text x="60" y="56" text-anchor="middle" font-size="22" font-weight="bold" fill="{color}">{score}</text>
      <text x="60" y="72" text-anchor="middle" font-size="10" fill="#6b7280">/ 100</text>
    </svg>"""


def _findings_table(findings) -> str:
    rows = ""
    for f in findings:
        icon   = "✅" if not f.triggered else "⚠️"
        status = "Passed" if not f.triggered else "Triggered"
        sc     = f.risk_points if f.triggered else 0
        color  = "#dc2626" if f.triggered else "#16a34a"
        rec    = f'<div style="font-size:11px;color:#2563eb;margin-top:4px;">→ {f.recommendation}</div>' if f.triggered and f.recommendation else ""
        rows  += f"""
        <tr>
          <td style="padding:10px 12px;">{icon} {f.check_name}</td>
          <td style="padding:10px 12px;font-size:12px;color:#374151;">{f.detail}{rec}</td>
          <td style="padding:10px 12px;text-align:center;font-weight:700;color:{color};">+{sc}</td>
          <td style="padding:10px 12px;text-align:center;"><span style="color:{color};font-weight:600;">{status}</span></td>
        </tr>"""
    return rows


def generate_url_report(result: URLAnalysisResult, output_path: str) -> str:
    color   = RISK_COLORS.get(result.risk_level, "#6b7280")
    bg      = RISK_BG.get(result.risk_level, "#f9fafb")
    ring    = _score_ring(result.total_score, result.risk_level)
    rows    = _findings_table(result.findings)
    ts      = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    triggered_count = len(result.triggered_findings)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>PhishGuard Report — URL Analysis</title>
<style>
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f3f4f6;margin:0;padding:0;color:#111827}}
  .wrap{{max-width:900px;margin:2rem auto;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)}}
  .header{{background:linear-gradient(135deg,#0f172a,#1e3a5f);color:#fff;padding:2rem 2.5rem}}
  .logo{{display:flex;align-items:center;gap:12px;margin-bottom:1.5rem}}
  .logo-icon{{width:40px;height:40px;background:#3b82f6;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px}}
  .logo-text{{font-size:1.4rem;font-weight:800}}
  .logo-sub{{font-size:11px;color:#94a3b8;letter-spacing:2px;text-transform:uppercase}}
  .verdict-box{{background:rgba(255,255,255,.08);border-radius:12px;padding:1.5rem;display:flex;align-items:center;gap:2rem;flex-wrap:wrap}}
  .url-text{{font-family:monospace;font-size:13px;color:#93c5fd;word-break:break-all;margin-top:.5rem}}
  .meta{{background:#f8fafc;padding:1.5rem 2.5rem;display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem;border-bottom:1px solid #e5e7eb}}
  .mc{{text-align:center}}.ml{{font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px}}.mv{{font-size:1.1rem;font-weight:700;color:#111827}}
  .section{{padding:1.5rem 2.5rem}}
  h2{{font-size:15px;font-weight:700;color:#1e293b;margin-bottom:1rem;text-transform:uppercase;letter-spacing:.5px;padding-bottom:6px;border-bottom:2px solid #e5e7eb}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  th{{background:#f1f5f9;padding:10px 12px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#475569;font-weight:600}}
  tr:nth-child(even){{background:#f8fafc}}
  .verdict{{font-size:1rem;font-weight:600;color:#fff}}
  footer{{text-align:center;padding:1rem;font-size:12px;color:#9ca3af;border-top:1px solid #f1f5f9}}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div class="logo">
      <div class="logo-icon">🎣</div>
      <div><div class="logo-text">PhishGuard</div><div class="logo-sub">Phishing Detection Engine</div></div>
    </div>
    <div class="verdict-box">
      <div>{ring}</div>
      <div style="flex:1">
        <div style="font-size:12px;color:#94a3b8;margin-bottom:6px;">ANALYSIS TARGET</div>
        <div class="url-text">{result.url}</div>
        <div style="margin-top:12px;">{_badge(result.risk_level)}</div>
        <div class="verdict" style="margin-top:8px;">{result.final_verdict}</div>
      </div>
    </div>
  </div>

  <div class="meta">
    <div class="mc"><div class="ml">Risk Score</div><div class="mv" style="color:{color}">{result.total_score}/100</div></div>
    <div class="mc"><div class="ml">Risk Level</div><div class="mv" style="color:{color}">{result.risk_level}</div></div>
    <div class="mc"><div class="ml">Checks Run</div><div class="mv">{len(result.findings)}</div></div>
    <div class="mc"><div class="ml">Triggered</div><div class="mv" style="color:#dc2626">{triggered_count}</div></div>
    <div class="mc"><div class="ml">Domain</div><div class="mv" style="font-size:.9rem">{result.parsed_domain or '—'}</div></div>
    <div class="mc"><div class="ml">Scan Time</div><div class="mv" style="font-size:.85rem">{ts}</div></div>
  </div>

  <div class="section">
    <h2>Detailed Findings</h2>
    <table>
      <thead><tr><th>Check</th><th>Detail</th><th>Points</th><th>Status</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>

  <footer>PhishGuard v1.0 &nbsp;|&nbsp; Built by <strong>Daksh Shah</strong> &nbsp;|&nbsp; github.com/daksh-shah9135/phishguard &nbsp;|&nbsp; For educational and authorized use only.</footer>
</div>
</body></html>"""

    Path(output_path).write_text(html, encoding="utf-8")
    return output_path


def generate_email_report(result: EmailAnalysisResult, output_path: str) -> str:
    color   = RISK_COLORS.get(result.risk_level, "#6b7280")
    ring    = _score_ring(result.total_score, result.risk_level)
    rows    = _findings_table(result.findings)
    ts      = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    triggered_count = len(result.triggered_findings)

    # URL sub-results section
    url_rows = ""
    for ur in result.url_results:
        uc   = RISK_COLORS.get(ur.risk_level, "#6b7280")
        url_rows += f"""<tr>
          <td style="padding:8px 12px;font-family:monospace;font-size:12px;word-break:break-all;color:#1e40af;">{ur.url[:80]}{'...' if len(ur.url)>80 else ''}</td>
          <td style="padding:8px 12px;text-align:center;">{_badge(ur.risk_level)}</td>
          <td style="padding:8px 12px;text-align:center;font-weight:700;color:{uc};">{ur.total_score}</td>
        </tr>"""
    url_section = f"""
    <div class="section">
      <h2>URLs Found in Email ({len(result.url_results)})</h2>
      {'<table><thead><tr><th>URL</th><th>Risk Level</th><th>Score</th></tr></thead><tbody>' + url_rows + '</tbody></table>' if url_rows else '<p style="color:#6b7280;font-size:13px;">No URLs found in email body.</p>'}
    </div>""" if result.url_results else ""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>PhishGuard Report — Email Analysis</title>
<style>
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f3f4f6;margin:0;padding:0;color:#111827}}
  .wrap{{max-width:960px;margin:2rem auto;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)}}
  .header{{background:linear-gradient(135deg,#0f172a,#1e3a5f);color:#fff;padding:2rem 2.5rem}}
  .logo{{display:flex;align-items:center;gap:12px;margin-bottom:1.5rem}}
  .logo-icon{{width:40px;height:40px;background:#3b82f6;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px}}
  .logo-text{{font-size:1.4rem;font-weight:800}}.logo-sub{{font-size:11px;color:#94a3b8;letter-spacing:2px;text-transform:uppercase}}
  .verdict-box{{background:rgba(255,255,255,.08);border-radius:12px;padding:1.5rem;display:flex;align-items:center;gap:2rem;flex-wrap:wrap}}
  .meta{{background:#f8fafc;padding:1.5rem 2.5rem;display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1rem;border-bottom:1px solid #e5e7eb}}
  .mc{{text-align:center}}.ml{{font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px}}.mv{{font-size:1.1rem;font-weight:700;color:#111827}}
  .section{{padding:1.5rem 2.5rem}}
  h2{{font-size:15px;font-weight:700;color:#1e293b;margin-bottom:1rem;text-transform:uppercase;letter-spacing:.5px;padding-bottom:6px;border-bottom:2px solid #e5e7eb}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  th{{background:#f1f5f9;padding:10px 12px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#475569;font-weight:600}}
  tr:nth-child(even){{background:#f8fafc}}
  footer{{text-align:center;padding:1rem;font-size:12px;color:#9ca3af;border-top:1px solid #f1f5f9}}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div class="logo">
      <div class="logo-icon">📧</div>
      <div><div class="logo-text">PhishGuard</div><div class="logo-sub">Email Phishing Analyzer</div></div>
    </div>
    <div class="verdict-box">
      <div>{ring}</div>
      <div style="flex:1">
        <div style="font-size:12px;color:#94a3b8;">FROM: <span style="color:#93c5fd;">{result.sender}</span></div>
        <div style="font-size:14px;font-weight:600;color:#fff;margin-top:6px;">SUBJECT: {result.subject}</div>
        <div style="margin-top:12px;">{_badge(result.risk_level)}</div>
        <div style="font-size:1rem;font-weight:600;color:#fff;margin-top:8px;">{result.final_verdict}</div>
      </div>
    </div>
  </div>

  <div class="meta">
    <div class="mc"><div class="ml">Risk Score</div><div class="mv" style="color:{color}">{result.total_score}/100</div></div>
    <div class="mc"><div class="ml">Risk Level</div><div class="mv" style="color:{color}">{result.risk_level}</div></div>
    <div class="mc"><div class="ml">Checks Run</div><div class="mv">{len(result.findings)}</div></div>
    <div class="mc"><div class="ml">Triggered</div><div class="mv" style="color:#dc2626">{triggered_count}</div></div>
    <div class="mc"><div class="ml">URLs Found</div><div class="mv">{len(result.extracted_urls)}</div></div>
    <div class="mc"><div class="ml">Scan Time</div><div class="mv" style="font-size:.85rem">{ts}</div></div>
  </div>

  <div class="section">
    <h2>Email Analysis Findings</h2>
    <table>
      <thead><tr><th>Check</th><th>Detail</th><th>Points</th><th>Status</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>

  {url_section}

  <footer>PhishGuard v1.0 &nbsp;|&nbsp; Built by <strong>Daksh Shah</strong> &nbsp;|&nbsp; github.com/daksh-shah9135/phishguard &nbsp;|&nbsp; For educational and authorized use only.</footer>
</div>
</body></html>"""

    Path(output_path).write_text(html, encoding="utf-8")
    return output_path

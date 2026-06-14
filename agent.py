#!/usr/bin/env python3
"""
GRC Assessment Agent — Phase 2
Multi-source passive reconnaissance + Gemini AI analysis

Usage:
    python grc_agent_phase2.py "Latitude Financial" --domain latitudefinancial.com.au
    python grc_agent_phase2.py "CBA" --domain commbank.com.au --doc policy.txt
    
Requirements:
    pip install requests python-dotenv rich google-generativeai
    
Environment variables (.env):
    GEMINI_API_KEY=AIzaSy...
    TAVILY_API_KEY=tvly-...          # optional, for news search
    HIBP_API_KEY=...                  # optional, for breach check
"""

import os
import sys
import time
import json
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from google import generativeai as genai
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich import box

load_dotenv()

# ── CONFIG ────────────────────────────────────────────────────
GEMINI_API_KEY    = os.getenv("GEMINI_API_KEY", "")
TAVILY_API_KEY    = os.getenv("TAVILY_API_KEY", "")
HIBP_API_KEY      = os.getenv("HIBP_API_KEY", "")
SSL_POLL_INTERVAL = 10  # seconds
SSL_MAX_WAIT      = 180  # seconds
USER_AGENT        = "GRC-Assessment-Agent/0.2 (portfolio; passive-recon-only)"

console = Console()


# ── UTILITIES ─────────────────────────────────────────────────

def clean_domain(domain: str) -> str:
    """Strip protocol and path from domain."""
    return domain.replace("https://", "").replace("http://", "").split("/")[0].strip()

def status(icon: str, msg: str, style: str = ""):
    console.print(f"  {icon}  {msg}", style=style)

def section(title: str):
    console.print(f"\n[bold white]{title}[/bold white]")
    console.print("─" * 60, style="dim")


# ── DATA SOURCES ──────────────────────────────────────────────

def check_ssl(domain: str) -> dict:
    """Qualys SSL Labs passive TLS/SSL assessment."""
    host = clean_domain(domain)
    base = "https://api.ssllabs.com/api/v3"
    
    try:
        # Trigger analysis (don't force new if cached)
        r = requests.get(f"{base}/analyze", params={"host": host, "startNew": "on", "all": "on"},
                         headers={"User-Agent": USER_AGENT}, timeout=15)
        r.raise_for_status()
        
        # Poll until ready
        elapsed = 0
        while elapsed < SSL_MAX_WAIT:
            time.sleep(SSL_POLL_INTERVAL)
            elapsed += SSL_POLL_INTERVAL
            
            r = requests.get(f"{base}/analyze", params={"host": host, "all": "on"},
                             headers={"User-Agent": USER_AGENT}, timeout=15)
            data = r.json()
            
            if data.get("status") == "READY":
                ep = data.get("endpoints", [{}])[0]
                d  = ep.get("details", {})
                return {
                    "grade":          ep.get("grade", "Unknown"),
                    "has_warnings":   ep.get("hasWarnings", False),
                    "ip":             ep.get("ipAddress"),
                    "protocols":      [f"{p['name']} {p['version']}" for p in d.get("protocols", [])],
                    "forward_secrecy": d.get("forwardSecrecy", 0) > 0,
                    "hsts":           d.get("hstsPolicy", {}).get("status", "absent"),
                    "heartbleed":     d.get("heartbleed", False),
                    "poodle_tls":     d.get("poodleTls", -3) > 0,
                    "beast":          d.get("vulnBeast", False),
                    "robot":          d.get("robotVulnerable", False) if "robotVulnerable" in d else None,
                    "cert_expiry":    d.get("cert", {}).get("notAfter"),
                    "cert_subject":   d.get("cert", {}).get("subject"),
                    "cert_issuer":    d.get("cert", {}).get("issuerSubject"),
                }
            
            if data.get("status") == "ERROR":
                return {"error": data.get("statusMessage", "SSL Labs error")}
        
        return {"error": "Timed out"}
    
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


def check_security_headers(domain: str) -> dict:
    """SecurityHeaders.com — parse response headers for grade."""
    host = clean_domain(domain)
    try:
        r = requests.get(
            f"https://securityheaders.com/",
            params={"q": host, "followRedirects": "on", "hide": "on"},
            headers={"User-Agent": USER_AGENT},
            timeout=15
        )
        grade = r.headers.get("X-Grade", "Unknown")
        score = r.headers.get("X-Score", "Unknown")
        
        # Parse which headers are present/missing from the response
        present = []
        missing = []
        security_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        
        # Check the actual site for these headers
        try:
            site_r = requests.get(
                f"https://{host}",
                headers={"User-Agent": USER_AGENT},
                timeout=10,
                allow_redirects=True
            )
            for h in security_headers:
                if h.lower() in {k.lower() for k in site_r.headers}:
                    present.append(h)
                else:
                    missing.append(h)
        except Exception:
            pass  # If we can't reach the site, we just use the grade
        
        return {
            "grade": grade,
            "score": score,
            "present": present,
            "missing": missing,
        }
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


def search_news(company: str) -> dict:
    """Tavily AI search for recent security incidents."""
    if not TAVILY_API_KEY:
        return {"skipped": True, "reason": "TAVILY_API_KEY not set"}
    
    try:
        r = requests.post(
            "https://api.tavily.com/search",
            json={
                "api_key": TAVILY_API_KEY,
                "query": f'"{company}" cybersecurity data breach hack incident security Australia',
                "search_depth": "basic",
                "max_results": 6,
                "include_answer": True,
            },
            timeout=30
        )
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


def check_hibp(domain: str) -> dict:
    """Have I Been Pwned — check domain breach history."""
    if not HIBP_API_KEY:
        return {"skipped": True, "reason": "HIBP_API_KEY not set"}
    
    host = clean_domain(domain)
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breaches",
            params={"domain": host},
            headers={
                "hibp-api-key": HIBP_API_KEY,
                "User-Agent": USER_AGENT,
            },
            timeout=15
        )
        if r.status_code == 200:
            breaches = r.json()
            return {
                "count": len(breaches),
                "breaches": [
                    {
                        "name": b["Name"],
                        "date": b["BreachDate"],
                        "records": b["PwnCount"],
                        "data_classes": b["DataClasses"][:5],
                        "description": b.get("Description", "")[:200]
                    }
                    for b in breaches
                ]
            }
        elif r.status_code == 404:
            return {"count": 0, "breaches": []}
        else:
            return {"error": f"HTTP {r.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


# ── GEMINI ANALYSIS ───────────────────────────────────────────

SYSTEM_PROMPT = """You are a senior GRC analyst specialising in Australian cybersecurity frameworks. 

You receive passive reconnaissance data gathered from public sources and optionally a company document. Synthesise all available intelligence into a comprehensive, accurate GRC assessment.

Rules:
- Only assert what the evidence supports
- Where technical data contradicts document claims, flag it as a finding  
- Use maturity 0 for Essential Eight controls with no evidence
- Be direct about gaps — this is a professional assessment, not marketing
- Mark confidence LOW if limited data was available

Respond ONLY with raw JSON matching this schema exactly (no markdown fences, no preamble):

{
  "executive_summary": "2-3 sentence synthesis of all data sources",
  "overall_risk_rating": "HIGH|MEDIUM|LOW",
  "risk_score": 7.5,
  "confidence": "HIGH|MEDIUM|LOW",
  "data_sensitivity": "what sensitive data this organisation handles",
  "data_sources_used": ["SSL Labs", "Security Headers", "News Intelligence", "HIBP", "Document"],
  "technical_summary": {
    "ssl_grade": "A|B|C|D|F|T|Unknown",
    "headers_grade": "A+|A|B|C|D|E|F|Unknown",
    "known_breaches": 0,
    "key_vulnerabilities": ["list of specific technical issues found"]
  },
  "findings": [
    {
      "id": "F001",
      "source": "SSL|Headers|News|HIBP|Document|Inferred",
      "category": "Privacy|Access Control|Incident Response|Data Security|Third Party Risk|Governance|Transport Security",
      "severity": "HIGH|MEDIUM|LOW",
      "title": "concise finding title",
      "observation": "what was found",
      "risk": "what risk this creates"
    }
  ],
  "essential_eight": {
    "patch_applications":        { "maturity": 0, "notes": "...", "source": "SSL|Headers|News|Document|None" },
    "patch_os":                  { "maturity": 0, "notes": "...", "source": "..." },
    "multi_factor_auth":         { "maturity": 0, "notes": "...", "source": "..." },
    "restrict_admin_privileges": { "maturity": 0, "notes": "...", "source": "..." },
    "application_control":       { "maturity": 0, "notes": "...", "source": "..." },
    "restrict_macros":           { "maturity": 0, "notes": "...", "source": "..." },
    "user_application_hardening":{ "maturity": 0, "notes": "...", "source": "..." },
    "regular_backups":           { "maturity": 0, "notes": "...", "source": "..." }
  },
  "iso_27001": [
    { "domain": "Information Security Policies",    "clause": "A.5",  "status": "Evident|Partial|Gap|Unknown", "notes": "..." },
    { "domain": "Organisation of Information Security", "clause": "A.6", "status": "...", "notes": "..." },
    { "domain": "Human Resource Security",          "clause": "A.7",  "status": "...", "notes": "..." },
    { "domain": "Asset Management",                 "clause": "A.8",  "status": "...", "notes": "..." },
    { "domain": "Access Control",                   "clause": "A.9",  "status": "...", "notes": "..." },
    { "domain": "Cryptography",                     "clause": "A.10", "status": "...", "notes": "..." },
    { "domain": "Physical Security",                "clause": "A.11", "status": "...", "notes": "..." },
    { "domain": "Operations Security",              "clause": "A.12", "status": "...", "notes": "..." },
    { "domain": "Communications Security",          "clause": "A.13", "status": "...", "notes": "..." },
    { "domain": "Supplier Relationships",           "clause": "A.15", "status": "...", "notes": "..." },
    { "domain": "Incident Management",              "clause": "A.16", "status": "...", "notes": "..." },
    { "domain": "Business Continuity",              "clause": "A.17", "status": "...", "notes": "..." },
    { "domain": "Compliance",                       "clause": "A.18", "status": "...", "notes": "..." }
  ],
  "nist_csf": [
    { "function": "Govern",   "status": "Evident|Partial|Gap|Unknown", "notes": "..." },
    { "function": "Identify", "status": "...", "notes": "..." },
    { "function": "Protect",  "status": "...", "notes": "..." },
    { "function": "Detect",   "status": "...", "notes": "..." },
    { "function": "Respond",  "status": "...", "notes": "..." },
    { "function": "Recover",  "status": "...", "notes": "..." }
  ],
  "privacy_act": {
    "overall_status": "Apparent|Partial|Concern|Unknown",
    "apps_assessed": [
      { "app": "APP 1 - Open and transparent management", "status": "...", "notes": "..." },
      { "app": "APP 3 - Collection of personal information", "status": "...", "notes": "..." },
      { "app": "APP 5 - Notification of collection", "status": "...", "notes": "..." },
      { "app": "APP 6 - Use and disclosure", "status": "...", "notes": "..." },
      { "app": "APP 11 - Security of personal information", "status": "...", "notes": "..." },
      { "app": "APP 12 - Access to personal information", "status": "...", "notes": "..." }
    ]
  },
  "recommendations": [
    {
      "priority": "HIGH|MEDIUM|LOW",
      "action": "concise action title",
      "rationale": "why this matters",
      "framework_ref": "e.g. Essential Eight - MFA, Level 2",
      "triggered_by": "what data source surfaced this"
    }
  ],
  "limitations": "honest note on what passive analysis cannot determine",
  "assessed_by": "GRC Assessment Agent v0.2 (Phase 2 - Multi-Source Intelligence)",
  "assessment_date": "ISO date string"
}"""


def build_user_message(company, domain, ssl_data, headers_data, news_data, hibp_data, doc_text):
    lines = [f"Company: {company}"]
    if domain:
        lines.append(f"Domain: {domain}")
    lines.append(f"Assessment date: {datetime.now().strftime('%d %B %Y')}")
    lines.append("")

    # SSL
    if ssl_data and "error" not in ssl_data:
        lines.append("=== SSL/TLS ASSESSMENT (Qualys SSL Labs) ===")
        lines.append(f"Grade: {ssl_data.get('grade', 'Unknown')}")
        lines.append(f"Has warnings: {ssl_data.get('has_warnings', False)}")
        if ssl_data.get("protocols"):
            lines.append(f"Protocols: {', '.join(ssl_data['protocols'])}")
        lines.append(f"Forward secrecy: {ssl_data.get('forward_secrecy', 'Unknown')}")
        lines.append(f"HSTS: {ssl_data.get('hsts', 'Unknown')}")
        if ssl_data.get("heartbleed"):
            lines.append("⚠ VULNERABLE: Heartbleed")
        if ssl_data.get("poodle_tls"):
            lines.append("⚠ VULNERABLE: POODLE TLS")
        if ssl_data.get("beast"):
            lines.append("⚠ VULNERABLE: BEAST")
        if ssl_data.get("cert_expiry"):
            expiry_ms = ssl_data["cert_expiry"]
            expiry_dt = datetime.fromtimestamp(expiry_ms / 1000)
            lines.append(f"Cert expiry: {expiry_dt.strftime('%d %b %Y')}")
        lines.append("")
    elif ssl_data and "error" in ssl_data:
        lines.append(f"=== SSL/TLS ASSESSMENT: Failed — {ssl_data['error']} ===\n")

    # Headers
    if headers_data and "error" not in headers_data:
        lines.append("=== SECURITY HEADERS ===")
        lines.append(f"Grade: {headers_data.get('grade', 'Unknown')}")
        lines.append(f"Score: {headers_data.get('score', 'Unknown')}")
        if headers_data.get("missing"):
            lines.append(f"Missing headers: {', '.join(headers_data['missing'])}")
        if headers_data.get("present"):
            lines.append(f"Present headers: {', '.join(headers_data['present'])}")
        lines.append("")
    elif headers_data and "error" in headers_data:
        lines.append(f"=== SECURITY HEADERS: Failed — {headers_data['error']} ===\n")

    # HIBP
    if hibp_data and "error" not in hibp_data and "skipped" not in hibp_data:
        lines.append("=== HAVE I BEEN PWNED — BREACH HISTORY ===")
        lines.append(f"Known breaches: {hibp_data.get('count', 0)}")
        for b in hibp_data.get("breaches", []):
            lines.append(f"- {b['name']} ({b['date']}): {b['records']:,} records | Data: {', '.join(b['data_classes'])}")
        lines.append("")
    elif hibp_data and hibp_data.get("skipped"):
        lines.append("=== HIBP: Skipped (no API key) ===\n")

    # News
    if news_data and "error" not in news_data and "skipped" not in news_data:
        lines.append("=== NEWS INTELLIGENCE (Tavily) ===")
        if news_data.get("answer"):
            lines.append(f"Summary: {news_data['answer']}")
        for r in news_data.get("results", [])[:5]:
            lines.append(f"- {r.get('title', '')}: {r.get('content', '')[:250]}...")
        lines.append("")
    elif news_data and news_data.get("skipped"):
        lines.append("=== NEWS: Skipped (no API key) ===\n")

    # Document
    if doc_text and doc_text.strip():
        lines.append("=== COMPANY DOCUMENT ===")
        lines.append(doc_text[:30000])  # Gemini handles much larger context windows
    else:
        lines.append("=== DOCUMENT: Not provided — base assessment on technical data only ===")

    return "\n".join(lines)


def analyse_with_gemini(user_message: str) -> dict:
    """Call Gemini API and parse JSON response."""
    if not GEMINI_API_KEY:
        raise ValueError("GEMINI_API_KEY not set in environment")
        
    genai.configure(api_key=GEMINI_API_KEY)
    
    # Using gemini-1.5-pro for best reasoning capabilities and large document analysis
    model = genai.GenerativeModel(
        model_name="gemini-1.5-pro",
        system_instruction=SYSTEM_PROMPT,
        generation_config={
            "response_mime_type": "application/json"
        }
    )
    
    try:
        response = model.generate_content(user_message)
        # Strip potential markdown codeblocks just in case, though mime_type should handle it
        text = response.text.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        return json.loads(text)
    except Exception as e:
        raise RuntimeError(f"Gemini API request failed: {e}")


# ── TERMINAL REPORT ───────────────────────────────────────────

RISK_COLORS = {"HIGH": "bold red", "MEDIUM": "bold yellow", "LOW": "bold green"}
STATUS_COLORS = {
    "Evident": "green", "Apparent": "green",
    "Partial": "yellow",
    "Gap": "red", "Concern": "red",
    "Unknown": "dim",
}

def grade_color(grade: str) -> str:
    if not grade or grade == "Unknown": return "dim"
    g = grade.upper()
    if g.startswith("A"): return "green"
    if g == "B": return "yellow"
    if g == "C": return "dark_orange"
    return "red"

def render_report(report: dict, company: str, domain: str = ""):
    console.print()
    
    # ── Header ──
    risk = report.get("overall_risk_rating", "UNKNOWN")
    score = report.get("risk_score", 0)
    risk_color = RISK_COLORS.get(risk, "white")
    
    header_text = Text()
    header_text.append(f"  {company.upper()}  ", style="bold white")
    header_text.append(f"| {risk} RISK  ", style=risk_color)
    header_text.append(f"| Score: {score}/10  ", style="white")
    header_text.append(f"| Confidence: {report.get('confidence', '?')}  ", style="dim")
    if domain:
        header_text.append(f"| {domain}", style="dim")
    
    console.print(Panel(
        header_text,
        title="[bold]GRC Assessment Agent v0.2[/bold]",
        subtitle=f"[dim]{report.get('assessment_date', datetime.now().strftime('%d %B %Y'))}[/dim]",
        border_style=risk_color,
    ))

    # ── Executive Summary ──
    section("Executive Summary")
    console.print(f"  {report.get('executive_summary', '')}\n", style="white")
    console.print(f"  [dim]Data handled:[/dim] {report.get('data_sensitivity', '')}\n")
    console.print(f"  [dim]Sources used:[/dim] {', '.join(report.get('data_sources_used', []))}\n")

    # ── Technical Summary ──
    tech = report.get("technical_summary", {})
    if tech:
        section("Technical Reconnaissance")
        cols = []
        ssl_g = tech.get("ssl_grade", "Unknown")
        hdr_g = tech.get("headers_grade", "Unknown")
        breaches = tech.get("known_breaches", 0)
        vulns = tech.get("key_vulnerabilities", [])
        
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        t.add_column("Key", style="dim")
        t.add_column("Value")
        t.add_row("SSL Grade", f"[{grade_color(ssl_g)}]{ssl_g}[/{grade_color(ssl_g)}]")
        t.add_row("Headers Grade", f"[{grade_color(hdr_g)}]{hdr_g}[/{grade_color(hdr_g)}]")
        t.add_row("Known Breaches", f"[{'red' if breaches > 0 else 'green'}]{breaches}[/{'red' if breaches > 0 else 'green'}]")
        if vulns:
            t.add_row("Vulnerabilities", "[red]" + ", ".join(vulns[:3]) + "[/red]")
        console.print(t)

    # ── Findings ──
    findings = report.get("findings", [])
    if findings:
        section(f"Findings ({len(findings)} total)")
        t = Table(box=box.SIMPLE, show_header=True, padding=(0, 1), expand=True)
        t.add_column("ID",       style="dim",  width=5)
        t.add_column("Sev",                    width=8)
        t.add_column("Source",   style="dim",  width=10)
        t.add_column("Category", style="dim",  width=18)
        t.add_column("Finding",                min_width=30)
        
        for f in findings:
            sev = f.get("severity", "")
            t.add_row(
                f.get("id", ""),
                f"[{RISK_COLORS.get(sev, 'white')}]{sev}[/]",
                f.get("source", ""),
                f.get("category", ""),
                f.get("title", ""),
            )
        console.print(t)

        # Detail for HIGH findings
        high = [f for f in findings if f.get("severity") == "HIGH"]
        if high:
            console.print("  [bold red]High severity detail:[/bold red]")
            for f in high:
                console.print(f"  [{f['id']}] {f['title']}")
                console.print(f"       Observation: {f.get('observation', '')}", style="dim")
                console.print(f"       Risk: {f.get('risk', '')}\n", style="dim red")

    # ── Essential Eight ──
    section("Essential Eight Maturity")
    e8 = report.get("essential_eight", {})
    e8_labels = {
        "patch_applications": "Patch Applications",
        "patch_os": "Patch OS",
        "multi_factor_auth": "MFA",
        "restrict_admin_privileges": "Restrict Admin",
        "application_control": "App Control",
        "restrict_macros": "Restrict Macros",
        "user_application_hardening": "App Hardening",
        "regular_backups": "Backups",
    }
    t = Table(box=box.SIMPLE, show_header=True, padding=(0, 1), expand=True)
    t.add_column("Control",  width=22)
    t.add_column("Maturity", width=10)
    t.add_column("Source",   style="dim", width=12)
    t.add_column("Notes",    min_width=30)
    
    for key, label in e8_labels.items():
        val = e8.get(key, {})
        m = val.get("maturity", 0)
        bar = "█" * m + "░" * (4 - m) if m > 0 else "? ? ? ?"
        bar_color = "green" if m >= 3 else "yellow" if m >= 2 else "red" if m == 1 else "dim"
        t.add_row(
            label,
            f"[{bar_color}]{bar} L{m}[/{bar_color}]" if m > 0 else f"[dim]{bar}[/dim]",
            val.get("source", ""),
            val.get("notes", ""),
        )
    console.print(t)

    # ── ISO 27001 ──
    section("ISO 27001:2022 Domains")
    t = Table(box=box.SIMPLE, show_header=True, padding=(0, 1), expand=True)
    t.add_column("Clause", style="dim", width=6)
    t.add_column("Domain",              width=30)
    t.add_column("Status",              width=10)
    t.add_column("Notes",               min_width=25)
    for d in report.get("iso_27001", []):
        st = d.get("status", "Unknown")
        t.add_row(
            d.get("clause", ""),
            d.get("domain", ""),
            f"[{STATUS_COLORS.get(st, 'white')}]{st}[/{STATUS_COLORS.get(st, 'white')}]",
            d.get("notes", ""),
        )
    console.print(t)

    # ── NIST CSF ──
    section("NIST CSF 2.0")
    t = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
    t.add_column("Function",  width=12)
    t.add_column("Status",    width=10)
    t.add_column("Notes",     min_width=40)
    for fn in report.get("nist_csf", []):
        st = fn.get("status", "Unknown")
        t.add_row(
            fn.get("function", ""),
            f"[{STATUS_COLORS.get(st, 'white')}]{st}[/{STATUS_COLORS.get(st, 'white')}]",
            fn.get("notes", ""),
        )
    console.print(t)

    # ── Recommendations ──
    recs = report.get("recommendations", [])
    if recs:
        section(f"Recommendations ({len(recs)})")
        for i, rec in enumerate(recs, 1):
            p = rec.get("priority", "")
            console.print(f"  [{i}] [{RISK_COLORS.get(p, 'white')}]{p}[/] — {rec.get('action', '')}")
            console.print(f"       {rec.get('rationale', '')}", style="dim")
            console.print(f"       [{rec.get('framework_ref', '')}] · triggered by: {rec.get('triggered_by', '')}\n", style="dim")

    # ── Disclaimer ──
    console.print(Panel(
        f"[dim]{report.get('limitations', '')}\n\n"
        "Passive reconnaissance only — no active scanning. Findings are indicative and require "
        "human review before professional use. Not a substitute for authorised security assessment.[/dim]",
        title="[dim]Disclaimer[/dim]",
        border_style="dim",
    ))


# ── MAIN ──────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="GRC Assessment Agent v0.2 — passive multi-source reconnaissance",
        epilog="Example: python grc_agent_phase2.py 'Latitude Financial' --domain latitudefinancial.com.au"
    )
    parser.add_argument("company",         help="Company name")
    parser.add_argument("--domain", "-d",  help="Domain to scan (e.g. commbank.com.au)")
    parser.add_argument("--doc",    "-f",  help="Path to document file (.txt, .pdf text)")
    parser.add_argument("--output", "-o",  default="both", choices=["terminal", "json", "both"],
                        help="Output format (default: both)")
    parser.add_argument("--no-ssl",        action="store_true", help="Skip SSL Labs check")
    parser.add_argument("--no-headers",    action="store_true", help="Skip security headers check")
    parser.add_argument("--no-news",       action="store_true", help="Skip news search")
    parser.add_argument("--no-hibp",       action="store_true", help="Skip HIBP breach check")
    args = parser.parse_args()

    # ── Startup banner ──
    console.print(Panel(
        "[bold white]GRC Assessment Agent[/bold white] [dim]v0.2 — Phase 2 Multi-Source Intelligence[/dim]\n"
        "[dim]Passive reconnaissance only · Australian frameworks · AI-powered analysis[/dim]",
        border_style="blue",
    ))

    # ── Validate ──
    if not GEMINI_API_KEY:
        console.print("[red]✗ GEMINI_API_KEY not set. Add it to your .env file.[/red]")
        sys.exit(1)

    doc_text = ""
    if args.doc:
        try:
            with open(args.doc, "r", encoding="utf-8", errors="ignore") as f:
                doc_text = f.read()
            status("📄", f"Document loaded: {args.doc} ({len(doc_text):,} chars)")
        except FileNotFoundError:
            status("⚠", f"Document not found: {args.doc}", "yellow")

    # ── Data gathering ──
    console.print()
    console.print("[bold white]Gathering intelligence...[/bold white]")
    console.print("─" * 60, style="dim")

    ssl_data     = None
    headers_data = None
    news_data    = None
    hibp_data    = None

    if args.domain:
        # Run non-SSL checks in parallel (they're fast)
        with ThreadPoolExecutor(max_workers=3) as ex:
            futures = {}
            
            if not args.no_headers:
                status("⟳", "Security headers check starting...")
                futures["headers"] = ex.submit(check_security_headers, args.domain)
            
            if not args.no_hibp:
                if HIBP_API_KEY:
                    status("⟳", "HIBP breach history check starting...")
                    futures["hibp"] = ex.submit(check_hibp, args.domain)
                else:
                    status("○", "HIBP: skipped (no HIBP_API_KEY)", "dim")
            
            if not args.no_news:
                if TAVILY_API_KEY:
                    status("⟳", "News intelligence search starting...")
                    futures["news"] = ex.submit(search_news, args.company)
                else:
                    status("○", "News search: skipped (no TAVILY_API_KEY)", "dim")

            # SSL Labs runs separately (it's slow and needs its own status updates)
            if not args.no_ssl:
                status("⟳", f"SSL Labs: starting analysis of {args.domain} (60–90s)...")
                ssl_data = check_ssl(args.domain)
                if "error" not in ssl_data:
                    status("✓", f"SSL Labs: grade [bold]{ssl_data.get('grade')}[/bold]", "green")
                else:
                    status("✗", f"SSL Labs: {ssl_data['error']}", "yellow")
            
            # Collect parallel results
            for name, fut in futures.items():
                try:
                    result = fut.result()
                    if name == "headers":
                        headers_data = result
                        if "error" not in result:
                            status("✓", f"Security headers: grade [bold]{result.get('grade', 'Unknown')}[/bold]", "green")
                        else:
                            status("✗", f"Security headers: {result['error']}", "yellow")
                    elif name == "hibp":
                        hibp_data = result
                        count = result.get("count", 0)
                        if "error" not in result:
                            style = "red" if count > 0 else "green"
                            status("✓", f"HIBP: [{style}]{count} breach(es) found[/{style}]", style)
                        else:
                            status("✗", f"HIBP: {result.get('error')}", "yellow")
                    elif name == "news":
                        news_data = result
                        count = len(result.get("results", []))
                        if "error" not in result:
                            status("✓", f"News: {count} results found", "green")
                        else:
                            status("✗", f"News: {result.get('error')}", "yellow")
                except Exception as e:
                    status("✗", f"{name}: {e}", "yellow")
    else:
        status("○", "No domain provided — skipping technical checks", "dim")
        if not args.no_news and TAVILY_API_KEY:
            status("⟳", "News intelligence search starting...")
            news_data = search_news(args.company)
            count = len((news_data or {}).get("results", []))
            status("✓", f"News: {count} results found", "green")

    # ── AI Analysis ──
    console.print()
    console.print("[bold white]Running AI analysis...[/bold white]")
    console.print("─" * 60, style="dim")
    status("⟳", "Sending to Gemini 1.5 Pro...")
    
    user_message = build_user_message(
        args.company, args.domain,
        ssl_data, headers_data, news_data, hibp_data,
        doc_text
    )
    
    try:
        report = analyse_with_gemini(user_message)
        report["assessment_date"] = datetime.now().strftime("%d %B %Y")
        report["_meta"] = {
            "company": args.company,
            "domain": args.domain,
            "agent_version": "0.2",
        }
        status("✓", "Analysis complete", "green")
    except Exception as e:
        console.print(f"\n[red]Analysis failed: {e}[/red]")
        sys.exit(1)

    # ── Output ──
    if args.output in ("terminal", "both"):
        render_report(report, args.company, args.domain or "")

    if args.output in ("json", "both"):
        filename = f"{args.company.replace(' ', '_').lower()}_grc_v02_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
        with open(filename, "w") as f:
            json.dump(report, f, indent=2)
        console.print(f"\n  [green]✓[/green] Report saved: [bold]{filename}[/bold]")
        console.print("  [dim]Pass this JSON to Phase 4 for PDF generation.[/dim]\n")


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
GRC Assessment Agent — Phase 2
Multi-source passive reconnaissance + local AI analysis via Ollama

Completely free. No API keys required for core functionality.
Runs entirely on your machine using open-source LLMs.

Maps findings to: Essential Eight, ISO 27001:2022, NIST CSF 2.0, Privacy Act AU

Setup:
    1. Install Ollama:  https://ollama.com
    2. Pull a model:    ollama pull llama3.1
    3. Install deps:    pip install requests python-dotenv rich
    4. Copy .env.example → .env and fill in optional keys
    5. Run it:          python grc_agent_phase2.py "Company" --domain domain.com.au

Usage:
    python grc_agent_phase2.py "Latitude Financial" --domain latitudefinancial.com.au
    python grc_agent_phase2.py "CBA" --domain commbank.com.au --doc policy.txt
    python grc_agent_phase2.py "ANZ" --domain anz.com.au --model mistral --no-ssl
    python grc_agent_phase2.py "Medibank" --domain medibank.com.au --output json

Data sources (all free):
    - Qualys SSL Labs       (free, no key needed)
    - SecurityHeaders.com   (free, no key needed)
    - Tavily news search    (optional — TAVILY_API_KEY in .env, free tier available)
    - Have I Been Pwned     (optional — HIBP_API_KEY in .env, ~$4 AUD/month)
    - Document analysis     (--doc flag, any .txt file)

Recommended Ollama models (in order of preference for this task):
    llama3.1        ollama pull llama3.1          (best quality, ~4.7GB)
    llama3.2        ollama pull llama3.2          (faster, ~2GB)
    mistral         ollama pull mistral            (great at JSON, ~4.1GB)
    gemma2          ollama pull gemma2             (good alternative, ~5.4GB)
    qwen2.5         ollama pull qwen2.5            (excellent instruction following)
"""

import os
import sys
import time
import json
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

import requests
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

load_dotenv()

# ── CONFIG ────────────────────────────────────────────────────────────────────

OLLAMA_HOST   = os.getenv("OLLAMA_HOST",  "http://localhost:11434")
OLLAMA_MODEL  = os.getenv("OLLAMA_MODEL", "llama3.1")
TAVILY_API_KEY = os.getenv("TAVILY_API_KEY", "")
HIBP_API_KEY   = os.getenv("HIBP_API_KEY",   "")

SSL_POLL_INTERVAL = 10   # seconds between SSL Labs polls
SSL_MAX_WAIT      = 180  # seconds before giving up
USER_AGENT        = "GRC-Assessment-Agent/0.2 (passive-recon-only; portfolio)"

console = Console()


# ── UTILITIES ─────────────────────────────────────────────────────────────────

def clean_domain(domain: str) -> str:
    return domain.replace("https://", "").replace("http://", "").split("/")[0].strip()

def log(icon: str, msg: str, style: str = "white"):
    console.print(f"  {icon}  {msg}", style=style)

def section(title: str):
    console.print(f"\n[bold white]{title}[/bold white]")
    console.print("─" * 60, style="dim")


# ── OLLAMA HEALTH CHECK ───────────────────────────────────────────────────────

def check_ollama(model: str) -> dict:
    """
    Verify Ollama is running and the requested model is available.
    Returns {"ok": True/False, "models": [...], "error": "..."}
    """
    try:
        r = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=5)
        r.raise_for_status()
        available = [m["name"].split(":")[0] for m in r.json().get("models", [])]
        model_base = model.split(":")[0]
        return {
            "ok":        model_base in available,
            "models":    available,
            "has_model": model_base in available,
        }
    except requests.exceptions.ConnectionError:
        return {"ok": False, "models": [], "error": "Ollama not running"}
    except Exception as e:
        return {"ok": False, "models": [], "error": str(e)}


# ── DATA SOURCE 1: SSL LABS ───────────────────────────────────────────────────

def check_ssl(domain: str) -> dict:
    """
    Qualys SSL Labs — passive TLS/SSL assessment. Free, no key required.
    Docs: https://api.ssllabs.com/api/v3/
    Takes 60-90s on first scan; uses cached results if available.
    """
    host = clean_domain(domain)
    base = "https://api.ssllabs.com/api/v3"

    try:
        requests.get(
            f"{base}/analyze",
            params={"host": host, "startNew": "on", "all": "on"},
            headers={"User-Agent": USER_AGENT},
            timeout=15,
        )

        elapsed = 0
        while elapsed < SSL_MAX_WAIT:
            time.sleep(SSL_POLL_INTERVAL)
            elapsed += SSL_POLL_INTERVAL

            r    = requests.get(f"{base}/analyze",
                                params={"host": host, "all": "on"},
                                headers={"User-Agent": USER_AGENT}, timeout=15)
            data = r.json()

            if data.get("status") == "READY":
                ep = data.get("endpoints", [{}])[0]
                d  = ep.get("details", {})

                cert_expiry = None
                raw_ts = d.get("cert", {}).get("notAfter")
                if raw_ts:
                    try:
                        cert_expiry = datetime.fromtimestamp(raw_ts / 1000).strftime("%d %b %Y")
                    except Exception:
                        cert_expiry = str(raw_ts)

                return {
                    "grade":           ep.get("grade", "Unknown"),
                    "has_warnings":    ep.get("hasWarnings", False),
                    "ip":              ep.get("ipAddress"),
                    "protocols":       [f"{p['name']} {p['version']}" for p in d.get("protocols", [])],
                    "forward_secrecy": d.get("forwardSecrecy", 0) > 0,
                    "hsts_status":     d.get("hstsPolicy", {}).get("status", "absent"),
                    "heartbleed":      d.get("heartbleed", False),
                    "poodle_tls":      d.get("poodleTls", -3) > 0,
                    "beast":           d.get("vulnBeast", False),
                    "cert_expiry":     cert_expiry,
                    "cert_subject":    d.get("cert", {}).get("subject"),
                }

            if data.get("status") == "ERROR":
                return {"error": data.get("statusMessage", "SSL Labs error")}

            log("  ", f"SSL Labs: still analysing... ({elapsed}s)", "dim")

        return {"error": f"Timed out after {SSL_MAX_WAIT}s"}

    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


# ── DATA SOURCE 2: SECURITY HEADERS ──────────────────────────────────────────

def check_security_headers(domain: str) -> dict:
    """
    SecurityHeaders.com — HTTP security header grade + direct header check.
    Free, no key required.
    """
    host = clean_domain(domain)
    grade = score = "Unknown"

    try:
        r = requests.get(
            "https://securityheaders.com/",
            params={"q": host, "followRedirects": "on", "hide": "on"},
            headers={"User-Agent": USER_AGENT},
            timeout=15,
            allow_redirects=True,
        )
        raw_grade = r.headers.get("X-Grade", "Unknown")
        score     = r.headers.get("X-Score", "Unknown")
        # SecurityHeaders.com returns an error message in X-Grade if no API key
        # is provided via their new paid tier. Validate it's an actual grade.
        valid_grades = {"A+", "A", "B", "C", "D", "E", "F"}
        grade = raw_grade if raw_grade in valid_grades else "Unknown"
        if raw_grade not in valid_grades and raw_grade != "Unknown":
            log("⚠", "Security headers grade unavailable (API key required for grade — direct header check still ran)", "yellow")
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

    # Direct header check on the live site
    wanted = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
    ]
    present, missing = [], []
    try:
        site = requests.get(f"https://{host}", headers={"User-Agent": USER_AGENT},
                            timeout=10, allow_redirects=True)
        lowered = {k.lower() for k in site.headers}
        for h in wanted:
            (present if h.lower() in lowered else missing).append(h)
    except Exception:
        pass

    return {"grade": grade, "score": score, "present": present, "missing": missing}


# ── DATA SOURCE 3: TAVILY NEWS ────────────────────────────────────────────────

def search_news(company: str) -> dict:
    """
    Tavily AI-optimised search — recent security incidents.
    Free tier: https://tavily.com  |  Set TAVILY_API_KEY in .env
    """
    if not TAVILY_API_KEY:
        return {"skipped": True, "reason": "TAVILY_API_KEY not set in .env"}
    try:
        r = requests.post(
            "https://api.tavily.com/search",
            json={
                "api_key":        TAVILY_API_KEY,
                "query":          f'"{company}" cybersecurity breach hack incident security Australia',
                "search_depth":   "basic",
                "max_results":    6,
                "include_answer": True,
            },
            timeout=30,
        )
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


# ── DATA SOURCE 4: HAVE I BEEN PWNED ─────────────────────────────────────────

def check_hibp(domain: str) -> dict:
    """
    HIBP — known breach history for a domain.
    ~$4 AUD/month: https://haveibeenpwned.com/API/Key  |  Set HIBP_API_KEY in .env
    """
    if not HIBP_API_KEY:
        return {"skipped": True, "reason": "HIBP_API_KEY not set in .env"}
    host = clean_domain(domain)
    try:
        r = requests.get(
            "https://haveibeenpwned.com/api/v3/breaches",
            params={"domain": host},
            headers={"hibp-api-key": HIBP_API_KEY, "User-Agent": USER_AGENT},
            timeout=15,
        )
        if r.status_code == 200:
            breaches = r.json()
            return {
                "count": len(breaches),
                "breaches": [
                    {
                        "name":         b["Name"],
                        "date":         b["BreachDate"],
                        "records":      b["PwnCount"],
                        "data_classes": b["DataClasses"][:6],
                    }
                    for b in breaches
                ],
            }
        if r.status_code == 404:
            return {"count": 0, "breaches": []}
        return {"error": f"HTTP {r.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


# ── OLLAMA ANALYSIS ───────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a senior GRC analyst specialising in Australian cybersecurity frameworks.

You receive passive reconnaissance data from public sources: SSL/TLS results, security headers, news intelligence, breach history, and optionally a company document.

Your job: synthesise all available data into a structured GRC assessment mapped to Essential Eight, ISO 27001:2022, NIST CSF 2.0, and the Australian Privacy Act.

CRITICAL RULES:
- Respond with ONLY valid JSON. No explanation, no markdown, no preamble.
- Only assert what the evidence supports. Mark unobservable controls as Unknown.
- Where technical evidence contradicts document claims, flag it as a "Contradiction" finding.
- Be conservative with maturity ratings — only assert what is evidenced.
- Use maturity 0 when there is no evidence for an Essential Eight control.

Required JSON structure (respond with this exact schema, filled in):
{
  "executive_summary": "2-3 sentence synthesis of all data sources",
  "overall_risk_rating": "HIGH",
  "risk_score": 7.5,
  "confidence": "MEDIUM",
  "data_sensitivity": "what sensitive data this organisation handles",
  "data_sources_used": ["SSL Labs", "Security Headers", "News Intelligence", "HIBP", "Document Analysis"],
  "technical_summary": {
    "ssl_grade": "Unknown",
    "headers_grade": "Unknown",
    "known_breaches": 0,
    "key_vulnerabilities": []
  },
  "findings": [
    {
      "id": "F001",
      "source": "SSL",
      "category": "Transport Security",
      "severity": "HIGH",
      "title": "finding title",
      "observation": "what was found",
      "risk": "what risk this creates"
    }
  ],
  "essential_eight": {
    "patch_applications":         {"maturity": 0, "notes": "...", "source": "None"},
    "patch_os":                   {"maturity": 0, "notes": "...", "source": "None"},
    "multi_factor_auth":          {"maturity": 0, "notes": "...", "source": "None"},
    "restrict_admin_privileges":  {"maturity": 0, "notes": "...", "source": "None"},
    "application_control":        {"maturity": 0, "notes": "...", "source": "None"},
    "restrict_macros":            {"maturity": 0, "notes": "...", "source": "None"},
    "user_application_hardening": {"maturity": 0, "notes": "...", "source": "None"},
    "regular_backups":            {"maturity": 0, "notes": "...", "source": "None"}
  },
  "iso_27001": [
    {"domain": "Information Security Policies",        "clause": "A.5",  "status": "Unknown", "notes": "..."},
    {"domain": "Organisation of Information Security", "clause": "A.6",  "status": "Unknown", "notes": "..."},
    {"domain": "Human Resource Security",              "clause": "A.7",  "status": "Unknown", "notes": "..."},
    {"domain": "Asset Management",                     "clause": "A.8",  "status": "Unknown", "notes": "..."},
    {"domain": "Access Control",                       "clause": "A.9",  "status": "Unknown", "notes": "..."},
    {"domain": "Cryptography",                         "clause": "A.10", "status": "Unknown", "notes": "..."},
    {"domain": "Physical Security",                    "clause": "A.11", "status": "Unknown", "notes": "..."},
    {"domain": "Operations Security",                  "clause": "A.12", "status": "Unknown", "notes": "..."},
    {"domain": "Communications Security",              "clause": "A.13", "status": "Unknown", "notes": "..."},
    {"domain": "Supplier Relationships",               "clause": "A.15", "status": "Unknown", "notes": "..."},
    {"domain": "Incident Management",                  "clause": "A.16", "status": "Unknown", "notes": "..."},
    {"domain": "Business Continuity",                  "clause": "A.17", "status": "Unknown", "notes": "..."},
    {"domain": "Compliance",                           "clause": "A.18", "status": "Unknown", "notes": "..."}
  ],
  "nist_csf": [
    {"function": "Govern",   "status": "Unknown", "notes": "..."},
    {"function": "Identify", "status": "Unknown", "notes": "..."},
    {"function": "Protect",  "status": "Unknown", "notes": "..."},
    {"function": "Detect",   "status": "Unknown", "notes": "..."},
    {"function": "Respond",  "status": "Unknown", "notes": "..."},
    {"function": "Recover",  "status": "Unknown", "notes": "..."}
  ],
  "privacy_act": {
    "overall_status": "Unknown",
    "apps_assessed": [
      {"app": "APP 1 - Open and transparent management",   "status": "Unknown", "notes": "..."},
      {"app": "APP 3 - Collection of personal information","status": "Unknown", "notes": "..."},
      {"app": "APP 5 - Notification of collection",        "status": "Unknown", "notes": "..."},
      {"app": "APP 6 - Use and disclosure",                "status": "Unknown", "notes": "..."},
      {"app": "APP 11 - Security of personal information", "status": "Unknown", "notes": "..."},
      {"app": "APP 12 - Access to personal information",   "status": "Unknown", "notes": "..."}
    ]
  },
  "recommendations": [
    {
      "priority":      "HIGH",
      "action":        "action title",
      "rationale":     "why this matters",
      "framework_ref": "Essential Eight — MFA Level 2",
      "triggered_by":  "which data source surfaced this"
    }
  ],
  "limitations": "note on what passive analysis cannot determine",
  "assessed_by": "GRC Assessment Agent v0.2 (Phase 2 — Ollama / Local AI)"
}"""


def build_user_message(company, domain, ssl_data, headers_data, news_data, hibp_data, doc_text):
    lines = [
        f"Company: {company}",
        f"Domain:  {domain or 'not provided'}",
        f"Date:    {datetime.now().strftime('%d %B %Y')}",
        "",
    ]

    if ssl_data and "error" not in ssl_data:
        lines += [
            "=== SSL/TLS ASSESSMENT (Qualys SSL Labs) ===",
            f"Grade:          {ssl_data.get('grade', 'Unknown')}",
            f"Has warnings:   {ssl_data.get('has_warnings', False)}",
            f"Protocols:      {', '.join(ssl_data.get('protocols', []))}",
            f"Forward secrecy:{ssl_data.get('forward_secrecy', 'Unknown')}",
            f"HSTS status:    {ssl_data.get('hsts_status', 'Unknown')}",
            f"Heartbleed:     {'VULNERABLE' if ssl_data.get('heartbleed') else 'Not vulnerable'}",
            f"POODLE TLS:     {'VULNERABLE' if ssl_data.get('poodle_tls') else 'Not vulnerable'}",
            f"BEAST:          {'VULNERABLE' if ssl_data.get('beast') else 'Not vulnerable'}",
            f"Cert expiry:    {ssl_data.get('cert_expiry', 'Unknown')}",
            "",
        ]
    elif ssl_data:
        lines += [f"=== SSL/TLS ASSESSMENT: Failed — {ssl_data.get('error')} ===", ""]

    if headers_data and "error" not in headers_data:
        lines += [
            "=== SECURITY HEADERS ===",
            f"Grade:   {headers_data.get('grade', 'Unknown')}",
            f"Score:   {headers_data.get('score', 'Unknown')}",
            f"Present: {', '.join(headers_data.get('present', [])) or 'None detected'}",
            f"Missing: {', '.join(headers_data.get('missing', [])) or 'None detected'}",
            "",
        ]
    elif headers_data:
        lines += [f"=== SECURITY HEADERS: Failed — {headers_data.get('error')} ===", ""]

    if hibp_data and "error" not in hibp_data and not hibp_data.get("skipped"):
        lines += [
            "=== HAVE I BEEN PWNED ===",
            f"Known breaches: {hibp_data.get('count', 0)}",
        ]
        for b in hibp_data.get("breaches", []):
            lines.append(
                f"  - {b['name']} ({b['date']}): "
                f"{b['records']:,} records | {', '.join(b['data_classes'])}"
            )
        lines.append("")
    elif hibp_data and hibp_data.get("skipped"):
        lines += ["=== HIBP: Skipped (no HIBP_API_KEY) ===", ""]

    if news_data and "error" not in news_data and not news_data.get("skipped"):
        lines += ["=== NEWS INTELLIGENCE ==="]
        if news_data.get("answer"):
            lines.append(f"Summary: {news_data['answer']}")
        for r in news_data.get("results", [])[:5]:
            snippet = (r.get("content") or "")[:300]
            lines.append(f"  - {r.get('title', '')}: {snippet}...")
        lines.append("")
    elif news_data and news_data.get("skipped"):
        lines += ["=== NEWS: Skipped (no TAVILY_API_KEY) ===", ""]

    if doc_text and doc_text.strip():
        lines += ["=== COMPANY DOCUMENT ===", doc_text[:8000]]
    else:
        lines += ["=== DOCUMENT: Not provided — base assessment on technical data only ==="]

    return "\n".join(lines)


def analyse_with_ollama(user_message: str, model: str) -> dict:
    """
    Send gathered intelligence to a local Ollama model for GRC analysis.
    Uses format='json' to constrain output to valid JSON.
    """
    url = f"{OLLAMA_HOST}/api/chat"

    try:
        r = requests.post(
            url,
            json={
                "model":  model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": user_message},
                ],
                "stream": False,
                "format": "json",      # Force valid JSON output
                "options": {
                    "temperature": 0.1,  # Low temp = consistent structured output
                    "num_ctx":     8192, # Context window — increase if model supports it
                },
            },
            timeout=600,  # Local inference can be slow on CPU — 10 min ceiling
        )
        r.raise_for_status()

    except requests.exceptions.ConnectionError:
        raise ConnectionError(
            f"Cannot connect to Ollama at {OLLAMA_HOST}.\n"
            "  → Install: https://ollama.com\n"
            f"  → Pull model: ollama pull {model}\n"
            "  → Start: ollama serve"
        )

    content = r.json().get("message", {}).get("content", "").strip()

    # Strip markdown fences if the model added them despite format=json
    if content.startswith("```"):
        parts = content.split("```")
        content = parts[1] if len(parts) > 1 else content
        if content.startswith("json"):
            content = content[4:]
    content = content.strip()

    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        # Try to extract JSON object if there's surrounding text
        start = content.find("{")
        end   = content.rfind("}") + 1
        if start != -1 and end > start:
            return json.loads(content[start:end])
        raise ValueError(f"Model did not return valid JSON: {e}\n\nRaw output:\n{content[:500]}")


# ── TERMINAL REPORT ───────────────────────────────────────────────────────────

RISK_STYLE   = {"HIGH": "bold red", "MEDIUM": "bold yellow", "LOW": "bold green"}
STATUS_STYLE = {
    "Evident": "green", "Apparent": "green",
    "Partial": "yellow",
    "Gap": "red", "Concern": "red",
    "Unknown": "dim",
}

def grade_style(g: str) -> str:
    if not g or g == "Unknown":  return "dim"
    if g.upper().startswith("A"): return "green"
    if g.upper() == "B":          return "yellow"
    if g.upper() == "C":          return "dark_orange"
    return "red"

def maturity_bar(level) -> str:
    try:
        level = int(level)
    except (TypeError, ValueError):
        level = 0
    level = max(0, min(4, level))  # clamp to 0-4
    if level == 0:
        return "[dim]·  ·  ·  ·  unknown[/dim]"
    color = "green" if level >= 3 else "yellow" if level == 2 else "red"
    return f"[{color}]{'█' * level}{'░' * (4 - level)}  L{level}[/{color}]"


def _s(v, fallback="") -> str:
    """Safely coerce any value to a non-None string."""
    if v is None:
        return fallback
    if isinstance(v, dict):
        # Model returned an object where a string was expected — grab the most useful field
        for key in ("name", "type", "title", "description", "value", "text"):
            if key in v:
                return str(v[key])
        return str(v)
    return str(v)


def sanitize_report(report: dict) -> dict:
    """
    Normalise model output before rendering.
    Local models occasionally return wrong types — dicts where strings are
    expected, strings where ints are expected, None for missing fields, etc.
    This pass makes the renderer crash-proof regardless of what the model did.
    """
    # Top-level strings
    for key in ("executive_summary", "overall_risk_rating", "confidence",
                "data_sensitivity", "limitations", "assessed_by", "assessment_date"):
        report[key] = _s(report.get(key))

    # risk_score → float
    try:
        report["risk_score"] = float(report.get("risk_score") or 0)
    except (TypeError, ValueError):
        report["risk_score"] = 0.0

    # data_sources_used → list of strings
    sources = report.get("data_sources_used", [])
    report["data_sources_used"] = [_s(s) for s in sources] if isinstance(sources, list) else []

    # technical_summary
    tech = report.get("technical_summary")
    if not isinstance(tech, dict):
        report["technical_summary"] = {}
        tech = report["technical_summary"]
    tech["ssl_grade"]     = _s(tech.get("ssl_grade"),     "Unknown")
    tech["headers_grade"] = _s(tech.get("headers_grade"), "Unknown")
    try:
        tech["known_breaches"] = int(tech.get("known_breaches") or 0)
    except (TypeError, ValueError):
        tech["known_breaches"] = 0
    vulns = tech.get("key_vulnerabilities", [])
    tech["key_vulnerabilities"] = (
        [_s(v) for v in vulns] if isinstance(vulns, list) else []
    )

    # findings
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        report["findings"] = []
    else:
        for f in findings:
            if isinstance(f, dict):
                for k in ("id", "source", "category", "severity", "title", "observation", "risk"):
                    f[k] = _s(f.get(k))

    # essential_eight
    e8 = report.get("essential_eight", {})
    if not isinstance(e8, dict):
        report["essential_eight"] = {}
        e8 = report["essential_eight"]
    for ctrl, val in e8.items():
        if not isinstance(val, dict):
            e8[ctrl] = {"maturity": 0, "notes": "", "source": ""}
            val = e8[ctrl]
        try:
            val["maturity"] = int(val.get("maturity") or 0)
        except (TypeError, ValueError):
            val["maturity"] = 0
        val["notes"]  = _s(val.get("notes"))
        val["source"] = _s(val.get("source"))

    # iso_27001
    iso = report.get("iso_27001", [])
    if isinstance(iso, list):
        for d in iso:
            if isinstance(d, dict):
                for k in ("domain", "clause", "status", "notes"):
                    d[k] = _s(d.get(k))

    # nist_csf
    nist = report.get("nist_csf", [])
    if isinstance(nist, list):
        for fn in nist:
            if isinstance(fn, dict):
                for k in ("function", "status", "notes"):
                    fn[k] = _s(fn.get(k))

    # privacy_act
    pa = report.get("privacy_act", {})
    if not isinstance(pa, dict):
        report["privacy_act"] = {"overall_status": "Unknown", "apps_assessed": []}
        pa = report["privacy_act"]
    pa["overall_status"] = _s(pa.get("overall_status"), "Unknown")
    apps = pa.get("apps_assessed", [])
    if isinstance(apps, list):
        for app in apps:
            if isinstance(app, dict):
                for k in ("app", "status", "notes"):
                    app[k] = _s(app.get(k))

    # recommendations
    recs = report.get("recommendations", [])
    if isinstance(recs, list):
        for rec in recs:
            if isinstance(rec, dict):
                for k in ("priority", "action", "rationale", "framework_ref", "triggered_by"):
                    rec[k] = _s(rec.get(k))

    return report


def render_report(report: dict, company: str, domain: str = "", model: str = ""):
    console.print()
    risk  = report.get("overall_risk_rating", "UNKNOWN")
    score = report.get("risk_score", 0)
    rc    = RISK_STYLE.get(risk, "white")

    header = Text()
    header.append(f"  {company.upper()}  ",         style="bold white")
    header.append(f"│  {risk} RISK  ",              style=rc)
    header.append(f"│  Score {score}/10  ",          style="white")
    header.append(f"│  Confidence: {report.get('confidence', '?')}  ", style="dim")
    if domain:
        header.append(f"│  {domain}", style="dim")
    console.print(Panel(
        header,
        title=f"[bold]GRC Assessment Agent v0.2[/bold]  [dim]· Ollama · {model}[/dim]",
        subtitle=f"[dim]{report.get('assessment_date', '')} · Passive reconnaissance only[/dim]",
        border_style=rc,
    ))

    section("Executive Summary")
    console.print(f"  {report.get('executive_summary', '')}", style="white")
    console.print(f"\n  [dim]Data handled:[/dim]  {report.get('data_sensitivity', '')}")
    console.print(f"  [dim]Sources used:[/dim]  {', '.join(_s(x) for x in report.get('data_sources_used', []))}\n")

    tech = report.get("technical_summary", {})
    if tech:
        section("Technical Snapshot")
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        t.add_column("Key",   style="dim", width=20)
        t.add_column("Value", min_width=40)
        sg = tech.get("ssl_grade",     "Unknown")
        hg = tech.get("headers_grade", "Unknown")
        bc = int(tech.get("known_breaches") or 0)
        t.add_row("SSL Grade",     f"[{grade_style(sg)}]{sg}[/{grade_style(sg)}]")
        t.add_row("Headers Grade", f"[{grade_style(hg)}]{hg}[/{grade_style(hg)}]")
        t.add_row("Known Breaches",f"[{'red' if bc > 0 else 'green'}]{bc}[/]")
        vulns = tech.get("key_vulnerabilities", [])
        if vulns:
            t.add_row("Vulnerabilities", "[red]" + " · ".join(vulns) + "[/red]")
        console.print(t)

    findings = report.get("findings", [])
    if findings:
        section(f"Findings  ({len(findings)})")
        t = Table(box=box.SIMPLE, show_header=True, padding=(0, 1), expand=True)
        t.add_column("ID",       style="dim",  width=5)
        t.add_column("Severity",               width=10)
        t.add_column("Source",   style="dim",  width=14)
        t.add_column("Category", style="dim",  width=20)
        t.add_column("Finding",                min_width=28)
        for f in findings:
            sev = f.get("severity", "")
            t.add_row(
                f.get("id", ""),
                f"[{RISK_STYLE.get(sev, 'white')}]{sev}[/]",
                f.get("source", ""),
                f.get("category", ""),
                f.get("title", ""),
            )
        console.print(t)

        highs = [f for f in findings if f.get("severity") == "HIGH"]
        if highs:
            console.print("  [bold red]High severity — detail[/bold red]\n")
            for f in highs:
                console.print(f"  [bold]{f['id']}  {f['title']}[/bold]")
                console.print(f"  Observation: {f.get('observation', '')}", style="dim")
                console.print(f"  Risk:        {f.get('risk', '')}\n",       style="dim red")

    section("Essential Eight Maturity")
    e8_labels = {
        "patch_applications":         "Patch Applications",
        "patch_os":                   "Patch OS",
        "multi_factor_auth":          "MFA",
        "restrict_admin_privileges":  "Restrict Admin",
        "application_control":        "App Control",
        "restrict_macros":            "Restrict Macros",
        "user_application_hardening": "App Hardening",
        "regular_backups":            "Backups",
    }
    t = Table(box=box.SIMPLE, show_header=True, padding=(0, 1), expand=True)
    t.add_column("Control",  width=24)
    t.add_column("Maturity", width=18)
    t.add_column("Source",   style="dim", width=12)
    t.add_column("Notes",    min_width=28)
    for key, label in e8_labels.items():
        val = report.get("essential_eight", {}).get(key, {})
        t.add_row(label, maturity_bar(val.get("maturity", 0)),
                  val.get("source", ""), val.get("notes", ""))
    console.print(t)

    section("ISO 27001:2022")
    t = Table(box=box.SIMPLE, show_header=True, padding=(0, 1), expand=True)
    t.add_column("Clause", style="dim", width=7)
    t.add_column("Domain",              width=32)
    t.add_column("Status",              width=10)
    t.add_column("Notes",               min_width=25)
    for d in report.get("iso_27001", []):
        st = d.get("status", "Unknown")
        t.add_row(d.get("clause",""), d.get("domain",""),
                  f"[{STATUS_STYLE.get(st,'white')}]{st}[/]", d.get("notes",""))
    console.print(t)

    section("NIST CSF 2.0")
    t = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
    t.add_column("Function", width=12)
    t.add_column("Status",   width=10)
    t.add_column("Notes",    min_width=44)
    for fn in report.get("nist_csf", []):
        st = fn.get("status", "Unknown")
        t.add_row(fn.get("function",""),
                  f"[{STATUS_STYLE.get(st,'white')}]{st}[/]", fn.get("notes",""))
    console.print(t)

    section("Australian Privacy Act — APPs")
    pa = report.get("privacy_act", {})
    overall = pa.get("overall_status", "Unknown")
    console.print(f"  Overall: [{STATUS_STYLE.get(overall,'white')}]{overall}[/]\n")
    t = Table(box=box.SIMPLE, show_header=True, padding=(0, 1), expand=True)
    t.add_column("APP",    width=40)
    t.add_column("Status", width=10)
    t.add_column("Notes",  min_width=26)
    for app in pa.get("apps_assessed", []):
        st = app.get("status", "Unknown")
        t.add_row(app.get("app",""),
                  f"[{STATUS_STYLE.get(st,'white')}]{st}[/]", app.get("notes",""))
    console.print(t)

    recs = report.get("recommendations", [])
    if recs:
        section(f"Recommendations  ({len(recs)})")
        for i, rec in enumerate(recs, 1):
            p = rec.get("priority", "")
            console.print(f"  [{i}] [{RISK_STYLE.get(p,'white')}]{p}[/]  {rec.get('action','')}")
            console.print(f"       {rec.get('rationale','')}",   style="dim")
            console.print(f"       {rec.get('framework_ref','')}  ·  triggered by: {rec.get('triggered_by','')}\n",
                          style="dim")

    console.print(Panel(
        f"[dim]{report.get('limitations','')}\n\n"
        "Passive reconnaissance only — no active scanning. "
        "Findings are indicative and require human review before professional use. "
        "Not a substitute for authorised security assessment or legal advice.[/dim]",
        title="[dim]Disclaimer[/dim]",
        border_style="dim",
    ))


# ── MAIN ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="GRC Assessment Agent v0.2 — free, local, Ollama-powered",
        epilog=(
            "Examples:\n"
            "  python grc_agent_phase2.py 'Latitude Financial' --domain latitudefinancial.com.au\n"
            "  python grc_agent_phase2.py 'CBA' --domain commbank.com.au --doc policy.txt\n"
            "  python grc_agent_phase2.py 'ANZ' --domain anz.com.au --model mistral --no-ssl\n"
            "  python grc_agent_phase2.py 'Medibank' --output json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("company",            help='Company name  e.g. "Latitude Financial"')
    parser.add_argument("--domain",   "-d",   help="Domain to scan  e.g. latitudefinancial.com.au")
    parser.add_argument("--doc",      "-f",   help="Path to .txt document for analysis")
    parser.add_argument("--model",    "-m",   default=OLLAMA_MODEL,
                        help=f"Ollama model to use (default: {OLLAMA_MODEL})")
    parser.add_argument("--output",   "-o",   default="both",
                        choices=["terminal", "json", "both"])
    parser.add_argument("--no-ssl",           action="store_true")
    parser.add_argument("--no-headers",       action="store_true")
    parser.add_argument("--no-news",          action="store_true")
    parser.add_argument("--no-hibp",          action="store_true")
    parser.add_argument("--list-models",      action="store_true",
                        help="List available Ollama models and exit")
    args = parser.parse_args()

    console.print(Panel(
        f"[bold white]GRC Assessment Agent[/bold white]  "
        f"[dim]v0.2 · Phase 2 · Ollama / {args.model}[/dim]\n"
        "[dim]Free · Local · Passive recon · Australian frameworks[/dim]",
        border_style="blue",
    ))

    # Check Ollama
    ollama_status = check_ollama(args.model)

    if args.list_models:
        if not ollama_status.get("models"):
            console.print("[red]✗  Ollama not running or no models installed.[/red]")
            console.print("  Install: https://ollama.com")
        else:
            console.print("\n  [bold]Available models:[/bold]")
            for m in ollama_status["models"]:
                console.print(f"  → {m}")
            console.print("\n  Recommended for this task: llama3.1, mistral, gemma2, qwen2.5\n")
        sys.exit(0)

    if not ollama_status.get("ok"):
        err = ollama_status.get("error", "unknown error")
        if "not running" in err:
            console.print(f"\n[red]✗  Ollama is not running.[/red]")
            console.print("  → Install:    https://ollama.com")
            console.print("  → Start:      ollama serve")
            console.print(f"  → Pull model: ollama pull {args.model}\n")
        else:
            console.print(f"\n[red]✗  Model '{args.model}' not found in Ollama.[/red]")
            console.print(f"  → Run: ollama pull {args.model}")
            if ollama_status.get("models"):
                console.print(f"  → Available: {', '.join(ollama_status['models'])}")
        sys.exit(1)

    log("✓", f"Ollama running · model: [bold]{args.model}[/bold]", "green")

    # Load document
    doc_text = ""
    if args.doc:
        try:
            with open(args.doc, encoding="utf-8", errors="ignore") as fh:
                doc_text = fh.read()
            log("📄", f"Document: {args.doc}  ({len(doc_text):,} chars)")
        except FileNotFoundError:
            log("⚠", f"Document not found: {args.doc}", "yellow")

    # ── Intelligence gathering ──────────────────────────────────────────────
    section("Gathering intelligence")
    ssl_data = headers_data = news_data = hibp_data = None

    if args.domain:
        with ThreadPoolExecutor(max_workers=3) as ex:
            futures = {}

            if not args.no_headers:
                log("⟳", f"Security headers: {args.domain}...")
                futures["headers"] = ex.submit(check_security_headers, args.domain)

            if not args.no_hibp and HIBP_API_KEY:
                log("⟳", f"HIBP: {clean_domain(args.domain)}...")
                futures["hibp"] = ex.submit(check_hibp, args.domain)
            elif not args.no_hibp:
                log("○", "HIBP: skipped — add HIBP_API_KEY to .env for breach history", "dim")

            if not args.no_news and TAVILY_API_KEY:
                log("⟳", f"News: searching '{args.company}'...")
                futures["news"] = ex.submit(search_news, args.company)
            elif not args.no_news:
                log("○", "News: skipped — add TAVILY_API_KEY to .env for news intel", "dim")

            # SSL runs separately (slow, needs live feedback)
            if not args.no_ssl:
                log("⟳", f"SSL Labs: analysing {args.domain} — takes 60-90s...")
                ssl_data = check_ssl(args.domain)
                if "error" not in ssl_data:
                    log("✓", f"SSL Labs: [bold]{ssl_data.get('grade')}[/bold]", "green")
                else:
                    log("✗", f"SSL Labs: {ssl_data['error']}", "yellow")
            else:
                log("○", "SSL Labs: skipped (--no-ssl)", "dim")

            for name, fut in futures.items():
                try:
                    result = fut.result()
                    if name == "headers":
                        headers_data = result
                        if "error" not in result:
                            log("✓", f"Headers: [bold]{result.get('grade','?')}[/bold]", "green")
                        else:
                            log("✗", f"Headers: {result['error']}", "yellow")
                    elif name == "hibp":
                        hibp_data = result
                        if "error" not in result:
                            n = result.get("count", 0)
                            log("✓", f"HIBP: [{'red' if n else 'green'}]{n} breach(es)[/]",
                                "red" if n else "green")
                        else:
                            log("✗", f"HIBP: {result.get('error')}", "yellow")
                    elif name == "news":
                        news_data = result
                        if "error" not in result:
                            log("✓", f"News: {len(result.get('results',[]))} results", "green")
                        else:
                            log("✗", f"News: {result.get('error')}", "yellow")
                except Exception as e:
                    log("✗", f"{name}: {e}", "yellow")
    else:
        log("○", "No domain — skipping technical checks", "dim")
        if not args.no_news and TAVILY_API_KEY:
            log("⟳", f"News: searching '{args.company}'...")
            news_data = search_news(args.company)
            log("✓", f"News: {len((news_data or {}).get('results',[]))} results", "green")

    # ── AI analysis ────────────────────────────────────────────────────────
    section(f"Running AI analysis  [{args.model}]")
    log("⟳", "Sending to Ollama... (may take 30-120s depending on hardware)")

    user_msg = build_user_message(
        args.company, args.domain,
        ssl_data, headers_data, news_data, hibp_data, doc_text,
    )

    try:
        report = analyse_with_ollama(user_msg, args.model)
        report = sanitize_report(report)   # normalise all model output before rendering
    except (ConnectionError, ValueError) as e:
        console.print(f"\n[red]✗  {e}[/red]")
        sys.exit(1)

    report["assessment_date"] = datetime.now().strftime("%d %B %Y")
    report["_meta"] = {
        "company": args.company,
        "domain":  args.domain,
        "model":   args.model,
        "version": "0.2",
        "phase":   "Phase 2 — Ollama Multi-Source Intelligence",
    }
    log("✓", "Analysis complete", "green")

    # ── Output ─────────────────────────────────────────────────────────────
    if args.output in ("terminal", "both"):
        render_report(report, args.company, args.domain or "", args.model)

    if args.output in ("json", "both"):
        ts       = datetime.now().strftime("%Y%m%d_%H%M")
        slug     = args.company.lower().replace(" ", "_")
        filename = f"{slug}_grc_v02_{ts}.json"
        with open(filename, "w") as fh:
            json.dump(report, fh, indent=2)
        console.print(f"\n  [green]✓[/green]  Saved: [bold]{filename}[/bold]")
        console.print("  [dim]Pass this JSON to Phase 4 for PDF generation.[/dim]\n")


if __name__ == "__main__":
    main()
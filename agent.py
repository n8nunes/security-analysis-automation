#!/usr/bin/env python3
"""
GRC Assessment Agent — Phase 3
Two-pass AI analysis, ASX/OAIC intelligence, risk register, framework mapping

What's new in Phase 3:
  ✦ Two-pass Ollama analysis  — token-efficient; findings then frameworks
  ✦ ASX announcement scraper  — security disclosures and material events
  ✦ OAIC NDB search           — regulatory notifications and enforcement
  ✦ Formal risk register      — likelihood × impact (ASD/NIST aligned)
  ✦ ASD maturity criteria     — 0–4 definitions baked into prompt
  ✦ Per-finding confidence    — HIGH / MEDIUM / LOW evidence basis
  ✦ Contradiction detection   — document vs technical evidence
  ✦ Assessment metadata       — ref number, assessor, version

Dependencies:
    pip install requests python-dotenv rich beautifulsoup4 lxml

    beautifulsoup4 + lxml enable ASX and OAIC scrapers.
    All other features work without them.

Usage:
    python agent.py "Latitude Financial" --domain latitudefinancial.com.au --ticker LFS
    python agent.py "Medibank"  --domain medibank.com.au --doc policy.txt
    python agent.py "CBA"       --domain commbank.com.au --ticker CBA --output json
    python agent.py "ANZ"       --domain anz.com.au --assessor "J. Smith" --ref GRC-2025-001
"""

import os
import re
import sys
import time
import json
import uuid
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

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

load_dotenv()

# ── CONFIG ─────────────────────────────────────────────────────────────────────

OLLAMA_HOST    = os.getenv("OLLAMA_HOST",  "http://localhost:11434")
OLLAMA_MODEL   = os.getenv("OLLAMA_MODEL", "llama3.1")
TAVILY_API_KEY = os.getenv("TAVILY_API_KEY", "")
HIBP_API_KEY   = os.getenv("HIBP_API_KEY",   "")

SSL_POLL_INTERVAL = 10    # seconds between SSL Labs polls
SSL_MAX_WAIT      = 180   # seconds before giving up
USER_AGENT        = "GRC-Assessment-Agent/0.3 (passive-recon-only; portfolio)"
ASX_TIMEOUT       = 15
OAIC_TIMEOUT      = 15

console = Console()


# ── UTILITIES ──────────────────────────────────────────────────────────────────

def clean_domain(domain: str) -> str:
    return domain.replace("https://", "").replace("http://", "").split("/")[0].strip()

def log(icon: str, msg: str, style: str = "white"):
    console.print(f"  {icon}  {msg}", style=style)

def section(title: str):
    console.print(f"\n[bold white]{title}[/bold white]")
    console.print("─" * 60, style="dim")

def truncate(text: str, max_chars: int = 300) -> str:
    if not text:
        return ""
    text = text.strip()
    return text[:max_chars] + "…" if len(text) > max_chars else text

def gen_ref() -> str:
    ts    = datetime.now().strftime("%Y%m%d")
    short = str(uuid.uuid4())[:6].upper()
    return f"GRC-{ts}-{short}"


# ── OLLAMA HEALTH CHECK ────────────────────────────────────────────────────────

def check_ollama(model: str) -> dict:
    try:
        r = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=5)
        r.raise_for_status()
        available  = [m["name"].split(":")[0] for m in r.json().get("models", [])]
        model_base = model.split(":")[0]
        return {"ok": model_base in available, "models": available,
                "has_model": model_base in available}
    except requests.exceptions.ConnectionError:
        return {"ok": False, "models": [], "error": "Ollama not running"}
    except Exception as e:
        return {"ok": False, "models": [], "error": str(e)}


# ── DATA SOURCE 1: SSL LABS ────────────────────────────────────────────────────

def check_ssl(domain: str) -> dict:
    """
    Qualys SSL Labs — passive TLS/SSL assessment. Free, no key required.
    First scan takes 60–90 s; uses cached results when available.
    """
    host = clean_domain(domain)
    base = "https://api.ssllabs.com/api/v3"
    try:
        requests.get(f"{base}/analyze",
                     params={"host": host, "startNew": "on", "all": "on"},
                     headers={"User-Agent": USER_AGENT}, timeout=15)
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
                    "protocols":       [f"{p['name']} {p['version']}"
                                        for p in d.get("protocols", [])],
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
            log("  ", f"SSL Labs: still analysing… ({elapsed}s)", "dim")
        return {"error": f"Timed out after {SSL_MAX_WAIT}s"}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


# ── DATA SOURCE 2: SECURITY HEADERS ───────────────────────────────────────────

def check_security_headers(domain: str) -> dict:
    """
    SecurityHeaders.com + direct header probe. Free, no key required.
    """
    host = clean_domain(domain)
    grade = score = "Unknown"
    try:
        r = requests.get(
            "https://securityheaders.com/",
            params={"q": host, "followRedirects": "on", "hide": "on"},
            headers={"User-Agent": USER_AGENT},
            timeout=15, allow_redirects=True)
        raw_grade = r.headers.get("X-Grade", "Unknown")
        score     = r.headers.get("X-Score", "Unknown")
        valid_grades = {"A+", "A", "B", "C", "D", "E", "F"}
        grade = raw_grade if raw_grade in valid_grades else "Unknown"
        if raw_grade not in valid_grades and raw_grade != "Unknown":
            log("⚠", "Security headers grade unavailable — direct header check still ran",
                "yellow")
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

    wanted = [
        "Content-Security-Policy",   "Strict-Transport-Security",
        "X-Frame-Options",           "X-Content-Type-Options",
        "Referrer-Policy",           "Permissions-Policy",
        "Cross-Origin-Opener-Policy","Cross-Origin-Resource-Policy",
    ]
    present, missing = [], []
    try:
        site = requests.get(f"https://{host}",
                            headers={"User-Agent": USER_AGENT},
                            timeout=10, allow_redirects=True)
        lowered = {k.lower() for k in site.headers}
        for h in wanted:
            (present if h.lower() in lowered else missing).append(h)
    except Exception:
        pass
    return {"grade": grade, "score": score, "present": present, "missing": missing}


# ── DATA SOURCE 3: TAVILY NEWS ─────────────────────────────────────────────────

def search_news(company: str) -> dict:
    """
    Tavily AI-optimised search — recent security incidents.
    Set TAVILY_API_KEY in .env for free tier: https://tavily.com
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
            }, timeout=30)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


# ── DATA SOURCE 4: HAVE I BEEN PWNED ──────────────────────────────────────────

def check_hibp(domain: str) -> dict:
    """
    HIBP breach history for a domain.
    Set HIBP_API_KEY in .env — ~$4 AUD/month: https://haveibeenpwned.com/API/Key
    """
    if not HIBP_API_KEY:
        return {"skipped": True, "reason": "HIBP_API_KEY not set in .env"}
    host = clean_domain(domain)
    try:
        r = requests.get(
            "https://haveibeenpwned.com/api/v3/breaches",
            params={"domain": host},
            headers={"hibp-api-key": HIBP_API_KEY, "User-Agent": USER_AGENT},
            timeout=15)
        if r.status_code == 200:
            breaches = r.json()
            return {
                "count": len(breaches),
                "breaches": [
                    {"name": b["Name"], "date": b["BreachDate"],
                     "records": b["PwnCount"], "data_classes": b["DataClasses"][:6]}
                    for b in breaches
                ],
            }
        if r.status_code == 404:
            return {"count": 0, "breaches": []}
        return {"error": f"HTTP {r.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


# ── DATA SOURCE 5: ASX ANNOUNCEMENTS ──────────────────────────────────────────

def search_asx(company: str, ticker: str = None) -> dict:
    """
    ASX public announcements API — no key required, publicly listed data.
    Searches for cybersecurity-related disclosures using keyword matching.
    If no ticker is supplied, attempts to look one up by company name.
    """
    results = {
        "ticker":          ticker,
        "announcements":   [],
        "security_related":[],
        "total_scanned":   0,
        "security_count":  0,
    }

    security_keywords = {
        "cyber", "breach", "hack", "ransomware", "security incident",
        "data breach", "unauthorised access", "privacy", "data leak",
        "information security", "notifiable", "oaic", "malware",
        "phishing", "extortion", "credentials", "unauthorised",
    }

    # ── Ticker-based API ──────────────────────────────────────────────────
    if ticker:
        ticker = ticker.upper().strip()
        results["ticker"] = ticker
        try:
            r = requests.get(
                f"https://www.asx.com.au/asx/1/company/{ticker}/announcements",
                params={"count": 20, "market_sensitive": "false"},
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                timeout=ASX_TIMEOUT)
            if r.status_code == 200:
                items = r.json().get("data", [])
                for item in items:
                    title = (item.get("header") or "").lower()
                    ann   = {
                        "title":           item.get("header", ""),
                        "date":            item.get("document_date", ""),
                        "url":             "https://www.asx.com.au" + item.get("url", ""),
                        "price_sensitive": item.get("price_sensitive", False),
                    }
                    results["announcements"].append(ann)
                    if any(kw in title for kw in security_keywords):
                        results["security_related"].append(ann)
                results["total_scanned"] = len(items)
                results["security_count"] = len(results["security_related"])
                return results
            elif r.status_code == 404:
                results["note"] = f"Ticker {ticker} not found on ASX"
        except requests.exceptions.RequestException as e:
            results["ticker_error"] = str(e)

    # ── Company-name lookup fallback ──────────────────────────────────────
    try:
        r = requests.get(
            "https://www.asx.com.au/asx/1/search",
            params={"q": company},
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            timeout=ASX_TIMEOUT)
        if r.status_code == 200:
            found = r.json().get("data", {}).get("companies", [])
            if found:
                found_ticker = found[0].get("code", "")
                if found_ticker and found_ticker != ticker:
                    return search_asx(company, ticker=found_ticker)
        results["note"] = "Company not found on ASX — may be unlisted or private"
    except Exception as e:
        results["search_error"] = str(e)

    return results


# ── DATA SOURCE 6: OAIC NDB SEARCH ────────────────────────────────────────────

def search_oaic(company: str) -> dict:
    """
    Searches OAIC (Office of the Australian Information Commissioner) pages for
    Notifiable Data Breach records, privacy determinations, and enforcement actions.
    No key required — all publicly available content.
    Requires beautifulsoup4: pip install beautifulsoup4 lxml
    """
    if not BS4_AVAILABLE:
        return {"skipped": True,
                "reason": "beautifulsoup4 not installed — pip install beautifulsoup4 lxml"}

    results = {
        "mentions":           [],
        "ndb_found":          False,
        "enforcement_found":  False,
        "mention_count":      0,
    }

    company_lower = company.lower()
    search_targets = [
        ("https://www.oaic.gov.au/privacy/notifiable-data-breaches",
         "NDB Statistics"),
        ("https://www.oaic.gov.au/privacy/privacy-decisions",
         "Privacy Decisions"),
        ("https://www.oaic.gov.au/privacy/privacy-guidance-for-organisations-and-government-agencies",
         "OAIC Guidance"),
    ]

    for url, label in search_targets:
        try:
            r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=OAIC_TIMEOUT)
            if r.status_code != 200:
                continue
            # Try lxml first (faster), fall back to html.parser
            try:
                soup = BeautifulSoup(r.text, "lxml")
            except Exception:
                soup = BeautifulSoup(r.text, "html.parser")

            text  = soup.get_text(separator=" ", strip=True)
            lower = text.lower()

            if company_lower not in lower:
                continue

            # Extract a snippet of context around the mention
            idx     = lower.find(company_lower)
            snippet = text[max(0, idx - 120): idx + 200].strip()
            results["mentions"].append({
                "source":  label,
                "url":     url,
                "snippet": snippet,
            })
            if "notifiable data breach" in lower or "ndb" in lower:
                results["ndb_found"] = True
            if "determination" in lower or "penalty" in lower or "enforcement" in lower:
                results["enforcement_found"] = True

        except Exception:
            pass  # OAIC is informational — never block the pipeline

    results["mention_count"] = len(results["mentions"])
    return results


# ── TWO-PASS AI ANALYSIS ───────────────────────────────────────────────────────
#
# Pass 1 — Technical synthesis
#   Input:  raw recon data (SSL, headers, HIBP, news, ASX, OAIC, document)
#   Output: structured findings + technical summary
#   Size:   ~1 500 input tokens → ~600 output tokens
#
# Pass 2 — Framework mapping + risk register
#   Input:  Pass 1 output (compact JSON) — clean, no raw data noise
#   Output: Essential Eight, ISO 27001, NIST CSF, Privacy Act, risk register
#   Size:   ~700 input tokens → ~1 200 output tokens
#
# Why two passes?
#   Each call is half the size → faster inference, fewer hallucinations.
#   The model focuses on one job at a time.
#   Pass 2 works from structured findings, not messy raw data → better mapping.
#   Either pass can be retried independently if it fails.

# ── Pass 1 system prompt ──────────────────────────────────────────────────────

PASS1_SYSTEM = """\
You are a cybersecurity analyst extracting structured findings from passive reconnaissance data.

RULES:
- Output ONLY valid JSON. No preamble, no markdown, no explanation.
- Base every finding strictly on evidence provided. Do not infer beyond what is shown.
- confidence: HIGH = direct technical evidence | MEDIUM = indirect/partial | LOW = inference only
- severity: HIGH = exploitable now or data already exposed | MEDIUM = real risk, not immediate | LOW = hygiene gap | INFO = neutral observation
- contradiction: if the company document claims X but technical data shows not-X, set this field to a short description. Otherwise null.
- If a data source was skipped or errored, do not invent findings from it.

Respond with this exact JSON schema (no extra keys):
{
  "data_sensitivity": "one sentence — what personal, financial or health data this organisation handles",
  "executive_brief": "1-2 sentence synthesis of the most significant technical findings",
  "technical_summary": {
    "ssl_grade": "grade letter or Unknown",
    "headers_grade": "grade letter or Unknown",
    "known_breaches": 0,
    "key_vulnerabilities": ["list of confirmed vuln names, empty if none"]
  },
  "findings": [
    {
      "id": "F001",
      "source": "SSL|Headers|HIBP|News|ASX|OAIC|Document",
      "category": "Transport Security|Web Security|Breach History|Regulatory|Disclosure|Policy",
      "severity": "HIGH|MEDIUM|LOW|INFO",
      "confidence": "HIGH|MEDIUM|LOW",
      "title": "concise finding title",
      "observation": "exactly what was observed — evidence only, no inference",
      "risk": "what risk this creates for the organisation or for data subjects",
      "contradiction": null
    }
  ],
  "document_claims": ["list of specific security claims made in the provided document, or empty array"]
}"""


# ── Pass 2 system prompt ──────────────────────────────────────────────────────

PASS2_SYSTEM = """\
You are a senior GRC analyst mapping structured cybersecurity findings to Australian and international frameworks.

ESSENTIAL EIGHT MATURITY LEVELS (ASD ACSC — use these definitions exactly):
  0 = Not implemented, or no evidence exists to assess
  1 = Partially implemented, or implemented inconsistently
  2 = Implemented with some gaps, or cannot be verified
  3 = Substantially implemented; evidence-backed; broadly consistent
  4 = Fully implemented; continuously improved; strong documentary evidence
Default to 0 for any control that passive recon cannot observe.
Only assert 2–4 when a finding directly supports it.

RISK SCORE = likelihood (1–5) × impact (1–5)
Rating thresholds: Critical ≥ 16 | High ≥ 10 | Medium ≥ 6 | Low < 6

RULES:
- Output ONLY valid JSON. No preamble, no markdown, no explanation.
- Map only what the provided findings support. Unknown is correct when evidence is absent.
- triggered_by in recommendations must cite specific finding IDs (e.g. "F001, F003").
- finding_refs in risk_register must cite specific finding IDs.
- ISO and NIST status values: Evident | Apparent | Partial | Gap | Concern | Unknown

Respond with this exact JSON schema (no extra keys):
{
  "overall_risk_rating": "CRITICAL|HIGH|MEDIUM|LOW",
  "risk_score": 7.5,
  "confidence": "HIGH|MEDIUM|LOW",
  "essential_eight": {
    "patch_applications":         {"maturity": 0, "notes": "...", "source": "finding ID or None"},
    "patch_os":                   {"maturity": 0, "notes": "...", "source": "..."},
    "multi_factor_auth":          {"maturity": 0, "notes": "...", "source": "..."},
    "restrict_admin_privileges":  {"maturity": 0, "notes": "...", "source": "..."},
    "application_control":        {"maturity": 0, "notes": "...", "source": "..."},
    "restrict_macros":            {"maturity": 0, "notes": "...", "source": "..."},
    "user_application_hardening": {"maturity": 0, "notes": "...", "source": "..."},
    "regular_backups":            {"maturity": 0, "notes": "...", "source": "..."}
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
      {"app": "APP 1 - Open and transparent management",    "status": "Unknown", "notes": "..."},
      {"app": "APP 3 - Collection of personal information", "status": "Unknown", "notes": "..."},
      {"app": "APP 5 - Notification of collection",         "status": "Unknown", "notes": "..."},
      {"app": "APP 6 - Use and disclosure",                 "status": "Unknown", "notes": "..."},
      {"app": "APP 11 - Security of personal information",  "status": "Unknown", "notes": "..."},
      {"app": "APP 12 - Access to personal information",    "status": "Unknown", "notes": "..."}
    ]
  },
  "risk_register": [
    {
      "id": "R001",
      "finding_refs": ["F001"],
      "description": "concise risk description",
      "category": "Confidentiality|Integrity|Availability|Compliance",
      "likelihood": 3,
      "impact": 4,
      "risk_score": 12,
      "risk_rating": "HIGH",
      "treatment": "Mitigate|Accept|Transfer|Avoid",
      "recommended_action": "specific, actionable step"
    }
  ],
  "recommendations": [
    {
      "priority": "HIGH|MEDIUM|LOW",
      "action": "action title",
      "rationale": "why this matters — impact if not addressed",
      "framework_ref": "Essential Eight — MFA Level 2",
      "triggered_by": "F001, F002"
    }
  ],
  "limitations": "brief note on what passive recon cannot determine for this organisation"
}"""


# ── Core Ollama call ──────────────────────────────────────────────────────────

def _call_ollama(system: str, user_msg: str, model: str, timeout: int = 300) -> dict:
    """
    Shared Ollama call used by both analysis passes.
    Forces JSON output at very low temperature for deterministic structured output.
    Raises ConnectionError or ValueError on failure.
    """
    try:
        r = requests.post(
            f"{OLLAMA_HOST}/api/chat",
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user",   "content": user_msg},
                ],
                "stream": False,
                "format": "json",
                "options": {
                    "temperature": 0.05,  # Near-deterministic structured output
                    "num_ctx":     6144,  # Sufficient for focused single-job passes
                    "top_p":       0.9,
                },
            },
            timeout=timeout,
        )
        r.raise_for_status()
    except requests.exceptions.ConnectionError:
        raise ConnectionError(
            f"Cannot connect to Ollama at {OLLAMA_HOST}.\n"
            f"  → Install:    https://ollama.com\n"
            f"  → Pull model: ollama pull {model}\n"
            "  → Start:     ollama serve"
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
        # Last-resort: extract the outermost JSON object from surrounding text
        start = content.find("{")
        end   = content.rfind("}") + 1
        if start != -1 and end > start:
            try:
                return json.loads(content[start:end])
            except json.JSONDecodeError:
                pass
        raise ValueError(
            f"Model did not return valid JSON: {e}\n"
            f"Raw output (first 500 chars):\n{content[:500]}"
        )


# ── Pass 1 message builder ────────────────────────────────────────────────────

def build_pass1_message(company, domain, ssl_data, headers_data,
                         news_data, hibp_data, asx_data, oaic_data, doc_text) -> str:
    """
    Compress all raw recon data into a token-efficient format for Pass 1.
    Every section is kept compact — the model doesn't need prose, it needs facts.
    """
    parts = [
        f"Company: {company}",
        f"Domain:  {domain or 'not provided'}",
        f"Date:    {datetime.now().strftime('%d %B %Y')}",
        "",
    ]

    # SSL
    if ssl_data and "error" not in ssl_data:
        vulns = []
        if ssl_data.get("heartbleed"): vulns.append("Heartbleed")
        if ssl_data.get("poodle_tls"): vulns.append("POODLE-TLS")
        if ssl_data.get("beast"):      vulns.append("BEAST")
        parts.append(
            f"SSL: grade={ssl_data.get('grade','?')} warnings={ssl_data.get('has_warnings',False)} "
            f"HSTS={ssl_data.get('hsts_status','?')} "
            f"forward_secrecy={ssl_data.get('forward_secrecy','?')} "
            f"protocols=[{','.join(ssl_data.get('protocols',[]))}] "
            f"cert_expiry={ssl_data.get('cert_expiry','?')} "
            f"confirmed_vulns=[{','.join(vulns) or 'none'}]"
        )
    elif ssl_data:
        parts.append(f"SSL: ERROR — {ssl_data.get('error')}")
    else:
        parts.append("SSL: not collected")

    # Headers
    if headers_data and "error" not in headers_data:
        parts.append(
            f"HEADERS: grade={headers_data.get('grade','?')} "
            f"present=[{','.join(headers_data.get('present',[]))}] "
            f"missing=[{','.join(headers_data.get('missing',[]))}]"
        )
    elif headers_data:
        parts.append(f"HEADERS: ERROR — {headers_data.get('error')}")
    else:
        parts.append("HEADERS: not collected")

    # HIBP
    if hibp_data and not hibp_data.get("skipped") and "error" not in hibp_data:
        count = hibp_data.get("count", 0)
        parts.append(f"HIBP: breach_count={count}")
        for b in hibp_data.get("breaches", [])[:4]:
            parts.append(
                f"  BREACH: name={b['name']} date={b['date']} "
                f"records={b['records']:,} types=[{','.join(b['data_classes'][:4])}]"
            )
    elif hibp_data and hibp_data.get("skipped"):
        parts.append("HIBP: skipped (no API key)")
    else:
        parts.append("HIBP: not collected")

    # News (max 3 results to save tokens)
    if news_data and not news_data.get("skipped") and "error" not in news_data:
        if news_data.get("answer"):
            parts.append(f"NEWS_SUMMARY: {truncate(news_data['answer'], 350)}")
        for item in (news_data.get("results", []) or [])[:3]:
            parts.append(
                f"NEWS: {item.get('title','')} | {truncate(item.get('content',''), 180)}"
            )
    elif news_data and news_data.get("skipped"):
        parts.append("NEWS: skipped (no API key)")
    else:
        parts.append("NEWS: not collected")

    # ASX
    if asx_data:
        if asx_data.get("skipped") or asx_data.get("note"):
            parts.append(f"ASX: {asx_data.get('note','not listed / no ticker provided')}")
        else:
            sc = asx_data.get("security_count", 0)
            parts.append(
                f"ASX: ticker={asx_data.get('ticker','?')} "
                f"announcements_scanned={asx_data.get('total_scanned',0)} "
                f"security_related={sc}"
            )
            for ann in asx_data.get("security_related", [])[:3]:
                parts.append(
                    f"  ASX_ANN: date={ann.get('date','')} "
                    f"price_sensitive={ann.get('price_sensitive',False)} "
                    f"title={ann.get('title','')}"
                )
    else:
        parts.append("ASX: not collected")

    # OAIC
    if oaic_data:
        if oaic_data.get("skipped"):
            parts.append("OAIC: skipped (beautifulsoup4 not installed)")
        elif oaic_data.get("mention_count", 0) > 0:
            parts.append(
                f"OAIC: mentions={oaic_data['mention_count']} "
                f"ndb_context={oaic_data.get('ndb_found',False)} "
                f"enforcement={oaic_data.get('enforcement_found',False)}"
            )
            for m in oaic_data.get("mentions", [])[:2]:
                parts.append(f"  OAIC_SNIPPET [{m['source']}]: {truncate(m['snippet'], 200)}")
        else:
            parts.append("OAIC: searched — no mentions found")
    else:
        parts.append("OAIC: not collected")

    # Document (hard-truncated to keep tokens manageable)
    if doc_text and doc_text.strip():
        parts.append(f"\nDOCUMENT (truncated to 4 000 chars):\n{doc_text.strip()[:4000]}")
    else:
        parts.append("\nDOCUMENT: not provided")

    return "\n".join(parts)


# ── Pass 2 message builder ────────────────────────────────────────────────────

def build_pass2_message(pass1: dict) -> str:
    """
    Compress Pass 1 output into a clean, minimal input for Pass 2.
    Findings become single-line strings so Pass 2 can focus purely on mapping.
    """
    findings_compact = []
    for f in pass1.get("findings", []):
        line = (
            f"{f.get('id','?')} "
            f"[{f.get('severity','?')}/{f.get('confidence','?')}] "
            f"src={f.get('source','?')} "
            f"cat={f.get('category','?')} — "
            f"{f.get('title','')} | "
            f"obs: {f.get('observation','')} | "
            f"risk: {f.get('risk','')} | "
            f"contradiction: {f.get('contradiction') or 'none'}"
        )
        findings_compact.append(line)

    payload = {
        "data_sensitivity":  pass1.get("data_sensitivity", ""),
        "executive_brief":   pass1.get("executive_brief", ""),
        "technical_summary": pass1.get("technical_summary", {}),
        "document_claims":   pass1.get("document_claims", []),
        "findings":          findings_compact,
    }
    # Compact JSON (no indentation) to save tokens
    return json.dumps(payload, separators=(",", ":"))


# ── Two-pass orchestrator ─────────────────────────────────────────────────────

def analyse_two_pass(company, domain, ssl_data, headers_data, news_data,
                      hibp_data, asx_data, oaic_data, doc_text, model) -> dict:
    """
    Runs Pass 1 (technical findings) then Pass 2 (framework mapping).
    If Pass 2 fails the partial Pass 1 output is returned with empty framework sections
    so the report still renders cleanly.
    """
    # ── Pass 1: technical findings ────────────────────────────────────────
    log("⟳", "Pass 1 — extracting technical findings…", "cyan")
    p1_msg = build_pass1_message(
        company, domain, ssl_data, headers_data,
        news_data, hibp_data, asx_data, oaic_data, doc_text,
    )
    pass1 = _call_ollama(PASS1_SYSTEM, p1_msg, model, timeout=300)
    finding_count = len(pass1.get("findings", []))
    log("✓", f"Pass 1 complete — {finding_count} finding(s) extracted", "green")

    # ── Pass 2: framework mapping ─────────────────────────────────────────
    log("⟳", "Pass 2 — framework mapping + risk register…", "cyan")
    p2_msg = build_pass2_message(pass1)
    pass2: dict = {}
    try:
        pass2 = _call_ollama(PASS2_SYSTEM, p2_msg, model, timeout=300)
        log("✓", "Pass 2 complete — frameworks mapped", "green")
    except (ConnectionError, ValueError) as e:
        log("⚠", f"Pass 2 failed — report will show findings only. Error: {e}", "yellow")

    # ── Merge into final report ───────────────────────────────────────────
    return {
        # From Pass 1
        "data_sensitivity": pass1.get("data_sensitivity", ""),
        "executive_summary": pass1.get("executive_brief", ""),
        "technical_summary": pass1.get("technical_summary", {}),
        "findings":          pass1.get("findings", []),
        "document_claims":   pass1.get("document_claims", []),
        "data_sources_used": _infer_sources(
            ssl_data, headers_data, news_data,
            hibp_data, asx_data, oaic_data, doc_text,
        ),
        # From Pass 2 (empty dicts/lists if pass2 failed)
        "overall_risk_rating": pass2.get("overall_risk_rating", "UNKNOWN"),
        "risk_score":          pass2.get("risk_score", 0.0),
        "confidence":          pass2.get("confidence", "LOW"),
        "essential_eight":     pass2.get("essential_eight", {}),
        "iso_27001":           pass2.get("iso_27001", []),
        "nist_csf":            pass2.get("nist_csf", []),
        "privacy_act":         pass2.get("privacy_act", {}),
        "risk_register":       pass2.get("risk_register", []),
        "recommendations":     pass2.get("recommendations", []),
        "limitations":         pass2.get("limitations",
                                         "Passive reconnaissance only — no active scanning."),
        "assessed_by":         f"GRC Assessment Agent v0.3 (Phase 3 — {model})",
    }


def _infer_sources(ssl_data, headers_data, news_data,
                    hibp_data, asx_data, oaic_data, doc_text) -> list:
    sources = []
    if ssl_data and "error" not in ssl_data:                    sources.append("SSL Labs")
    if headers_data and "error" not in headers_data:            sources.append("Security Headers")
    if news_data and not news_data.get("skipped"):              sources.append("News Intelligence")
    if hibp_data and not hibp_data.get("skipped"):              sources.append("HIBP")
    if asx_data  and not asx_data.get("skipped"):               sources.append("ASX Announcements")
    if oaic_data and not oaic_data.get("skipped"):              sources.append("OAIC Records")
    if doc_text  and doc_text.strip():                          sources.append("Document Analysis")
    return sources


# ── SANITIZE ───────────────────────────────────────────────────────────────────

def _s(v, fallback: str = "") -> str:
    """Safely coerce any model-returned value to a non-None string."""
    if v is None:
        return fallback
    if isinstance(v, dict):
        for key in ("name", "type", "title", "description", "value", "text"):
            if key in v:
                return str(v[key])
        return str(v)
    return str(v)


def sanitize_report(report: dict) -> dict:
    """
    Normalise every field before rendering.
    Local models can return wrong types (dict where str expected, None, etc).
    This pass makes the renderer crash-proof regardless of model behaviour.
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

    # Lists of strings
    for key in ("data_sources_used", "document_claims"):
        val = report.get(key, [])
        report[key] = [_s(x) for x in val] if isinstance(val, list) else []

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
    tech["key_vulnerabilities"] = [_s(v) for v in vulns] if isinstance(vulns, list) else []

    # findings — now includes confidence and contradiction
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        report["findings"] = []
    else:
        for f in findings:
            if isinstance(f, dict):
                for k in ("id", "source", "category", "severity", "confidence",
                          "title", "observation", "risk"):
                    f[k] = _s(f.get(k))
                if "contradiction" not in f:
                    f["contradiction"] = None

    # essential_eight — maturity clamped 0–4
    e8 = report.get("essential_eight", {})
    if not isinstance(e8, dict):
        report["essential_eight"] = {}
        e8 = report["essential_eight"]
    for ctrl, val in e8.items():
        if not isinstance(val, dict):
            e8[ctrl] = {"maturity": 0, "notes": "", "source": ""}
            val = e8[ctrl]
        try:
            val["maturity"] = max(0, min(4, int(val.get("maturity") or 0)))
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

    # risk_register (new in Phase 3)
    rr = report.get("risk_register", [])
    if not isinstance(rr, list):
        report["risk_register"] = []
    else:
        for r in rr:
            if isinstance(r, dict):
                for k in ("id", "description", "category",
                          "risk_rating", "treatment", "recommended_action"):
                    r[k] = _s(r.get(k))
                for k in ("likelihood", "impact", "risk_score"):
                    try:
                        r[k] = int(r.get(k) or 0)
                    except (TypeError, ValueError):
                        r[k] = 0
                refs = r.get("finding_refs", [])
                r["finding_refs"] = [_s(x) for x in refs] if isinstance(refs, list) else []

    # recommendations
    recs = report.get("recommendations", [])
    if isinstance(recs, list):
        for rec in recs:
            if isinstance(rec, dict):
                for k in ("priority", "action", "rationale", "framework_ref", "triggered_by"):
                    rec[k] = _s(rec.get(k))

    return report


# ── TERMINAL RENDERING ─────────────────────────────────────────────────────────

RISK_STYLE = {
    "CRITICAL": "bold magenta",
    "HIGH":     "bold red",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold green",
}
STATUS_STYLE = {
    "Evident": "green", "Apparent": "green", "Compliant": "green",
    "Partial": "yellow",
    "Gap": "red", "Concern": "red", "Non-Compliant": "red",
    "Unknown": "dim",
}


def grade_style(g: str) -> str:
    if not g or g == "Unknown":    return "dim"
    if g.upper().startswith("A"):  return "green"
    if g.upper() == "B":           return "yellow"
    if g.upper() == "C":           return "dark_orange"
    return "red"


def maturity_bar(level) -> str:
    try:
        level = max(0, min(4, int(level)))
    except (TypeError, ValueError):
        level = 0
    if level == 0:
        return "[dim]·  ·  ·  ·  ML0[/dim]"
    color = "green" if level >= 3 else "yellow" if level == 2 else "red"
    return f"[{color}]{'█' * level}{'░' * (4 - level)}  ML{level}[/{color}]"


def risk_score_color(score: int) -> str:
    if score >= 16: return "bold magenta"
    if score >= 10: return "bold red"
    if score >= 6:  return "bold yellow"
    return "bold green"


def render_report(report: dict, company: str, domain: str = "",
                  model: str = "", ref: str = "", assessor: str = ""):
    console.print()
    risk  = report.get("overall_risk_rating", "UNKNOWN")
    score = report.get("risk_score", 0)
    rc    = RISK_STYLE.get(risk, "white")

    # ── Header panel ──────────────────────────────────────────────────────
    header = Text()
    header.append(f"  {company.upper()}  ",       style="bold white")
    header.append(f"│  {risk} RISK  ",             style=rc)
    header.append(f"│  Score {score}/10  ",        style="white")
    header.append(f"│  Confidence: {report.get('confidence','?')}  ", style="dim")
    if domain:
        header.append(f"│  {domain}", style="dim")
    console.print(Panel(
        header,
        title=f"[bold]GRC Assessment Report[/bold]  [dim]v0.3 · {model}[/dim]",
        subtitle=(
            f"[dim]Ref: {ref}  ·  "
            f"{report.get('assessment_date','')}  ·  "
            f"Assessor: {assessor or 'not specified'}  ·  "
            "Passive reconnaissance only[/dim]"
        ),
        border_style=rc,
    ))

    # ── Executive Summary ─────────────────────────────────────────────────
    section("Executive Summary")
    console.print(f"  {report.get('executive_summary','')}", style="white")
    console.print(f"\n  [dim]Data handled:[/dim]  {report.get('data_sensitivity','')}")
    console.print(
        f"  [dim]Sources used:[/dim]  "
        f"{', '.join(_s(x) for x in report.get('data_sources_used',[]))}\n"
    )

    # ── Document claims ───────────────────────────────────────────────────
    claims = [c for c in report.get("document_claims", []) if c.strip()]
    if claims:
        section("Published Security Claims (from document)")
        for c in claims:
            console.print(f"  [dim]·[/dim] {c}")

    # ── Technical Snapshot ────────────────────────────────────────────────
    tech = report.get("technical_summary", {})
    if tech:
        section("Technical Snapshot")
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        t.add_column("Key",   style="dim", width=22)
        t.add_column("Value", min_width=40)
        sg = tech.get("ssl_grade",     "Unknown")
        hg = tech.get("headers_grade", "Unknown")
        bc = int(tech.get("known_breaches") or 0)
        t.add_row("SSL Grade",      f"[{grade_style(sg)}]{sg}[/{grade_style(sg)}]")
        t.add_row("Headers Grade",  f"[{grade_style(hg)}]{hg}[/{grade_style(hg)}]")
        t.add_row("Known Breaches", f"[{'red' if bc > 0 else 'green'}]{bc}[/]")
        vulns = tech.get("key_vulnerabilities", [])
        if vulns:
            t.add_row("Vulnerabilities", "[red]" + " · ".join(vulns) + "[/red]")
        console.print(t)

    # ── Findings ──────────────────────────────────────────────────────────
    findings = report.get("findings", [])
    if findings:
        section(f"Findings  ({len(findings)})")
        t = Table(box=box.SIMPLE, show_header=True, padding=(0, 1), expand=True)
        t.add_column("ID",       style="dim", width=5)
        t.add_column("Sev",                   width=8)
        t.add_column("Conf",     style="dim", width=7)
        t.add_column("Source",   style="dim", width=12)
        t.add_column("Category", style="dim", width=18)
        t.add_column("Finding",               min_width=28)
        for f in findings:
            sev  = f.get("severity",   "")
            conf = f.get("confidence", "")
            t.add_row(
                f.get("id", ""),
                f"[{RISK_STYLE.get(sev, 'white')}]{sev}[/]",
                f"[dim]{conf}[/dim]",
                f.get("source",   ""),
                f.get("category", ""),
                f.get("title",    ""),
            )
        console.print(t)

        # Detailed view for HIGH findings
        highs = [f for f in findings if f.get("severity") == "HIGH"]
        if highs:
            console.print("  [bold red]High severity — detail[/bold red]\n")
            for f in highs:
                console.print(f"  [bold]{f.get('id','')}  {f.get('title','')}[/bold]")
                console.print(f"  Observation: {f.get('observation','')}", style="dim")
                console.print(f"  Risk:        {f.get('risk','')}", style="dim red")
                if f.get("contradiction"):
                    console.print(
                        f"  ⚠ Contradiction: {f['contradiction']}", style="bold yellow"
                    )
                console.print()

    # ── Risk Register (new in Phase 3) ────────────────────────────────────
    rr = report.get("risk_register", [])
    if rr:
        section(f"Risk Register  ({len(rr)} risks)")
        t = Table(box=box.SIMPLE, show_header=True, padding=(0, 1), expand=True)
        t.add_column("ID",        style="dim",   width=5)
        t.add_column("Rating",                   width=10)
        t.add_column("Score",                    width=6)
        t.add_column("L×I",       style="dim",   width=5)
        t.add_column("Category",  style="dim",   width=16)
        t.add_column("Description",              min_width=30)
        t.add_column("Treatment", style="dim",   width=10)
        for r in rr:
            rs     = r.get("risk_score", 0)
            rating = r.get("risk_rating", "")
            t.add_row(
                r.get("id", ""),
                f"[{RISK_STYLE.get(rating.upper(), 'white')}]{rating}[/]",
                f"[{risk_score_color(rs)}]{rs}[/]",
                f"{r.get('likelihood','?')}×{r.get('impact','?')}",
                r.get("category", ""),
                r.get("description", ""),
                r.get("treatment", ""),
            )
        console.print(t)

        # Expanded detail for Critical / High
        crit_high = [
            r for r in rr
            if r.get("risk_rating", "").upper() in ("CRITICAL", "HIGH")
        ]
        if crit_high:
            console.print("  [bold red]Critical / High risks — actions[/bold red]\n")
            for r in crit_high:
                refs = ", ".join(r.get("finding_refs", []))
                console.print(f"  [bold]{r.get('id','')}[/bold]  {r.get('description','')}")
                console.print(f"  Action:       {r.get('recommended_action','')}", style="dim")
                if refs:
                    console.print(f"  Triggered by: {refs}", style="dim")
                console.print()

    # ── Essential Eight ───────────────────────────────────────────────────
    section("Essential Eight Maturity  (ASD ACSC)")
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
    t.add_column("Evidence", style="dim", width=12)
    t.add_column("Notes",    min_width=28)
    for key, label in e8_labels.items():
        val = report.get("essential_eight", {}).get(key, {})
        t.add_row(
            label,
            maturity_bar(val.get("maturity", 0)),
            val.get("source", ""),
            val.get("notes",  ""),
        )
    console.print(t)

    # ── ISO 27001 ─────────────────────────────────────────────────────────
    section("ISO 27001:2022")
    t = Table(box=box.SIMPLE, show_header=True, padding=(0, 1), expand=True)
    t.add_column("Clause", style="dim", width=7)
    t.add_column("Domain",              width=32)
    t.add_column("Status",              width=13)
    t.add_column("Notes",               min_width=24)
    for d in report.get("iso_27001", []):
        st = d.get("status", "Unknown")
        t.add_row(
            d.get("clause", ""),
            d.get("domain", ""),
            f"[{STATUS_STYLE.get(st, 'white')}]{st}[/]",
            d.get("notes",  ""),
        )
    console.print(t)

    # ── NIST CSF ──────────────────────────────────────────────────────────
    section("NIST CSF 2.0")
    t = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
    t.add_column("Function", width=12)
    t.add_column("Status",   width=13)
    t.add_column("Notes",    min_width=44)
    for fn in report.get("nist_csf", []):
        st = fn.get("status", "Unknown")
        t.add_row(
            fn.get("function", ""),
            f"[{STATUS_STYLE.get(st, 'white')}]{st}[/]",
            fn.get("notes", ""),
        )
    console.print(t)

    # ── Privacy Act APPs ──────────────────────────────────────────────────
    section("Australian Privacy Act — APPs")
    pa = report.get("privacy_act", {})
    overall = pa.get("overall_status", "Unknown")
    console.print(f"  Overall: [{STATUS_STYLE.get(overall,'white')}]{overall}[/]\n")
    t = Table(box=box.SIMPLE, show_header=True, padding=(0, 1), expand=True)
    t.add_column("APP",    width=42)
    t.add_column("Status", width=12)
    t.add_column("Notes",  min_width=24)
    for app in pa.get("apps_assessed", []):
        st = app.get("status", "Unknown")
        t.add_row(
            app.get("app", ""),
            f"[{STATUS_STYLE.get(st, 'white')}]{st}[/]",
            app.get("notes", ""),
        )
    console.print(t)

    # ── Recommendations ───────────────────────────────────────────────────
    recs = report.get("recommendations", [])
    if recs:
        section(f"Recommendations  ({len(recs)})")
        for i, rec in enumerate(recs, 1):
            p = rec.get("priority", "")
            console.print(
                f"  [{i}] [{RISK_STYLE.get(p, 'white')}]{p}[/]  {rec.get('action','')}"
            )
            console.print(f"       {rec.get('rationale','')}",   style="dim")
            console.print(
                f"       {rec.get('framework_ref','')}  ·  "
                f"triggered by: {rec.get('triggered_by','')}\n",
                style="dim",
            )

    # ── Disclaimer ────────────────────────────────────────────────────────
    console.print(Panel(
        f"[dim]{report.get('limitations','')}\n\n"
        "Passive reconnaissance only — no active scanning was performed. "
        "Findings are indicative and require human review before professional or client use. "
        "This report is not a substitute for authorised penetration testing, "
        "legal advice, or a formal compliance audit.[/dim]",
        title="[dim]Disclaimer & Limitations[/dim]",
        border_style="dim",
    ))


# ── MAIN ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="GRC Assessment Agent v0.3 — Phase 3: framework mapping + risk register",
        epilog=(
            "Examples:\n"
            "  python agent.py 'Latitude Financial' --domain latitudefinancial.com.au --ticker LFS\n"
            "  python agent.py 'Medibank' --domain medibank.com.au --doc policy.txt\n"
            "  python agent.py 'CBA' --domain commbank.com.au --ticker CBA --output json\n"
            "  python agent.py 'ANZ' --domain anz.com.au --assessor 'J. Smith'\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("company",             help='Company name e.g. "Latitude Financial"')
    parser.add_argument("--domain",    "-d",   help="Domain to scan e.g. latitudefinancial.com.au")
    parser.add_argument("--ticker",    "-t",   help="ASX ticker e.g. LFS  (enables announcement search)")
    parser.add_argument("--doc",       "-f",   help="Path to .txt document for analysis")
    parser.add_argument("--model",     "-m",   default=OLLAMA_MODEL,
                        help=f"Ollama model (default: {OLLAMA_MODEL})")
    parser.add_argument("--output",    "-o",   default="both",
                        choices=["terminal", "json", "both"])
    parser.add_argument("--assessor",          default="",
                        help="Assessor name for report metadata")
    parser.add_argument("--ref",               default="",
                        help="Assessment reference number (auto-generated if omitted)")
    parser.add_argument("--no-ssl",            action="store_true")
    parser.add_argument("--no-headers",        action="store_true")
    parser.add_argument("--no-news",           action="store_true")
    parser.add_argument("--no-hibp",           action="store_true")
    parser.add_argument("--no-asx",            action="store_true",
                        help="Skip ASX announcement search")
    parser.add_argument("--no-oaic",           action="store_true",
                        help="Skip OAIC NDB search")
    parser.add_argument("--list-models",       action="store_true",
                        help="List available Ollama models and exit")
    args = parser.parse_args()

    ref = args.ref or gen_ref()

    console.print(Panel(
        f"[bold white]GRC Assessment Agent[/bold white]  "
        f"[dim]v0.3 · Phase 3 · {args.model}[/dim]\n"
        f"[dim]Ref: {ref}  ·  Two-pass AI  ·  ASX + OAIC  ·  "
        "Passive recon · Australian frameworks[/dim]",
        border_style="blue",
    ))

    # Ollama check
    ollama_status = check_ollama(args.model)

    if args.list_models:
        if not ollama_status.get("models"):
            console.print("[red]✗  Ollama not running or no models installed.[/red]")
            console.print("  Install: https://ollama.com")
        else:
            console.print("\n  [bold]Available models:[/bold]")
            for m in ollama_status["models"]:
                console.print(f"  → {m}")
            console.print("\n  Recommended: llama3.1, mistral, gemma2, qwen2.5\n")
        sys.exit(0)

    if not ollama_status.get("ok"):
        err = ollama_status.get("error", "unknown error")
        if "not running" in err:
            console.print("[red]✗  Ollama is not running.[/red]")
            console.print("  → Install:    https://ollama.com")
            console.print("  → Start:      ollama serve")
            console.print(f"  → Pull model: ollama pull {args.model}")
        else:
            console.print(f"[red]✗  Model '{args.model}' not found in Ollama.[/red]")
            console.print(f"  → Run: ollama pull {args.model}")
            if ollama_status.get("models"):
                console.print(f"  → Available: {', '.join(ollama_status['models'])}")
        sys.exit(1)

    log("✓", f"Ollama running · model: [bold]{args.model}[/bold]", "green")

    if not BS4_AVAILABLE:
        log("⚠",
            "beautifulsoup4 not installed — ASX/OAIC scrapers disabled  "
            "(pip install beautifulsoup4 lxml)", "yellow")

    # Load optional document
    doc_text = ""
    if args.doc:
        try:
            with open(args.doc, encoding="utf-8", errors="ignore") as fh:
                doc_text = fh.read()
            log("📄", f"Document: {args.doc}  ({len(doc_text):,} chars)")
        except FileNotFoundError:
            log("⚠", f"Document not found: {args.doc}", "yellow")

    # ── Intelligence gathering ─────────────────────────────────────────────
    section("Gathering intelligence")
    ssl_data = headers_data = news_data = hibp_data = None
    asx_data = oaic_data = None

    # Functions to run in parallel (everything except SSL, which needs live feedback)
    def _collect_parallel(has_domain: bool):
        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = {}

            if has_domain and not args.no_headers:
                log("⟳", f"Security headers: {args.domain}…")
                futures["headers"] = ex.submit(check_security_headers, args.domain)

            if has_domain and not args.no_hibp and HIBP_API_KEY:
                log("⟳", f"HIBP: {clean_domain(args.domain)}…")
                futures["hibp"] = ex.submit(check_hibp, args.domain)
            elif not args.no_hibp:
                log("○", "HIBP: skipped — add HIBP_API_KEY to .env", "dim")

            if not args.no_news and TAVILY_API_KEY:
                log("⟳", f"News: '{args.company}'…")
                futures["news"] = ex.submit(search_news, args.company)
            elif not args.no_news:
                log("○", "News: skipped — add TAVILY_API_KEY to .env", "dim")

            if not args.no_asx:
                log("⟳", f"ASX: {args.ticker or args.company}…")
                futures["asx"] = ex.submit(search_asx, args.company, args.ticker)

            if not args.no_oaic and BS4_AVAILABLE:
                log("⟳", f"OAIC: '{args.company}'…")
                futures["oaic"] = ex.submit(search_oaic, args.company)
            elif not args.no_oaic:
                log("○", "OAIC: skipped (install beautifulsoup4)", "dim")

            results = {}
            for name, fut in futures.items():
                try:
                    results[name] = fut.result()
                except Exception as e:
                    log("✗", f"{name}: {e}", "yellow")
                    results[name] = None
            return results

    if args.domain:
        # SSL runs separately so we can stream progress messages
        if not args.no_ssl:
            log("⟳", f"SSL Labs: {args.domain} — takes 60–90 s…")
            ssl_data = check_ssl(args.domain)
            if "error" not in ssl_data:
                log("✓", f"SSL Labs: [bold]{ssl_data.get('grade')}[/bold]", "green")
            else:
                log("✗", f"SSL Labs: {ssl_data['error']}", "yellow")
        else:
            log("○", "SSL Labs: skipped (--no-ssl)", "dim")

        collected = _collect_parallel(has_domain=True)
    else:
        log("○", "No domain — skipping SSL / headers / HIBP", "dim")
        collected = _collect_parallel(has_domain=False)

    headers_data = collected.get("headers")
    hibp_data    = collected.get("hibp")
    news_data    = collected.get("news")
    asx_data     = collected.get("asx")
    oaic_data    = collected.get("oaic")

    # Log parallel results
    if headers_data:
        if "error" not in headers_data:
            log("✓", f"Headers: [bold]{headers_data.get('grade','?')}[/bold]", "green")
        else:
            log("✗", f"Headers: {headers_data['error']}", "yellow")
    if hibp_data and not hibp_data.get("skipped"):
        if "error" not in hibp_data:
            n = hibp_data.get("count", 0)
            log("✓", f"HIBP: [{'red' if n else 'green'}]{n} breach(es)[/]",
                "red" if n else "green")
        else:
            log("✗", f"HIBP: {hibp_data.get('error')}", "yellow")
    if news_data and not news_data.get("skipped") and "error" not in (news_data or {}):
        log("✓", f"News: {len((news_data or {}).get('results',[]))} results", "green")
    if asx_data:
        if asx_data.get("skipped") or asx_data.get("note"):
            log("○", f"ASX: {asx_data.get('note','not listed')}", "dim")
        else:
            sc = asx_data.get("security_count", 0)
            t_count = asx_data.get("total_scanned", 0)
            log("✓",
                f"ASX [{asx_data.get('ticker','?')}]: {t_count} announcements, "
                f"[{'red' if sc else 'green'}]{sc} security-related[/]",
                "red" if sc else "green")
    if oaic_data and not oaic_data.get("skipped"):
        mc = oaic_data.get("mention_count", 0)
        log("✓", f"OAIC: [{'red' if mc else 'green'}]{mc} mention(s)[/]",
            "red" if mc else "green")

    # ── Two-pass AI analysis ───────────────────────────────────────────────
    section(f"Running two-pass AI analysis  [{args.model}]")

    try:
        report = analyse_two_pass(
            args.company, args.domain or "",
            ssl_data, headers_data, news_data,
            hibp_data, asx_data, oaic_data, doc_text,
            args.model,
        )
        report = sanitize_report(report)
    except (ConnectionError, ValueError) as e:
        console.print(f"\n[red]✗  {e}[/red]")
        sys.exit(1)

    report["assessment_date"] = datetime.now().strftime("%d %B %Y")
    report["_meta"] = {
        "ref":      ref,
        "company":  args.company,
        "domain":   args.domain or "",
        "ticker":   args.ticker or "",
        "assessor": args.assessor or "",
        "model":    args.model,
        "version":  "0.3",
        "phase":    "Phase 3 — Two-pass AI · Framework mapping · Risk register",
    }

    # ── Output ─────────────────────────────────────────────────────────────
    if args.output in ("terminal", "both"):
        render_report(
            report, args.company, args.domain or "",
            args.model, ref=ref, assessor=args.assessor,
        )

    if args.output in ("json", "both"):
        ts       = datetime.now().strftime("%Y%m%d_%H%M")
        slug     = re.sub(r"[^a-z0-9]+", "_", args.company.lower()).strip("_")
        filename = f"{slug}_grc_v03_{ts}.json"
        with open(filename, "w") as fh:
            json.dump(report, fh, indent=2)
        console.print(f"\n  [green]✓[/green]  Saved: [bold]{filename}[/bold]")
        console.print("  [dim]Pass this JSON to Phase 4 for PDF generation.[/dim]\n")


if __name__ == "__main__":
    main()
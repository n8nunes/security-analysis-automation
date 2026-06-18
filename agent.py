#!/usr/bin/env python3
"""
GRC Assessment Agent — Phase 4 (Full Version)
Two-pass AI analysis, ASX/OAIC intelligence, risk register, framework mapping, and PDF generation.

What's new in Phase 4:
  ✦ PDF Report Generation   — outputs professional, branded deliverable via WeasyPrint
  ✦ Zero-Dependency Fallback— gracefully drops back to full HTML report if GTK/DLLs are missing
  ✦ Formalised Disclaimers  — structured legal & ethical boundaries explicitly stated
  ✦ Deliverable Formatting   — HTML to PDF pipeline for clean, shareable client reports

Dependencies:
    pip install requests python-dotenv rich beautifulsoup4 lxml weasyprint

Usage:
    python agent.py "Latitude Financial" --domain latitudefinancial.com.au --ticker LFS --output pdf
    python agent.py "Medibank"  --domain medibank.com.au --doc policy.txt --output all
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

try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False

load_dotenv()

# ── CONFIG ─────────────────────────────────────────────────────────────────────

OLLAMA_HOST    = os.getenv("OLLAMA_HOST",  "http://localhost:11434")
OLLAMA_MODEL   = os.getenv("OLLAMA_MODEL", "llama3.1")
TAVILY_API_KEY = os.getenv("TAVILY_API_KEY", "")
HIBP_API_KEY   = os.getenv("HIBP_API_KEY",   "")

SSL_POLL_INTERVAL = 10    # seconds between SSL Labs polls
SSL_MAX_WAIT      = 180   # seconds before giving up
USER_AGENT        = "GRC-Assessment-Agent/0.4 (passive-recon-only; portfolio)"
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
    if not BS4_AVAILABLE:
        return {"skipped": True, "reason": "beautifulsoup4 not installed"}

    results = {
        "mentions":           [],
        "ndb_found":          False,
        "enforcement_found":  False,
        "mention_count":      0,
    }
    company_lower = company.lower()
    search_targets = [
        ("https://www.oaic.gov.au/privacy/notifiable-data-breaches", "NDB Statistics"),
        ("https://www.oaic.gov.au/privacy/privacy-decisions", "Privacy Decisions"),
        ("https://www.oaic.gov.au/privacy/privacy-guidance-for-organisations-and-government-agencies", "OAIC Guidance"),
    ]

    for url, label in search_targets:
        try:
            r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=OAIC_TIMEOUT)
            if r.status_code != 200: continue
            try: soup = BeautifulSoup(r.text, "lxml")
            except Exception: soup = BeautifulSoup(r.text, "html.parser")

            text  = soup.get_text(separator=" ", strip=True)
            lower = text.lower()
            if company_lower not in lower: continue

            idx     = lower.find(company_lower)
            snippet = text[max(0, idx - 120): idx + 200].strip()
            results["mentions"].append({"source": label, "url": url, "snippet": snippet})
            if "notifiable data breach" in lower or "ndb" in lower:
                results["ndb_found"] = True
            if "determination" in lower or "penalty" in lower or "enforcement" in lower:
                results["enforcement_found"] = True
        except Exception:
            pass

    results["mention_count"] = len(results["mentions"])
    return results


# ── TWO-PASS AI ANALYSIS ───────────────────────────────────────────────────────

PASS1_SYSTEM = """\
You are a cybersecurity analyst extracting structured findings from passive reconnaissance data.
RULES:
- Output ONLY valid JSON. No preamble, no markdown, no explanation.
- Base every finding strictly on evidence provided. Do not infer beyond what is shown.
- confidence: HIGH = direct technical evidence | MEDIUM = indirect/partial | LOW = inference only
- severity: HIGH = exploitable now or data already exposed | MEDIUM = real risk, not immediate | LOW = hygiene gap | INFO = neutral observation
- contradiction: if the company document claims X but technical data shows not-X, set this field to a short description. Otherwise null.
Respond with this exact JSON schema:
{
  "data_sensitivity": "...",
  "executive_brief": "...",
  "technical_summary": { "ssl_grade": "...", "headers_grade": "...", "known_breaches": 0, "key_vulnerabilities": [] },
  "findings": [ { "id": "F001", "source": "...", "category": "...", "severity": "HIGH", "confidence": "HIGH", "title": "...", "observation": "...", "risk": "...", "contradiction": null } ],
  "document_claims": []
}"""

PASS2_SYSTEM = """\
You are a senior GRC analyst mapping structured cybersecurity findings to Australian and international frameworks.
ESSENTIAL EIGHT MATURITY LEVELS (ASD ACSC — 0 to 4). Default to 0 for any control that passive recon cannot observe.
RISK SCORE = likelihood (1–5) × impact (1–5)
RULES: Output ONLY valid JSON. No preamble.
Respond with this exact JSON schema:
{
  "overall_risk_rating": "CRITICAL|HIGH|MEDIUM|LOW", "risk_score": 7.5, "confidence": "HIGH|MEDIUM|LOW",
  "essential_eight": { "patch_applications": {"maturity": 0, "notes": "...", "source": "..."}, "patch_os": {"maturity": 0, "notes": "...", "source": "..."}, "multi_factor_auth": {"maturity": 0, "notes": "...", "source": "..."}, "restrict_admin_privileges": {"maturity": 0, "notes": "...", "source": "..."}, "application_control": {"maturity": 0, "notes": "...", "source": "..."}, "restrict_macros": {"maturity": 0, "notes": "...", "source": "..."}, "user_application_hardening": {"maturity": 0, "notes": "...", "source": "..."}, "regular_backups": {"maturity": 0, "notes": "...", "source": "..."} },
  "iso_27001": [ {"domain": "...", "clause": "...", "status": "Unknown", "notes": "..."} ],
  "nist_csf": [ {"function": "Govern", "status": "Unknown", "notes": "..."} ],
  "privacy_act": { "overall_status": "Unknown", "apps_assessed": [ {"app": "...", "status": "...", "notes": "..."} ] },
  "risk_register": [ { "id": "R001", "finding_refs": ["F001"], "description": "...", "category": "...", "likelihood": 3, "impact": 4, "risk_score": 12, "risk_rating": "HIGH", "treatment": "...", "recommended_action": "..." } ],
  "recommendations": [ { "priority": "HIGH", "action": "...", "rationale": "...", "framework_ref": "...", "triggered_by": "F001" } ],
  "limitations": "brief note on what passive recon cannot determine"
}"""

def _call_ollama(system: str, user_msg: str, model: str, timeout: int = 300) -> dict:
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
                    "temperature": 0.05,
                    "num_ctx":     6144,
                    "top_p":       0.9,
                },
            },
            timeout=timeout,
        )
        r.raise_for_status()
    except requests.exceptions.ConnectionError:
        raise ConnectionError(f"Cannot connect to Ollama at {OLLAMA_HOST}.")

    content = r.json().get("message", {}).get("content", "").strip()
    if content.startswith("```"):
        parts = content.split("```")
        content = parts[1] if len(parts) > 1 else content
        if content.startswith("json"): content = content[4:]
    content = content.strip()

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        start = content.find("{"); end = content.rfind("}") + 1
        if start != -1 and end > start:
            try: return json.loads(content[start:end])
            except json.JSONDecodeError: pass
        raise ValueError("Model did not return valid JSON.")

def build_pass1_message(company, domain, ssl_data, headers_data, news_data, hibp_data, asx_data, oaic_data, doc_text) -> str:
    parts = [f"Company: {company}", f"Domain:  {domain or 'not provided'}", f"Date:    {datetime.now().strftime('%d %B %Y')}", ""]
    if ssl_data and "error" not in ssl_data: parts.append(f"SSL: grade={ssl_data.get('grade','?')} warnings={ssl_data.get('has_warnings',False)} HSTS={ssl_data.get('hsts_status','?')} cert_expiry={ssl_data.get('cert_expiry','?')}")
    else: parts.append(f"SSL: {ssl_data.get('error') if ssl_data else 'not collected'}")
    if headers_data and "error" not in headers_data: parts.append(f"HEADERS: grade={headers_data.get('grade','?')} present=[{','.join(headers_data.get('present',[]))}] missing=[{','.join(headers_data.get('missing',[]))}]")
    else: parts.append(f"HEADERS: {headers_data.get('error') if headers_data else 'not collected'}")
    if hibp_data and not hibp_data.get("skipped") and "error" not in hibp_data: parts.append(f"HIBP: breach_count={hibp_data.get('count', 0)}")
    if news_data and not news_data.get("skipped") and "error" not in news_data:
        if news_data.get("answer"): parts.append(f"NEWS_SUMMARY: {truncate(news_data['answer'], 350)}")
    if asx_data and not asx_data.get("skipped"): parts.append(f"ASX: security_related={asx_data.get('security_count', 0)}")
    if oaic_data and not oaic_data.get("skipped"): parts.append(f"OAIC: mentions={oaic_data.get('mention_count', 0)} ndb_context={oaic_data.get('ndb_found',False)}")
    if doc_text and doc_text.strip(): parts.append(f"\nDOCUMENT (truncated to 4000 chars):\n{doc_text.strip()[:4000]}")
    return "\n".join(parts)

def build_pass2_message(pass1: dict) -> str:
    findings_compact = [f"{f.get('id','?')} [{f.get('severity','?')}] {f.get('title','')} | {f.get('observation','')}" for f in pass1.get("findings", [])]
    return json.dumps({"data_sensitivity": pass1.get("data_sensitivity", ""), "executive_brief": pass1.get("executive_brief", ""), "findings": findings_compact}, separators=(",", ":"))

def analyse_two_pass(company, domain, ssl_data, headers_data, news_data, hibp_data, asx_data, oaic_data, doc_text, model) -> dict:
    log("⟳", "Pass 1 — extracting technical findings…", "cyan")
    p1_msg = build_pass1_message(company, domain, ssl_data, headers_data, news_data, hibp_data, asx_data, oaic_data, doc_text)
    pass1 = _call_ollama(PASS1_SYSTEM, p1_msg, model)
    log("✓", f"Pass 1 complete — {len(pass1.get('findings', []))} finding(s) extracted", "green")
    
    log("⟳", "Pass 2 — framework mapping + risk register…", "cyan")
    p2_msg = build_pass2_message(pass1)
    pass2: dict = {}
    try:
        pass2 = _call_ollama(PASS2_SYSTEM, p2_msg, model)
        log("✓", "Pass 2 complete — frameworks mapped", "green")
    except Exception as e:
        log("⚠", f"Pass 2 failed. Error: {e}", "yellow")

    sources = []
    if ssl_data and "error" not in ssl_data: sources.append("SSL Labs")
    if headers_data and "error" not in headers_data: sources.append("Security Headers")
    if news_data and not news_data.get("skipped"): sources.append("News Intelligence")
    if hibp_data and not hibp_data.get("skipped"): sources.append("HIBP")
    if asx_data and not asx_data.get("skipped"): sources.append("ASX Announcements")
    if oaic_data and not oaic_data.get("skipped"): sources.append("OAIC Records")

    return {
        "data_sensitivity": pass1.get("data_sensitivity", ""), "executive_summary": pass1.get("executive_brief", ""),
        "technical_summary": pass1.get("technical_summary", {}), "findings": pass1.get("findings", []), "document_claims": pass1.get("document_claims", []),
        "data_sources_used": sources, "overall_risk_rating": pass2.get("overall_risk_rating", "UNKNOWN"), "risk_score": pass2.get("risk_score", 0.0),
        "confidence": pass2.get("confidence", "LOW"), "essential_eight": pass2.get("essential_eight", {}), "iso_27001": pass2.get("iso_27001", []),
        "nist_csf": pass2.get("nist_csf", []), "privacy_act": pass2.get("privacy_act", {}), "risk_register": pass2.get("risk_register", []),
        "recommendations": pass2.get("recommendations", []), "limitations": pass2.get("limitations", "Passive reconnaissance only — no active scanning."),
        "assessed_by": f"GRC Assessment Agent v0.4 (Phase 4 — {model})"
    }


# ── SANITIZE & TERMINAL RENDER ─────────────────────────────────────────────────

def _s(v, fallback: str = "") -> str:
    if v is None: return fallback
    if isinstance(v, dict):
        for k in ("name", "type", "title", "description", "value", "text"):
            if k in v: return str(v[k])
        return str(v)
    return str(v)

def sanitize_report(report: dict) -> dict:
    for k in ("executive_summary", "overall_risk_rating", "confidence", "data_sensitivity", "limitations", "assessed_by", "assessment_date"):
        report[k] = _s(report.get(k))
    try: report["risk_score"] = float(report.get("risk_score") or 0)
    except (TypeError, ValueError): report["risk_score"] = 0.0
    for key in ("data_sources_used", "document_claims"):
        val = report.get(key, [])
        report[key] = [_s(x) for x in val] if isinstance(val, list) else []
    tech = report.get("technical_summary")
    if not isinstance(tech, dict): report["technical_summary"] = {}; tech = report["technical_summary"]
    tech["ssl_grade"] = _s(tech.get("ssl_grade"), "Unknown")
    tech["headers_grade"] = _s(tech.get("headers_grade"), "Unknown")
    try: tech["known_breaches"] = int(tech.get("known_breaches") or 0)
    except (TypeError, ValueError): tech["known_breaches"] = 0
    vulns = tech.get("key_vulnerabilities", [])
    tech["key_vulnerabilities"] = [_s(v) for v in vulns] if isinstance(vulns, list) else []
    findings = report.get("findings", [])
    if not isinstance(findings, list): report["findings"] = []
    else:
        for f in findings:
            if isinstance(f, dict):
                for k in ("id", "source", "category", "severity", "confidence", "title", "observation", "risk"): f[k] = _s(f.get(k))
                if "contradiction" not in f: f["contradiction"] = None
    rr = report.get("risk_register", [])
    if not isinstance(rr, list): report["risk_register"] = []
    else:
        for r in rr:
            if isinstance(r, dict):
                for k in ("id", "description", "category", "risk_rating", "treatment", "recommended_action"): r[k] = _s(r.get(k))
                for k in ("likelihood", "impact", "risk_score"):
                    try: r[k] = int(r.get(k) or 0)
                    except (TypeError, ValueError): r[k] = 0
                refs = r.get("finding_refs", [])
                r["finding_refs"] = [_s(x) for x in refs] if isinstance(refs, list) else []
    return report

def grade_style(g: str) -> str:
    if not g or g == "Unknown": return "dim"
    if g.upper().startswith("A"): return "green"
    if g.upper() == "B": return "yellow"
    return "red"

def risk_score_color(score: int) -> str:
    if score >= 16: return "bold magenta"
    if score >= 10: return "bold red"
    if score >= 6:  return "bold yellow"
    return "bold green"

RISK_STYLE = {"CRITICAL": "bold magenta", "HIGH": "bold red", "MEDIUM": "bold yellow", "LOW": "bold green", "UNKNOWN": "white"}

def render_report(report: dict, company: str, domain: str = "", model: str = "", ref: str = "", assessor: str = ""):
    console.print()
    risk  = report.get("overall_risk_rating", "UNKNOWN").upper()
    score = report.get("risk_score", 0)
    rc    = RISK_STYLE.get(risk, "white")

    header = Text()
    header.append(f"  {company.upper()}  ", style="bold white")
    header.append(f"│  {risk} RISK  ", style=rc)
    header.append(f"│  Score {score}/10  ", style="white")
    if domain: header.append(f"│  {domain}", style="dim")
    
    console.print(Panel(header, title=f"[bold]GRC Assessment Report[/bold] [dim]v0.4 · {model}[/dim]", subtitle=f"[dim]Ref: {ref} · Assessor: {assessor or 'Automated'} · Passive recon[/dim]", border_style=rc))
    
    section("Executive Summary")
    console.print(f"  {report.get('executive_summary','')}", style="white")
    console.print(f"\n  [dim]Data handled:[/dim]  {report.get('data_sensitivity','')}")
    console.print(f"  [dim]Sources used:[/dim]  {', '.join(report.get('data_sources_used',[]))}\n")

    tech = report.get("technical_summary", {})
    if tech:
        section("Technical Snapshot")
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        sg = tech.get("ssl_grade", "Unknown")
        hg = tech.get("headers_grade", "Unknown")
        bc = int(tech.get("known_breaches") or 0)
        t.add_row("SSL Grade", f"[{grade_style(sg)}]{sg}[/{grade_style(sg)}]")
        t.add_row("Headers Grade", f"[{grade_style(hg)}]{hg}[/{grade_style(hg)}]")
        t.add_row("Known Breaches", f"[{'red' if bc > 0 else 'green'}]{bc}[/]")
        console.print(t)


# ── PHASE 4: DELIVERABLE GENERATION (PDF / HTML FALLBACK) ──────────────────────

def generate_pdf_report(report: dict, company: str, output_path: str):
    """
    Generates a professional, branded deliverable.
    Includes full framework mapping for Essential Eight, ISO 27001, NIST CSF, and APPs.
    """
    # 1. Build HTML Rows for Findings
    findings_html = ""
    for f in report.get("findings", []):
        sev_class = f"risk-{f.get('severity', 'UNKNOWN').upper()}"
        findings_html += f"""
        <tr>
            <td>{f.get('id', '')}</td>
            <td class='{sev_class}'>{f.get('severity', '')}</td>
            <td>{f.get('category', '')}</td>
            <td><strong>{f.get('title', '')}</strong><br><span style='font-size:0.9em; color:#555;'>{f.get('observation', '')}</span></td>
        </tr>"""

    # 2. Build HTML Rows for Risk Register
    risks_html = ""
    for r in report.get("risk_register", []):
        sev_class = f"risk-{r.get('risk_rating', 'UNKNOWN').upper()}"
        risks_html += f"""
        <tr>
            <td>{r.get('id', '')}</td>
            <td class='{sev_class}'>{r.get('risk_rating', '')} ({r.get('risk_score', '')})</td>
            <td>{r.get('description', '')}</td>
            <td>{r.get('recommended_action', '')}</td>
        </tr>"""

    # 3. Build HTML Rows for Essential Eight
    e8_labels = {
        "patch_applications":         "Patch Applications",
        "patch_os":                   "Patch OS",
        "multi_factor_auth":          "Multi-Factor Authentication (MFA)",
        "restrict_admin_privileges":  "Restrict Admin Privileges",
        "application_control":        "Application Control",
        "restrict_macros":            "Restrict Microsoft Office Macros",
        "user_application_hardening": "User Application Hardening",
        "regular_backups":            "Regular Backups",
    }
    e8_html = ""
    for key, label in e8_labels.items():
        val = report.get("essential_eight", {}).get(key, {})
        mat = val.get("maturity", 0)
        # Simple CSS bar mimicry
        bar = f"<span style='color:#27AE60;'>{'★' * mat}</span><span style='color:#BDC3C7;'>{'☆' * (4 - mat)}</span> (ML{mat})" if mat >= 3 else f"<span style='color:#F39C12;'>{'★' * mat}</span><span style='color:#BDC3C7;'>{'☆' * (4 - mat)}</span> (ML{mat})"
        if mat == 0: bar = "<span style='color:#7F8C8D;'>☆☆☆☆ (ML0)</span>"
        e8_html += f"""
        <tr>
            <td><strong>{label}</strong></td>
            <td>{bar}</td>
            <td>{val.get('source', 'None')}</td>
            <td>{val.get('notes', '')}</td>
        </tr>"""

    # 4. Build HTML Rows for ISO 27001
    iso_html = ""
    for d in report.get("iso_27001", []):
        iso_html += f"""
        <tr>
            <td>{d.get('clause', '')}</td>
            <td>{d.get('domain', '')}</td>
            <td><span class='status-{d.get("status", "Unknown").lower()}'>{d.get('status', 'Unknown')}</span></td>
            <td>{d.get('notes', '')}</td>
        </tr>"""

    # 5. Build HTML Rows for NIST CSF
    nist_html = ""
    for fn in report.get("nist_csf", []):
        nist_html += f"""
        <tr>
            <td><strong>{fn.get('function', '')}</strong></td>
            <td><span class='status-{fn.get("status", "Unknown").lower()}'>{fn.get('status', 'Unknown')}</span></td>
            <td>{fn.get('notes', '')}</td>
        </tr>"""

    # 6. Build HTML Rows for Privacy Act APPs
    pa = report.get("privacy_act", {})
    pa_html = ""
    for app in pa.get("apps_assessed", []):
        pa_html += f"""
        <tr>
            <td>{app.get('app', '')}</td>
            <td><span class='status-{app.get("status", "Unknown").lower()}'>{app.get('status', 'Unknown')}</span></td>
            <td>{app.get('notes', '')}</td>
        </tr>"""

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>GRC Assessment - {company}</title>
        <style>
            @page {{ size: A4; margin: 2cm; @bottom-right {{ content: counter(page) " of " counter(pages); font-family: 'Helvetica', sans-serif; font-size: 9pt; color: #7F8C8D; }} }}
            @media print {{ body {{ font-size: 10pt; }} .no-print {{ display: none; }} }}
            body {{ font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; color: #2C3E50; line-height: 1.6; max-width: 900px; margin: 40px auto; padding: 0 20px; }}
            h1, h2, h3 {{ color: #2980B9; margin-top: 30px; border-bottom: 1px solid #ECF0F1; padding-bottom: 5px; }}
            .cover {{ text-align: center; margin-top: 15vh; margin-bottom: 20vh; }}
            .cover h1 {{ font-size: 3em; margin-bottom: 10px; }}
            .cover h2 {{ font-size: 1.8em; color: #7F8C8D; font-weight: 300; }}
            .cover .meta {{ margin-top: 50px; font-size: 1.1em; color: #34495E; }}
            .section {{ page-break-before: always; margin-top: 40px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 15px; margin-bottom: 30px; font-size: 10pt; }}
            th, td {{ border: 1px solid #BDC3C7; padding: 12px; text-align: left; vertical-align: top; }}
            th {{ background-color: #ECF0F1; font-weight: bold; }}
            .risk-CRITICAL {{ color: #C0392B; font-weight: bold; }}
            .risk-HIGH {{ color: #E74C3C; font-weight: bold; }}
            .risk-MEDIUM {{ color: #F39C12; font-weight: bold; }}
            .risk-LOW {{ color: #27AE60; font-weight: bold; }}
            .status-evident, .status-compliant {{ color: #27AE60; font-weight: bold; }}
            .status-partial, .status-apparent {{ color: #F39C12; font-weight: bold; }}
            .status-gap, .status-concern, .status-non-compliant {{ color: #C0392B; font-weight: bold; }}
            .status-unknown {{ color: #7F8C8D; font-style: italic; }}
            .disclaimer {{ font-size: 0.85em; color: #7F8C8D; margin-top: 40px; padding: 15px; background-color: #F9F9F9; border-left: 4px solid #BDC3C7; }}
            .fallback-alert {{ background-color: #E6F2FF; border: 1px solid #B3D7FF; padding: 15px; border-radius: 4px; margin-bottom: 20px; font-size: 0.95em; color: #004085; }}
        </style>
    </head>
    <body>
        <div class="fallback-alert no-print">
            <strong>💡 Standalone Document View:</strong> Formatted cleanly. To export this deliverable directly to an offline copy, open this document inside a browser, press <code>Ctrl + P</code>, and click <strong>Save as PDF</strong>.
        </div>
        <div class="cover">
            <h1>Security Assessment Report</h1>
            <h2>{company}</h2>
            <div class="meta">
                <p><strong>Reference:</strong> {report.get('_meta', {}).get('ref', 'N/A')}</p>
                <p><strong>Date:</strong> {report.get('assessment_date', 'N/A')}</p>
                <p><strong>Assessor:</strong> {report.get('_meta', {}).get('assessor', 'Automated GRC Agent v0.4')}</p>
            </div>
        </div>
        <div class="section">
            <h2>1. Executive Summary</h2>
            <p>{report.get('executive_summary', 'No summary provided.')}</p>
            <p><strong>Data Sensitivity Context:</strong> {report.get('data_sensitivity', 'Unknown')}</p>
        </div>
        <div class="section">
            <h2>2. Technical Findings</h2>
            <table>
                <thead><tr><th>ID</th><th>Severity</th><th>Category</th><th>Observation</th></tr></thead>
                <tbody>{findings_html}</tbody>
            </table>
        </div>
        <div class="section">
            <h2>3. Risk Register</h2>
            <table>
                <thead><tr><th>ID</th><th>Rating</th><th>Description</th><th>Recommended Action</th></tr></thead>
                <tbody>{risks_html}</tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>4. Framework Mappings</h2>
            
            <h3>Essential Eight Maturity (ASD ACSC)</h3>
            <table>
                <thead><tr><th>Control Strategy</th><th>Maturity Level</th><th>Evidence Ref</th><th>Notes / Observations</th></tr></thead>
                <tbody>{e8_html}</tbody>
            </table>

            <h3>ISO 27001:2022 Alignment</h3>
            <table>
                <thead><tr><th>Clause</th><th>Domain</th><th>Status</th><th>Notes</th></tr></thead>
                <tbody>{iso_html}</tbody>
            </table>

            <h3>NIST CSF 2.0 Mapping</h3>
            <table>
                <thead><tr><th>Function</th><th>Status</th><th>Notes</th></tr></thead>
                <tbody>{nist_html}</tbody>
            </table>

            <h3>Australian Privacy Act (APPs)</h3>
            <p><strong>Overall Privacy Status:</strong> <span class="status-{pa.get('overall_status', 'Unknown').lower()}">{pa.get('overall_status', 'Unknown')}</span></p>
            <table>
                <thead><tr><th>Australian Privacy Principle (APP)</th><th>Status</th><th>Notes</th></tr></thead>
                <tbody>{pa_html}</tbody>
            </table>
        </div>

        <div class="section">
            <h2>5. Limitations & Disclaimers</h2>
            <div class="disclaimer">
                <p><strong>Strictly Passive Reconnaissance:</strong> This report was generated using only public, passive data sources. No active scanning was performed.</p>
                <p><strong>Indicative Findings:</strong> The findings mapped in this document require human review by a qualified cybersecurity professional before professional or client use.</p>
                <p><strong>Not Authorized Penetration Testing:</strong> This assessment is not a substitute for an authorized penetration test, a formal compliance audit, or legal counsel.</p>
            </div>
        </div>
    </body>
    </html>
    """

    if WEASYPRINT_AVAILABLE:
        try:
            log("⟳", "Generating PDF report via WeasyPrint...", "cyan")
            HTML(string=html_content).write_pdf(output_path)
            log("✓", f"Successfully generated PDF: {output_path}", "green")
            return
        except Exception as e:
            log("⚠", f"WeasyPrint engine failure, dropping back to clean HTML. Error: {e}", "yellow")
    
    html_path = output_path.replace(".pdf", ".html")
    try:
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(html_content)
        log("✓", f"Created standalone report: [bold]{html_path}[/bold]", "green")
        log("📎", "Double-click the .html file, press Ctrl+P, and hit 'Save as PDF' to generate the deliverable.", "dim")
    except Exception as e:
        log("✗", f"Failed to save fallback report: {e}", "red")


# ── MAIN ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="GRC Assessment Agent v0.4 — Phase 4")
    parser.add_argument("company",             help='Company name e.g. "Latitude Financial"')
    parser.add_argument("--domain",    "-d",   help="Domain to scan e.g. latitudefinancial.com.au")
    parser.add_argument("--ticker",    "-t",   help="ASX ticker e.g. LFS")
    parser.add_argument("--doc",       "-f",   help="Path to .txt document for analysis")
    parser.add_argument("--model",     "-m",   default=OLLAMA_MODEL)
    parser.add_argument("--output",    "-o",   default="both", choices=["terminal", "json", "both", "pdf", "all"])
    parser.add_argument("--assessor",          default="")
    parser.add_argument("--ref",               default="")
    args = parser.parse_args()

    ref = args.ref or gen_ref()

    console.print(Panel(
        f"[bold white]GRC Assessment Agent[/bold white]  [dim]v0.4 · Phase 4 · {args.model}[/dim]\n"
        f"[dim]Ref: {ref}  ·  Two-pass AI  ·  ASX + OAIC  ·  Passive recon[/dim]",
        border_style="blue",
    ))

    # Restored verification status logs
    ollama_status = check_ollama(args.model)
    if not ollama_status.get("ok"):
        console.print(f"[red]✗ Model '{args.model}' not found or Ollama not running.[/red]")
        sys.exit(1)

    log("✓", f"Ollama running · model: [bold]{args.model}[/bold]", "green")

    # ── Intelligence Gathering ─────────────────────────────────────────────
    section("Gathering intelligence")
    ssl_data = headers_data = news_data = hibp_data = asx_data = oaic_data = None

    def _collect_parallel():
        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = {}
            if args.domain and not HIBP_API_KEY: log("○", "HIBP: skipped — add HIBP_API_KEY to .env", "dim")
            if args.domain and HIBP_API_KEY:     futures["hibp"] = ex.submit(check_hibp, args.domain)
            if TAVILY_API_KEY:                   futures["news"] = ex.submit(search_news, args.company)
            else:                                log("○", "News: skipped — add TAVILY_API_KEY to .env", "dim")
            futures["asx"]  = ex.submit(search_asx, args.company, args.ticker)
            futures["oaic"] = ex.submit(search_oaic, args.company)
            if args.domain:                      futures["headers"] = ex.submit(check_security_headers, args.domain)
            
            res = {}
            for k, f in futures.items():
                try: res[k] = f.result()
                except Exception as e: res[k] = {"error": str(e)}
            return res

    if args.domain:
        log("⟳", f"SSL Labs: {args.domain} — takes 60–90 s…")
        ssl_data = check_ssl(args.domain)
        if "error" not in ssl_data: log("✓", f"SSL Labs: [bold]{ssl_data.get('grade')}[/bold]", "green")
        else:                       log("✗", f"SSL Labs: {ssl_data['error']}", "yellow")
    else:
        log("○", "No domain — skipping SSL / headers / HIBP", "dim")

    collected = _collect_parallel()
    headers_data = collected.get("headers")
    hibp_data    = collected.get("hibp")
    news_data    = collected.get("news")
    asx_data     = collected.get("asx")
    oaic_data    = collected.get("oaic")

    # Restored data source status prints
    if headers_data and "error" not in headers_data: log("✓", f"Headers: [bold]{headers_data.get('grade','?')}[/bold]", "green")
    if hibp_data and "error" not in hibp_data and not hibp_data.get("skipped"): log("✓", f"HIBP: {hibp_data.get('count', 0)} breach(es)", "green")
    if news_data and "error" not in news_data and not news_data.get("skipped"): log("✓", f"News: {len(news_data.get('results', []))} items", "green")
    if asx_data and not asx_data.get("note"): log("✓", f"ASX: {asx_data.get('security_count', 0)} security alerts", "green")
    if oaic_data and not oaic_data.get("skipped"): log("✓", f"OAIC: {oaic_data.get('mention_count', 0)} mentions", "green")

    doc_text = ""
    if args.doc and os.path.exists(args.doc):
        with open(args.doc, encoding="utf-8", errors="ignore") as fh: doc_text = fh.read()

    # ── Analysis ───────────────────────────────────────────────────────────
    section(f"Running two-pass AI analysis  [{args.model}]")
    try:
        report = analyse_two_pass(args.company, args.domain or "", ssl_data, headers_data, news_data, hibp_data, asx_data, oaic_data, doc_text, args.model)
        report = sanitize_report(report)
    except Exception as e:
        console.print(f"\n[red]✗  Analysis failed: {e}[/red]")
        sys.exit(1)

    report["assessment_date"] = datetime.now().strftime("%d %B %Y")
    report["_meta"] = {"ref": ref, "company": args.company, "domain": args.domain or "", "assessor": args.assessor, "model": args.model}

    # ── Outputs ─────────────────────────────────────────────────────────────
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    slug = re.sub(r"[^a-z0-9]+", "_", args.company.lower()).strip("_")

    if args.output in ("terminal", "both", "all"):
        render_report(report, args.company, args.domain or "", args.model, ref=ref, assessor=args.assessor)
    if args.output in ("json", "both", "all"):
        with open(f"{slug}_grc_v04_{ts}.json", "w") as fh: json.dump(report, fh, indent=2)
    if args.output in ("pdf", "all"):
        generate_pdf_report(report, args.company, f"{slug}_grc_v04_{ts}.pdf")

if __name__ == "__main__":
    main()
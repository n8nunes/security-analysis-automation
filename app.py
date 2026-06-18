import streamlit as st
import os
import json
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Ensure environment variables load gracefully
from dotenv import load_dotenv
load_dotenv()

# Import the existing CLI engine logic
import agent

# Configure the web interface
st.set_page_config(page_title="GRC Assessment Agent", page_icon="🛡️", layout="centered")

st.title("🛡️ GRC Assessment Agent")
st.markdown("Automated Governance, Risk, and Compliance (GRC) assessment mapping public intelligence to security frameworks.")

# Sidebar for advanced configurations
with st.sidebar:
    st.header("Engine Configuration")
    ollama_model = st.text_input("Ollama Model", value=agent.OLLAMA_MODEL)
    assessor_name = st.text_input("Assessor Name", value="Automated Agent")
    st.markdown("---")
    st.markdown("**API Keys Detected:**")
    st.markdown(f"- HIBP: {'✅' if agent.HIBP_API_KEY else '❌'}")
    st.markdown(f"- Tavily: {'✅' if agent.TAVILY_API_KEY else '❌'}")

# Primary Input Interface
with st.form("assessment_form"):
    st.subheader("Target Intelligence")
    col1, col2 = st.columns(2)
    with col1:
        company = st.text_input("Company Name*", placeholder="e.g., Latitude Financial")
    with col2:
        domain = st.text_input("Domain (Optional)", placeholder="e.g., latitudefinancial.com.au")
        
    ticker = st.text_input("ASX Ticker (Optional)", placeholder="e.g., LFS")
    doc_upload = st.file_uploader("Internal Documentation (.txt) [Optional]", type=["txt"], help="Supply privacy policies or internal posture statements to improve framework mapping accuracy.")
    
    submitted = st.form_submit_button("Run Assessment Pipeline")

if submitted:
    if not company:
        st.error("Company Name is required to begin the assessment.")
        st.stop()
        
    ref = agent.gen_ref()
    doc_text = ""
    if doc_upload:
        doc_text = str(doc_upload.read(), "utf-8", errors="ignore")
        
    st.info(f"Target locked: **{company}** | Reference: `{ref}`")

    # System Health Check
    with st.spinner(f"Waking up AI Engine ({ollama_model})..."):
        ollama_status = agent.check_ollama(ollama_model)
        if not ollama_status.get("ok"):
            st.error(f"Cannot connect to Ollama. Ensure the service is running and '{ollama_model}' is available.")
            st.stop()
    
    # Parallel Intelligence Gathering
    st.markdown("### 📡 Intelligence Collection")
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    ssl_data = headers_data = news_data = hibp_data = asx_data = oaic_data = None
    
    status_text.text("Connecting to public endpoints. SSL Labs analysis may take 60-90 seconds...")
    
    def _collect_parallel():
        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = {}
            if domain and agent.HIBP_API_KEY: futures["hibp"] = ex.submit(agent.check_hibp, domain)
            if agent.TAVILY_API_KEY:          futures["news"] = ex.submit(agent.search_news, company)
            futures["asx"]  = ex.submit(agent.search_asx, company, ticker)
            futures["oaic"] = ex.submit(agent.search_oaic, company)
            if domain:                        futures["headers"] = ex.submit(agent.check_security_headers, domain)
            
            res = {}
            for k, f in futures.items():
                try: res[k] = f.result()
                except Exception as e: res[k] = {"error": str(e)}
            return res

    # Run SSL independently as it blocks heavily
    if domain:
        ssl_data = agent.check_ssl(domain)
    
    progress_bar.progress(35)
    status_text.text("Querying ASX, OAIC, HIBP, and OSINT databases...")
    
    collected = _collect_parallel()
    headers_data = collected.get("headers")
    hibp_data    = collected.get("hibp")
    news_data    = collected.get("news")
    asx_data     = collected.get("asx")
    oaic_data    = collected.get("oaic")
    
    progress_bar.progress(60)
    status_text.text("Public intelligence successfully acquired.")

    # AI Analysis Engine
    st.markdown("### 🧠 AI Analysis Pipeline")
    status_text.text("Pass 1: Extracting technical findings and security gaps...")
    
    try:
        p1_msg = agent.build_pass1_message(company, domain, ssl_data, headers_data, news_data, hibp_data, asx_data, oaic_data, doc_text)
        pass1 = agent._call_ollama(agent.PASS1_SYSTEM, p1_msg, ollama_model)
        
        progress_bar.progress(80)
        status_text.text("Pass 2: Mapping findings to frameworks and building risk register...")
        
        p2_msg = agent.build_pass2_message(pass1)
        pass2 = agent._call_ollama(agent.PASS2_SYSTEM, p2_msg, ollama_model)
        
        progress_bar.progress(95)
        status_text.text("Sanitizing report data...")
        
        sources = []
        if ssl_data and "error" not in ssl_data: sources.append("SSL Labs")
        if headers_data and "error" not in headers_data: sources.append("Security Headers")
        if news_data and not news_data.get("skipped"): sources.append("News Intelligence")
        if hibp_data and not hibp_data.get("skipped"): sources.append("HIBP")
        if asx_data and not asx_data.get("skipped"): sources.append("ASX Announcements")
        if oaic_data and not oaic_data.get("skipped"): sources.append("OAIC Records")

        report = {
            "data_sensitivity": pass1.get("data_sensitivity", ""), "executive_summary": pass1.get("executive_brief", ""),
            "technical_summary": pass1.get("technical_summary", {}), "findings": pass1.get("findings", []), "document_claims": pass1.get("document_claims", []),
            "data_sources_used": sources, "overall_risk_rating": pass2.get("overall_risk_rating", "UNKNOWN"), "risk_score": pass2.get("risk_score", 0.0),
            "confidence": pass2.get("confidence", "LOW"), "essential_eight": pass2.get("essential_eight", {}), "iso_27001": pass2.get("iso_27001", []),
            "nist_csf": pass2.get("nist_csf", []), "privacy_act": pass2.get("privacy_act", {}), "risk_register": pass2.get("risk_register", []),
            "recommendations": pass2.get("recommendations", []), "limitations": pass2.get("limitations", "Passive reconnaissance only - no active scanning."),
            "assessed_by": f"GRC Assessment Agent v0.5 (Phase 5 - {ollama_model})"
        }
        
        report = agent.sanitize_report(report)
        report["assessment_date"] = datetime.now().strftime("%d %B %Y")
        report["_meta"] = {"ref": ref, "company": company, "domain": domain or "", "assessor": assessor_name, "model": ollama_model}
        
    except Exception as e:
        st.error(f"Analysis pipeline crashed: {e}")
        st.stop()
        
    progress_bar.progress(100)
    status_text.text("Assessment generation complete.")
    st.success("✓ Deliverables are ready.")

    # Report Generation & Download
    st.markdown("### 📄 Assessment Deliverables")
    
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    slug = re.sub(r"[^a-z0-9]+", "_", company.lower()).strip("_")
    pdf_filename = f"{slug}_grc_v05_{ts}.pdf"
    html_filename = f"{slug}_grc_v05_{ts}.html"
    json_filename = f"{slug}_grc_v05_{ts}.json"
    
    # Build local files using the existing engine function
    agent.generate_pdf_report(report, company, pdf_filename)
    with open(json_filename, "w") as fh:
        json.dump(report, fh, indent=2)

    col1, col2 = st.columns(2)
    
    if os.path.exists(pdf_filename):
        with open(pdf_filename, "rb") as f:
            col1.download_button("📄 Download PDF Report", data=f, file_name=pdf_filename, mime="application/pdf")
    elif os.path.exists(html_filename):
        with open(html_filename, "rb") as f:
            col1.download_button("🌐 Download HTML Report (Fallback)", data=f, file_name=html_filename, mime="text/html")
            
    with open(json_filename, "rb") as f:
        col2.download_button("⚙️ Download Raw JSON Data", data=f, file_name=json_filename, mime="application/json")
        
    st.markdown("---")
    st.subheader("Executive Snapshot")
    risk = report.get("overall_risk_rating", "UNKNOWN").upper()
    risk_color = "red" if risk in ["CRITICAL", "HIGH"] else "orange" if risk == "MEDIUM" else "green"
    st.markdown(f"**Overall Risk Rating:** :{risk_color}[**{risk}**] (Score: {report.get('risk_score', 0)}/10)")
    st.markdown(f"**Executive Summary:** {report.get('executive_summary', '')}")
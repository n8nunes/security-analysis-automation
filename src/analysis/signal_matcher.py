import json
import re
from datetime import datetime
from typing import Dict, Any, List
from src.llm.ollama_service import OllamaService

class EvidenceCollector:
    @staticmethod
    def create_evidence(quote: str, source: str, source_type: str, signal_origin: str, confidence: float, details: Dict = None) -> Dict:
        evidence = {
            "quote": quote,
            "source": source,
            "source_type": source_type,
            "signal_origin": signal_origin,
            "confidence": confidence,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        if details:
            evidence["details"] = details
        return evidence

class SignalMatcher:
    def __init__(self, controls_file: str, ollama_service: OllamaService):
        with open(controls_file, "r") as f:
            self.controls = json.load(f)
        self.ollama_service = ollama_service
        
    def find_keyword_match(self, text: str, keywords: List[str]) -> str:
        lower_text = text.lower()
        for kw in keywords:
            kw_lower = kw.lower()
            if kw_lower in lower_text:
                # Extract surrounding context
                idx = lower_text.find(kw_lower)
                start = max(0, idx - 100)
                end = min(len(text), idx + len(kw_lower) + 100)
                snippet = text[start:end].strip()
                # Clean up snippet
                snippet = "..." + snippet + "..."
                return snippet
        return ""

    def process_control(self, control: Dict, website_data: Dict, trust_center_data: Dict) -> Dict:
        evidence = []
        
        # 1. Certificate validation (specific controls)
        if control["control_id"] == "PR.DS-02" and website_data.get("ssl", {}).get("valid"):
            evidence.append(EvidenceCollector.create_evidence(
                quote="SSL/TLS certificate valid",
                source="certificate_validation",
                source_type="website",
                signal_origin="cert",
                confidence=1.0,
                details=website_data["ssl"]
            ))

        # 2. Structured data / Certifications
        if "certifications" in trust_center_data:
            certs = trust_center_data["certifications"]
            if control["control_id"] == "GV.RM-01" and ("SOC 2 Type II" in certs or "ISO 27001" in certs):
                evidence.append(EvidenceCollector.create_evidence(
                    quote=f"Identified certifications: {', '.join(certs)}",
                    source=trust_center_data.get("url", "trust_center"),
                    source_type="trust_center",
                    signal_origin="structured_data",
                    confidence=0.95
                ))

        # 3. Keyword matching
        keywords = control.get("keyword_matching_terms", [])
        
        # Check Trust Center text
        tc_text = trust_center_data.get("raw_text", "")
        if tc_text:
            match = self.find_keyword_match(tc_text, keywords)
            if match:
                evidence.append(EvidenceCollector.create_evidence(
                    quote=match,
                    source=trust_center_data.get("url", "trust_center"),
                    source_type="trust_center",
                    signal_origin="keyword",
                    confidence=0.85
                ))
                
        # Check Website text
        wb_text = website_data.get("raw_text", "")
        if wb_text and not evidence: # Only if we haven't found strong evidence yet
            match = self.find_keyword_match(wb_text, keywords)
            if match:
                evidence.append(EvidenceCollector.create_evidence(
                    quote=match,
                    source=website_data.get("domain", "website"),
                    source_type="website",
                    signal_origin="keyword",
                    confidence=0.75
                ))

        # 4. LLM Fallback
        llm_triggered = False
        if not evidence and self.ollama_service.is_available:
            llm_triggered = True
            prompt = control.get("llm_extraction_prompt", "")
            if tc_text:
                # Truncate text if too long to fit in context window, or send a summary
                context_text = tc_text[:10000] 
                full_prompt = f"Context:\n{context_text}\n\nQuestion: {prompt}"
                response = self.ollama_service.query(full_prompt)
                
                if response and response.startswith("YES"):
                    # Cross-validation would go here in a real scenario
                    # For now, mark it requires_verification if no corroboration
                    evidence.append(EvidenceCollector.create_evidence(
                        quote=response,
                        source=trust_center_data.get("url", "trust_center"),
                        source_type="trust_center",
                        signal_origin="llm",
                        confidence=0.85,
                        details={"requires_verification": True}
                    ))

        status = "SIGNAL_NOT_FOUND"
        score = 0
        
        if evidence:
            status = "SIGNAL_FOUND"
            # High confidence if keyword/cert
            if any(e["signal_origin"] in ["keyword", "cert", "structured_data"] for e in evidence):
                score = 100
            elif any(e["signal_origin"] == "llm" for e in evidence):
                score = 85

        return {
            "control_id": control["control_id"],
            "control_name": control["control_name"],
            "function": control["function"],
            "status": status,
            "score": score,
            "evidence": evidence,
            "llm_triggered": llm_triggered
        }

    def analyze(self, website_data: Dict, trust_center_data: Dict) -> Dict:
        results = []
        llm_fallback_count = 0
        
        for control in self.controls:
            result = self.process_control(control, website_data, trust_center_data)
            if result.get("llm_triggered"):
                llm_fallback_count += 1
            results.append(result)
            
        return {
            "controls": results,
            "llm_fallback_count": llm_fallback_count
        }

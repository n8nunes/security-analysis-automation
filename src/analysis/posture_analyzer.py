import datetime
from typing import Dict, Any, List
from src.llm.ollama_service import OllamaService
from src.analysis.signal_matcher import SignalMatcher

class PostureAnalyzer:
    def __init__(self, ollama_service: OllamaService, controls_file: str):
        self.ollama_service = ollama_service
        self.signal_matcher = SignalMatcher(controls_file, ollama_service)
        
    def generate_gap_narrative(self, control: Dict) -> str:
        if not self.ollama_service.is_available:
            return "No public information detected. Consider publishing documentation to strengthen this control."
            
        prompt = (
            f"Control: {control['control_name']} ({control['control_id']})\n"
            f"Control Description: {control.get('description', '')}\n"
            f"Current Status: No public evidence found\n\n"
            f"Generate a 1-paragraph, actionable explanation for why this control is missing evidence and "
            f"suggest what the company could publish to demonstrate compliance. Keep it concise and professional."
        )
        
        response = self.ollama_service.query(prompt)
        return response if response else "No public information detected. Consider publishing documentation."

    def analyze(self, domain: str, website_data: Dict, trust_center_data: Dict) -> Dict:
        matcher_result = self.signal_matcher.analyze(website_data, trust_center_data)
        controls = matcher_result["controls"]
        llm_fallback_count = matcher_result["llm_fallback_count"]
        
        # Calculate scores
        function_totals = {"Govern": 0, "Protect": 0, "Detect": 0, "Respond": 0, "Recover": 0}
        function_counts = {"Govern": 0, "Protect": 0, "Detect": 0, "Respond": 0, "Recover": 0}
        
        gaps = []
        
        for control in controls:
            func = control["function"]
            score = control["score"]
            function_totals[func] += score
            function_counts[func] += 1
            
            if score < 50:
                gap_narrative = self.generate_gap_narrative(control)
                control["gap_narrative"] = gap_narrative
                gaps.append({
                    "control_id": control["control_id"],
                    "gap_description": f"No public evidence found for {control['control_name']}",
                    "gap_narrative": gap_narrative,
                    "suggested_remediation": f"Publish documentation or evidence related to {control['control_name']}"
                })
                
        function_scores = {}
        for func, count in function_counts.items():
            if count > 0:
                function_scores[func] = round(function_totals[func] / count, 1)
            else:
                function_scores[func] = 0
                
        overall_posture = sum(function_scores.values()) / max(1, len(function_scores))
        overall_posture = round(overall_posture, 1)
        
        llm_notes = ""
        if llm_fallback_count > 0:
            llm_notes = f"LLM fallback was triggered for {llm_fallback_count} controls."
        elif not self.ollama_service.is_available:
            llm_notes = "LLM service unavailable. Operating in keyword-only mode."
        
        return {
            "domain": domain,
            "scan_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "trust_center_url": trust_center_data.get("url", ""),
            "llm_available": self.ollama_service.is_available,
            "metadata": {
                "company_name": domain.split('.')[0].capitalize(),
                "description": website_data.get("titles", [""])[0] if website_data.get("titles") else "",
                "website": f"https://{domain}"
            },
            "overall_posture_rating": overall_posture,
            "function_scores": function_scores,
            "controls": controls,
            "gaps": gaps,
            "llm_extraction_notes": llm_notes,
            "disclaimer": "This analysis is based on publicly available OSINT data and LLM-assisted semantic analysis. It is for educational purposes only and is not a compliance audit, certification, or professional opinion. All LLM-extracted claims are marked and should be independently verified. This tool should not be used for certification or regulatory claims."
        }

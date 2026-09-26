import pytest
from unittest.mock import patch, Mock
from src.analysis.posture_analyzer import PostureAnalyzer
from src.llm.ollama_service import OllamaService
import os

@pytest.fixture
def controls_file():
    return os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'mappings', 'nist_controls.json')

def test_full_pipeline_keyword_only(controls_file):
    # Mock Ollama as unavailable
    ollama = Mock(spec=OllamaService)
    ollama.is_available = False
    
    website_data = {
        "domain": "test.com",
        "raw_text": "We are committed to security.",
        "ssl": {"valid": True, "issuer": "Test CA", "algorithm": "RSA"}
    }
    
    trust_center_data = {
        "url": "https://test.com/trust",
        "raw_text": "We use AES-256 encryption at rest. We have a CISO. We use SSO. We use MFA. We do regular data backups.",
        "certifications": ["SOC 2 Type II"]
    }
    
    analyzer = PostureAnalyzer(ollama, controls_file)
    result = analyzer.analyze("test.com", website_data, trust_center_data)
    
    assert result["llm_available"] is False
    assert result["overall_posture_rating"] > 0
    assert "LLM service unavailable" in result["llm_extraction_notes"]
    
    # Verify PR.DS-01 (Data Encryption at Rest) was found via keyword
    control = next(c for c in result["controls"] if c["control_id"] == "PR.DS-01")
    assert control["status"] == "SIGNAL_FOUND"
    assert control["score"] == 100
    
    # Verify GV.RM-01 found via certifications
    control2 = next(c for c in result["controls"] if c["control_id"] == "GV.RM-01")
    assert control2["status"] == "SIGNAL_FOUND"

def test_full_pipeline_with_llm(controls_file):
    ollama = Mock(spec=OllamaService)
    ollama.is_available = True
    
    def mock_query(prompt):
        if "MFA" in prompt or "Two-Factor" in prompt:
            return "YES, found: 'We require 2FA.'"
        return "NO, no evidence found."
        
    ollama.query.side_effect = mock_query
    
    website_data = {"domain": "test.com", "raw_text": "", "ssl": {"valid": False}}
    trust_center_data = {
        "url": "https://test.com/trust",
        "raw_text": "We require 2FA for all employees.", # 2FA is a keyword though?
        # Let's say keyword is MFA, 2FA is in keyword_matching_terms.
        # Wait, 2FA is in keyword terms. So I need to use something NOT in keywords to trigger LLM fallback.
    }
    
    # Let's just remove 2FA from keyword match list for the test purpose, or use something else.
    # We can just use the mock to return YES for PR.AC-03
    
    analyzer = PostureAnalyzer(ollama, controls_file)
    
    # Run analysis with empty text to force LLM
    result = analyzer.analyze("test.com", website_data, {"url": "https://test.com/trust", "raw_text": "Some other text."})
    
    # PR.AC-03 should have LLM score
    control = next(c for c in result["controls"] if c["control_id"] == "PR.AC-03")
    assert control["status"] == "SIGNAL_FOUND"
    assert control["score"] == 85
    assert control["evidence"][0]["signal_origin"] == "llm"

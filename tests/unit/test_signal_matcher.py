import pytest
import os
from unittest.mock import Mock, patch
from src.analysis.signal_matcher import SignalMatcher, EvidenceCollector
from src.llm.ollama_service import OllamaService

@pytest.fixture
def mock_ollama():
    service = Mock(spec=OllamaService)
    service.is_available = True
    service.query.return_value = "YES, we have AES-256."
    return service

@pytest.fixture
def controls_file():
    return os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'mappings', 'nist_controls.json')

def test_evidence_collector():
    evidence = EvidenceCollector.create_evidence(
        quote="Test quote",
        source="https://test.com",
        source_type="trust_center",
        signal_origin="keyword",
        confidence=0.85
    )
    assert evidence["quote"] == "Test quote"
    assert evidence["source"] == "https://test.com"
    assert "timestamp" in evidence

def test_signal_matcher_keyword(mock_ollama, controls_file):
    matcher = SignalMatcher(controls_file, mock_ollama)
    
    website_data = {"raw_text": "Welcome."}
    tc_data = {"raw_text": "We use AES-256 for data at rest.", "url": "test.com/trust"}
    
    # Process PR.DS-01 (Data Encryption at Rest)
    control = next(c for c in matcher.controls if c["control_id"] == "PR.DS-01")
    
    result = matcher.process_control(control, website_data, tc_data)
    
    assert result["status"] == "SIGNAL_FOUND"
    assert result["score"] == 100
    assert len(result["evidence"]) == 1
    assert result["evidence"][0]["signal_origin"] == "keyword"
    mock_ollama.query.assert_not_called()

def test_signal_matcher_llm_fallback(mock_ollama, controls_file):
    matcher = SignalMatcher(controls_file, mock_ollama)
    
    website_data = {"raw_text": "Welcome."}
    tc_data = {"raw_text": "We secure data on disks.", "url": "test.com/trust"} # No keyword match for AES, etc.
    
    # Process PR.DS-01
    control = next(c for c in matcher.controls if c["control_id"] == "PR.DS-01")
    
    result = matcher.process_control(control, website_data, tc_data)
    
    assert result["status"] == "SIGNAL_FOUND"
    assert result["score"] == 85
    assert len(result["evidence"]) == 1
    assert result["evidence"][0]["signal_origin"] == "llm"
    mock_ollama.query.assert_called_once()

def test_signal_matcher_cert(mock_ollama, controls_file):
    matcher = SignalMatcher(controls_file, mock_ollama)
    
    website_data = {"ssl": {"valid": True, "algorithm": "RSA"}, "raw_text": ""}
    tc_data = {"raw_text": "", "url": "test.com/trust"}
    
    control = next(c for c in matcher.controls if c["control_id"] == "PR.DS-02")
    
    result = matcher.process_control(control, website_data, tc_data)
    
    assert result["status"] == "SIGNAL_FOUND"
    assert result["score"] == 100
    assert len(result["evidence"]) == 1
    assert result["evidence"][0]["signal_origin"] == "cert"

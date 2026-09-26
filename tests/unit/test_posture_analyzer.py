import pytest
import os
from unittest.mock import Mock, patch
from src.analysis.posture_analyzer import PostureAnalyzer
from src.llm.ollama_service import OllamaService

@pytest.fixture
def mock_ollama():
    service = Mock(spec=OllamaService)
    service.is_available = True
    service.query.return_value = "Mocked LLM narrative."
    return service

@pytest.fixture
def controls_file():
    return os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'mappings', 'nist_controls.json')

def test_posture_analyzer_scoring(mock_ollama, controls_file):
    analyzer = PostureAnalyzer(mock_ollama, controls_file)
    
    # Mock SignalMatcher.analyze
    mock_controls = [
        {"control_id": "C1", "control_name": "C1", "function": "Govern", "score": 100, "status": "SIGNAL_FOUND", "evidence": []},
        {"control_id": "C2", "control_name": "C2", "function": "Protect", "score": 85, "status": "SIGNAL_FOUND", "evidence": [], "llm_triggered": True},
        {"control_id": "C3", "control_name": "C3", "function": "Protect", "score": 0, "status": "SIGNAL_NOT_FOUND", "evidence": []},
        {"control_id": "C4", "control_name": "C4", "function": "Detect", "score": 100, "status": "SIGNAL_FOUND", "evidence": []},
        {"control_id": "C5", "control_name": "C5", "function": "Respond", "score": 0, "status": "SIGNAL_NOT_FOUND", "evidence": []},
        {"control_id": "C6", "control_name": "C6", "function": "Recover", "score": 100, "status": "SIGNAL_FOUND", "evidence": []}
    ]
    
    with patch('src.analysis.posture_analyzer.SignalMatcher.analyze') as mock_analyze:
        mock_analyze.return_value = {"controls": mock_controls, "llm_fallback_count": 1}
        
        result = analyzer.analyze("test.com", {}, {})
        
        # Check scores
        assert result["function_scores"]["Govern"] == 100.0
        assert result["function_scores"]["Protect"] == 42.5  # (85 + 0) / 2
        
        # Check gaps
        assert len(result["gaps"]) == 2
        assert result["gaps"][0]["control_id"] == "C3"
        assert result["gaps"][0]["gap_narrative"] == "Mocked LLM narrative."
        
        # Check overall score
        # Functions: Gov: 100, Pro: 42.5, Det: 100, Res: 0, Rec: 100
        # Avg = (100 + 42.5 + 100 + 0 + 100) / 5 = 68.5
        assert result["overall_posture_rating"] == 68.5

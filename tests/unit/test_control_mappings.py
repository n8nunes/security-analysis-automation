import json
import os
from pathlib import Path

def test_nist_controls_mapping():
    mappings_file = Path(__file__).parent.parent.parent / "src" / "mappings" / "nist_controls.json"
    assert mappings_file.exists()
    
    with open(mappings_file, "r") as f:
        controls = json.load(f)
        
    assert len(controls) == 20
    
    function_counts = {
        "Govern": 0,
        "Protect": 0,
        "Detect": 0,
        "Respond": 0,
        "Recover": 0
    }
    
    required_keys = {
        "control_id",
        "control_name",
        "function",
        "description",
        "observable_signals",
        "confidence_level",
        "data_sources",
        "evidence_format",
        "keyword_matching_terms",
        "llm_extraction_prompt"
    }
    
    control_ids = set()
    
    for control in controls:
        # Check required keys
        assert set(control.keys()) == required_keys
        
        # Check no duplicates
        assert control["control_id"] not in control_ids
        control_ids.add(control["control_id"])
        
        # Check function
        assert control["function"] in function_counts
        function_counts[control["function"]] += 1
        
        # Check confidence level
        assert control["confidence_level"] == "HIGH"
        
    # Check distribution
    assert function_counts["Govern"] == 5
    assert function_counts["Protect"] == 8
    assert function_counts["Detect"] == 4
    assert function_counts["Respond"] == 2
    assert function_counts["Recover"] == 1

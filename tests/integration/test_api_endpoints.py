import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, Mock
from src.api.main import app, ollama_service

client = TestClient(app)

def test_health_check():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "ollama_available" in data

def test_get_config():
    response = client.get("/api/config")
    assert response.status_code == 200
    data = response.json()
    assert "ollama_model" in data

@patch('src.api.main.WebsiteScanner.run_scan')
@patch('src.api.main.TrustCenterScanner.scan')
@patch('src.api.main.PostureAnalyzer.analyze')
def test_scan_endpoint_success(mock_analyze, mock_tc_scan, mock_web_scan):
    mock_web_scan.return_value = {"links": ["https://test.com/trust"]}
    mock_tc_scan.return_value = {"found": True, "url": "https://test.com/trust", "raw_text": "data"}
    mock_analyze.return_value = {"overall_posture_rating": 85.0}

    response = client.post("/api/scan", json={"domain": "test.com"})
    
    assert response.status_code == 200
    assert response.json() == {"overall_posture_rating": 85.0}

@patch('src.api.main.WebsiteScanner.run_scan')
@patch('src.api.main.TrustCenterScanner.scan')
def test_scan_endpoint_tc_not_found(mock_tc_scan, mock_web_scan):
    mock_web_scan.return_value = {"links": ["https://test.com/blog"]}
    mock_tc_scan.return_value = {"found": False, "candidates": ["https://test.com/blog"]}

    response = client.post("/api/scan", json={"domain": "test.com"})
    
    assert response.status_code == 200
    assert "candidates" in response.json()
    assert response.json()["error"] == "Trust Center could not be auto-detected"

def test_scan_endpoint_invalid_domain():
    response = client.post("/api/scan", json={"domain": "invalid_domain!"})
    assert response.status_code == 400

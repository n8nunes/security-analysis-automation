import pytest
from unittest.mock import patch, Mock
import requests
from src.llm.ollama_service import OllamaService

@pytest.fixture
def mock_requests_get():
    with patch("src.llm.ollama_service.requests.get") as mock_get:
        yield mock_get

@pytest.fixture
def mock_requests_post():
    with patch("src.llm.ollama_service.requests.post") as mock_post:
        yield mock_post

def test_ollama_service_initialization_success(mock_requests_get):
    # Mock /api/tags response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "models": [{"name": "llama3.1:latest"}]
    }
    mock_requests_get.return_value = mock_response

    service = OllamaService()
    assert service.initialize() is True
    assert service.is_available is True

def test_ollama_service_initialization_no_server(mock_requests_get):
    mock_requests_get.side_effect = requests.RequestException("Connection error")

    service = OllamaService()
    assert service.initialize() is False
    assert service.is_available is False

def test_ollama_service_initialization_no_model(mock_requests_get):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "models": [{"name": "llama3:latest"}] # Different model
    }
    mock_requests_get.return_value = mock_response

    service = OllamaService()
    assert service.initialize() is False
    assert service.is_available is False

def test_ollama_service_query_success(mock_requests_post):
    service = OllamaService()
    service.is_available = True
    
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "response": "YES, found: 'All data is encrypted'"
    }
    mock_requests_post.return_value = mock_response

    result = service.query("Test prompt")
    assert result == "YES, found: 'All data is encrypted'"
    mock_requests_post.assert_called_once()
    
def test_ollama_service_query_unavailable(mock_requests_post):
    service = OllamaService()
    service.is_available = False
    
    result = service.query("Test prompt")
    assert result is None
    mock_requests_post.assert_not_called()

def test_ollama_service_query_timeout(mock_requests_post):
    service = OllamaService()
    service.is_available = True
    
    mock_requests_post.side_effect = requests.RequestException("Timeout")
    
    result = service.query("Test prompt")
    assert result is None

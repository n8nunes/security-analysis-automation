import os
import logging
from typing import Dict, Any, Optional
import requests

logger = logging.getLogger(__name__)

class OllamaService:
    def __init__(self, host: str = None, model: str = None, timeout: int = None):
        self.host = host or os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3.1")
        self.timeout = timeout or int(os.getenv("OLLAMA_TIMEOUT", 30))
        self.temperature = 0.2
        self.max_tokens = 500
        self.is_available = False
        
        self.system_prompt = (
            "You are a security compliance expert analyzing documents for NIST Cybersecurity Framework controls.\n"
            "You must extract information conservatively—only report what is explicitly stated or clearly implied.\n"
            "When asked about a specific control, respond with ONLY: YES or NO, followed by the exact quote from the document that supports your answer.\n"
            "If no evidence is found, respond with: NO, no evidence found.\n"
            "Do not speculate, infer, or make assumptions about capabilities not explicitly mentioned."
        )

    def initialize(self) -> bool:
        """Check if Ollama is running and the model is available."""
        if not self.check_health():
            logger.warning(f"Ollama server is not accessible at {self.host}. Degrading to keyword-only mode.")
            self.is_available = False
            return False

        if not self.check_model():
            logger.warning(f"Model {self.model} is not available on Ollama server. Degrading to keyword-only mode.")
            self.is_available = False
            return False

        self.is_available = True
        logger.info("Ollama service initialized successfully.")
        return True

    def check_health(self) -> bool:
        """Check if the Ollama server is responsive."""
        try:
            response = requests.get(f"{self.host}/api/tags", timeout=self.timeout)
            return response.status_code == 200
        except requests.RequestException:
            return False

    def check_model(self) -> bool:
        """Check if the specified model is present on the server."""
        try:
            response = requests.get(f"{self.host}/api/tags", timeout=self.timeout)
            if response.status_code == 200:
                tags = response.json().get("models", [])
                for tag in tags:
                    # Model name could be 'llama3.1' or 'llama3.1:latest' or 'llama3.1:8b'
                    if tag.get("name", "").startswith(self.model):
                        return True
            return False
        except requests.RequestException:
            return False

    def query(self, prompt: str) -> Optional[str]:
        """Send a prompt to the Ollama model."""
        if not self.is_available:
            return None

        try:
            response = requests.post(
                f"{self.host}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "system": self.system_prompt,
                    "stream": False,
                    "options": {
                        "temperature": self.temperature,
                        "num_predict": self.max_tokens
                    }
                },
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()
            return data.get("response", "").strip()
        except requests.RequestException as e:
            logger.error(f"Error querying Ollama: {e}")
            return None

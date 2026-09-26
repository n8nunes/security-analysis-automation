import os
import logging
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import Optional, Dict, Any

from src.llm.ollama_service import OllamaService
from src.scanners.website_scanner import WebsiteScanner
from src.scanners.trust_center_scanner import TrustCenterScanner
from src.analysis.posture_analyzer import PostureAnalyzer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="NIST CSF Security Posture Analysis Tool")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global instances
ollama_service = OllamaService()
CONTROLS_FILE = os.path.join(os.path.dirname(__file__), '..', 'mappings', 'nist_controls.json')

class ScanRequest(BaseModel):
    domain: str
    trust_center_url: Optional[str] = None

@app.on_event("startup")
async def startup_event():
    logger.info("Initializing Ollama service...")
    ollama_service.initialize()
    logger.info(f"Ollama available: {ollama_service.is_available}")

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "ollama_available": ollama_service.is_available,
        "ollama_model": ollama_service.model
    }

@app.get("/api/config")
async def get_config():
    return {
        "ollama_host": ollama_service.host,
        "ollama_model": ollama_service.model,
        "ollama_timeout": ollama_service.timeout,
        "keyword_match_threshold": 0.6,
        "enable_llm": True
    }

@app.post("/api/scan")
async def perform_scan(request: ScanRequest):
    try:
        logger.info(f"Starting scan for {request.domain}")
        
        # 1. Scan Website
        website_scanner = WebsiteScanner(request.domain)
        try:
            website_data = website_scanner.run_scan()
        except Exception as e:
            logger.error(f"Website scan failed: {e}")
            raise HTTPException(status_code=503, detail="Website unreachable or invalid domain")

        # 2. Scan Trust Center
        trust_center_scanner = TrustCenterScanner(request.domain, provided_url=request.trust_center_url)
        trust_center_data = trust_center_scanner.scan(website_data.get("links", []))
        
        if not trust_center_data.get("found") and not request.trust_center_url:
            # Could not auto-detect, return candidates
            return {
                "error": "Trust Center could not be auto-detected",
                "candidates": trust_center_data.get("candidates", [])
            }

        # 3. Analyze Posture
        analyzer = PostureAnalyzer(ollama_service, CONTROLS_FILE)
        result = analyzer.analyze(request.domain, website_data, trust_center_data)
        
        logger.info(f"Scan complete for {request.domain}. Score: {result['overall_posture_rating']}")
        return result

    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Scan error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/scan/{domain}")
async def get_scan(domain: str):
    return {"message": "Caching not implemented in MVP"}

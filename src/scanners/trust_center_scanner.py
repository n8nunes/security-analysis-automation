import urllib.request
import urllib.parse
from urllib.error import URLError
from bs4 import BeautifulSoup
import re
import json
from typing import Dict, Any, List, Optional

class TrustCenterScanner:
    def __init__(self, domain: str, provided_url: Optional[str] = None):
        self.domain = domain
        self.base_url = f"https://{self.domain}"
        self.provided_url = provided_url
        
    def fetch_url(self, url: str) -> str:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.getcode() == 200:
                    return response.read().decode('utf-8')
        except Exception:
            pass
        return ""

    def detect_trust_center(self, website_links: List[str]) -> Dict[str, Any]:
        if self.provided_url:
            content = self.fetch_url(self.provided_url)
            if content:
                return {"url": self.provided_url, "content": content}

        patterns = [
            "/trust", "/trust-center", "/security", "/compliance", "/security/compliance"
        ]
        
        for pattern in patterns:
            url = f"{self.base_url}{pattern}"
            content = self.fetch_url(url)
            if content:
                # Basic validation it's a real page, not a soft 404
                if "page not found" not in content.lower() and "404" not in content:
                    return {"url": url, "content": content}
        
        # Fallback to candidate links
        candidates = []
        for link in website_links:
            if any(term in link.lower() for term in ['trust', 'security', 'compliance']):
                candidates.append(link)
                
        return {"url": None, "candidates": candidates, "content": ""}

    def extract_certifications(self, text: str) -> List[str]:
        certifications = []
        patterns = {
            "SOC 2 Type II": r"soc\s*2\s*type\s*ii",
            "SOC 2": r"soc\s*2",
            "SOC 3": r"soc\s*3",
            "ISO 27001": r"iso\s*27001",
            "FedRAMP": r"fedramp",
            "PCI-DSS": r"pci[\s-]*dss",
            "HIPAA": r"hipaa",
            "GDPR": r"gdpr"
        }
        
        lower_text = text.lower()
        for cert, pattern in patterns.items():
            if re.search(pattern, lower_text):
                certifications.append(cert)
                
        return list(set(certifications))
        
    def extract_json_ld(self, soup: BeautifulSoup) -> List[Dict]:
        structured_data = []
        for script in soup.find_all('script', type='application/ld+json'):
            if script.string:
                try:
                    data = json.loads(script.string)
                    if isinstance(data, list):
                        structured_data.extend(data)
                    else:
                        structured_data.append(data)
                except json.JSONDecodeError:
                    pass
        return structured_data

    def scan(self, website_links: List[str]) -> Dict[str, Any]:
        detection = self.detect_trust_center(website_links)
        url = detection.get("url")
        content = detection.get("content", "")
        
        if not url:
            return {
                "found": False,
                "candidates": detection.get("candidates", []),
                "error": "Trust Center could not be auto-detected."
            }
            
        soup = BeautifulSoup(content, 'html.parser')
        
        # Extract raw text
        raw_text = ""
        for p in soup.find_all(['p', 'li', 'h1', 'h2', 'h3', 'h4']):
            if p.text:
                raw_text += p.text.strip() + "\n"
                
        # Extract certifications
        certs = self.extract_certifications(raw_text)
        
        # Extract structured data
        structured_data = self.extract_json_ld(soup)
        
        return {
            "found": True,
            "url": url,
            "raw_text": raw_text,
            "certifications": certs,
            "structured_data": structured_data
        }

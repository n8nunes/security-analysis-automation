import ssl
import socket
import urllib.request
import urllib.parse
from urllib.error import URLError
from bs4 import BeautifulSoup
import re
from typing import Dict, Any, List
import dns.resolver

class WebsiteScanner:
    def __init__(self, domain: str):
        self.domain = self.validate_domain(domain)
        self.base_url = f"https://{self.domain}"
        
    def validate_domain(self, domain: str) -> str:
        # Simple domain validation
        domain = domain.strip().lower()
        if domain.startswith("http://") or domain.startswith("https://"):
            domain = urllib.parse.urlparse(domain).netloc
        if not re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", domain):
            raise ValueError(f"Invalid domain format: {domain}")
        return domain
        
    def fetch_url(self, url: str) -> str:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                return response.read().decode('utf-8')
        except Exception:
            return ""

    def scan_pages(self) -> Dict[str, Any]:
        pages_to_check = [
            "/", "/security", "/security-center", "/trust", 
            "/compliance", "/about", "/robots.txt", "/.well-known/security.txt"
        ]
        
        extracted_text = ""
        external_links = set()
        titles = []
        
        for page in pages_to_check:
            content = self.fetch_url(f"{self.base_url}{page}")
            if content:
                if page.endswith(".txt"):
                    extracted_text += content + "\n"
                    continue
                    
                soup = BeautifulSoup(content, 'html.parser')
                if soup.title and soup.title.string:
                    titles.append(soup.title.string)
                    
                for p in soup.find_all('p'):
                    if p.text:
                        extracted_text += p.text + " "
                
                for a in soup.find_all('a', href=True):
                    href = a['href']
                    if href.startswith('http') and self.domain not in href:
                        external_links.add(href)
                    elif href.startswith('/'):
                        # Keep internal links if they look like trust center
                        if 'trust' in href or 'security' in href or 'compliance' in href:
                            external_links.add(f"{self.base_url}{href}")
                            
        return {
            "titles": titles,
            "raw_text": extracted_text,
            "links": list(external_links)
        }

    def get_ssl_certificate(self) -> Dict[str, Any]:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        "issuer": dict(x[0] for x in cert.get('issuer', []))['organizationName'],
                        "expires": cert.get('notAfter', ''),
                        "algorithm": ssock.cipher()[0] if ssock.cipher() else "Unknown",
                        "valid": True
                    }
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def get_dns_records(self) -> Dict[str, List[str]]:
        records = {"A": [], "MX": [], "DMARC": []}
        try:
            for rdata in dns.resolver.resolve(self.domain, 'A'):
                records["A"].append(rdata.to_text())
        except Exception: pass
        
        try:
            for rdata in dns.resolver.resolve(self.domain, 'MX'):
                records["MX"].append(rdata.to_text())
        except Exception: pass
        
        try:
            for rdata in dns.resolver.resolve(f"_dmarc.{self.domain}", 'TXT'):
                records["DMARC"].append(rdata.to_text())
        except Exception: pass
        
        return records

    def run_scan(self) -> Dict[str, Any]:
        data = self.scan_pages()
        data["ssl"] = self.get_ssl_certificate()
        data["dns"] = self.get_dns_records()
        return data

import pytest
from unittest.mock import patch, Mock
from src.scanners.website_scanner import WebsiteScanner
from src.scanners.trust_center_scanner import TrustCenterScanner

@patch('src.scanners.website_scanner.urllib.request.urlopen')
def test_website_scanner(mock_urlopen):
    mock_response = Mock()
    mock_response.read.return_value = b"<html><title>Test Security</title><body><p>We use AES-256 encryption.</p><a href='https://other.com'>External</a><a href='/trust'>Trust Center</a></body></html>"
    mock_urlopen.return_value.__enter__.return_value = mock_response

    scanner = WebsiteScanner("stripe.com")
    
    with patch.object(scanner, 'get_ssl_certificate') as mock_ssl:
        with patch.object(scanner, 'get_dns_records') as mock_dns:
            mock_ssl.return_value = {"valid": True, "issuer": "Test", "algorithm": "RSA"}
            mock_dns.return_value = {"A": ["1.1.1.1"]}
            
            result = scanner.run_scan()
            
            assert "titles" in result
            assert "Test Security" in result["titles"]
            assert "AES-256" in result["raw_text"]
            assert "https://other.com" in result["links"]
            assert "https://stripe.com/trust" in result["links"]

@patch('src.scanners.trust_center_scanner.urllib.request.urlopen')
def test_trust_center_scanner_auto_detect(mock_urlopen):
    mock_response = Mock()
    mock_response.getcode.return_value = 200
    mock_response.read.return_value = b"<html><body><p>We are SOC 2 Type II and ISO 27001 certified.</p></body></html>"
    mock_urlopen.return_value.__enter__.return_value = mock_response

    scanner = TrustCenterScanner("stripe.com")
    result = scanner.scan([])
    
    assert result["found"] is True
    assert result["url"] == "https://stripe.com/trust"
    assert "SOC 2 Type II" in result["certifications"]
    assert "ISO 27001" in result["certifications"]

@patch('src.scanners.trust_center_scanner.urllib.request.urlopen')
def test_trust_center_scanner_manual_url(mock_urlopen):
    mock_response = Mock()
    mock_response.getcode.return_value = 200
    mock_response.read.return_value = b"<html><body><p>PCI-DSS compliant</p></body></html>"
    mock_urlopen.return_value.__enter__.return_value = mock_response

    scanner = TrustCenterScanner("stripe.com", provided_url="https://stripe.com/custom-trust")
    result = scanner.scan([])
    
    assert result["found"] is True
    assert result["url"] == "https://stripe.com/custom-trust"
    assert "PCI-DSS" in result["certifications"]

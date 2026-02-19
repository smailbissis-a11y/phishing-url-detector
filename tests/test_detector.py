"""
Unit Tests for Phishing URL Detector
=====================================
Run with: pytest tests/test_detector.py -v

Author: [Your Name]
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.url_features import URLFeatureExtractor
from utils.detector import PhishingDetector


class TestURLFeatureExtractor:
    """Tests for the URLFeatureExtractor class."""
    
    def test_safe_url_parsing(self):
        """Test that safe URLs are parsed correctly."""
        url = "https://www.google.com"
        extractor = URLFeatureExtractor(url)
        
        assert extractor.domain == "www.google.com"
        assert extractor.parsed.scheme == "https"
    
    def test_url_without_scheme(self):
        """Test URLs without http/https prefix."""
        url = "example.com"
        extractor = URLFeatureExtractor(url)
        
        # Should add http:// by default
        assert extractor.parsed.scheme == "http"
    
    def test_ip_address_detection(self):
        """Test detection of IP addresses in URL."""
        url = "http://192.168.1.1/login"
        extractor = URLFeatureExtractor(url)
        
        assert extractor.has_ip_address() == True
    
    def test_domain_name_not_ip(self):
        """Test that domain names are not detected as IP."""
        url = "https://www.google.com"
        extractor = URLFeatureExtractor(url)
        
        assert extractor.has_ip_address() == False
    
    def test_at_symbol_detection(self):
        """Test detection of @ symbol (phishing trick)."""
        url = "http://legitimate.com@phishing.com"
        extractor = URLFeatureExtractor(url)
        
        assert extractor.has_at_symbol() == True
    
    def test_no_at_symbol_in_normal_url(self):
        """Test that normal URLs don't have @ symbol."""
        url = "https://www.google.com/search?q=test"
        extractor = URLFeatureExtractor(url)
        
        assert extractor.has_at_symbol() == False
    
    def test_https_detection(self):
        """Test HTTPS protocol detection."""
        url = "https://secure-site.com"
        extractor = URLFeatureExtractor(url)
        
        assert extractor.uses_https() == True
    
    def test_http_detection(self):
        """Test HTTP protocol detection."""
        url = "http://insecure-site.com"
        extractor = URLFeatureExtractor(url)
        
        assert extractor.uses_https() == False
    
    def test_suspicious_keywords(self):
        """Test detection of suspicious keywords."""
        url = "http://secure-login-verify.com/account/urgent"
        extractor = URLFeatureExtractor(url)
        
        assert extractor.has_suspicious_keywords() == True
    
    def test_dash_in_domain(self):
        """Test detection of dashes in domain."""
        url = "http://amazon-secure-account.com"
        extractor = URLFeatureExtractor(url)
        
        assert extractor.has_dash_in_domain() == True
    
    def test_suspicious_tld(self):
        """Test detection of suspicious TLDs."""
        url = "http://bank-account.xyz"
        extractor = URLFeatureExtractor(url)
        
        assert extractor.has_suspicious_tld() == True
    
    def test_legitimate_tld(self):
        """Test that legitimate TLDs pass."""
        url = "https://www.amazon.com"
        extractor = URLFeatureExtractor(url)
        
        assert extractor.has_suspicious_tld() == False
    
    def test_subdomain_count(self):
        """Test subdomain counting."""
        url = "https://a.b.c.d.example.com"
        extractor = URLFeatureExtractor(url)
        
        # a.b.c.d are subdomains, example.com is domain + TLD
        assert extractor.count_subdomains() == 4
    
    def test_get_all_features(self):
        """Test that all features are extracted."""
        url = "https://www.google.com"
        extractor = URLFeatureExtractor(url)
        features = extractor.get_all_features()
        
        # Check that we get a dictionary
        assert isinstance(features, dict)
        
        # Check that expected features exist
        expected_features = [
            'url_length', 'domain_length', 'path_length',
            'has_ip_address', 'has_at_symbol', 'uses_https'
        ]
        
        for feature in expected_features:
            assert feature in features


class TestPhishingDetector:
    """Tests for the PhishingDetector class."""
    
    def setup_method(self):
        """Set up detector for each test."""
        self.detector = PhishingDetector()
    
    def test_safe_url_analysis(self):
        """Test analysis of a known safe URL."""
        result = self.detector.analyze("https://www.google.com")
        
        assert result['risk_level'] == 'safe'
        assert result['risk_score'] < 15
    
    def test_phishing_url_with_ip(self):
        """Test detection of phishing URL with IP address."""
        result = self.detector.analyze("http://192.168.1.1/secure-login")
        
        assert result['risk_level'] in ['suspicious', 'phishing']
        assert any('IP address' in w['message'] for w in result['warnings'])
    
    def test_phishing_url_with_at_symbol(self):
        """Test detection of @ symbol phishing."""
        result = self.detector.analyze("http://bank.com@evil.com")
        
        assert result['risk_level'] == 'phishing'
        assert any('@ symbol' in w['message'] for w in result['warnings'])
    
    def test_suspicious_url_with_keywords(self):
        """Test detection of suspicious keywords."""
        result = self.detector.analyze("http://secure-login-verify.xyz/account")
        
        # Should have warnings about keywords or suspicious TLD
        assert len(result['warnings']) > 0
    
    def test_result_structure(self):
        """Test that analysis result has correct structure."""
        result = self.detector.analyze("https://example.com")
        
        # Check required fields exist
        assert 'url' in result
        assert 'risk_score' in result
        assert 'risk_level' in result
        assert 'features' in result
        assert 'warnings' in result
        assert 'recommendations' in result
        assert 'analysis_summary' in result
    
    def test_warnings_have_severity(self):
        """Test that warnings include severity level."""
        result = self.detector.analyze("http://192.168.1.1@login.xyz")
        
        if result['warnings']:
            warning = result['warnings'][0]
            assert 'severity' in warning
            assert 'message' in warning
            assert 'explanation' in warning
    
    def test_recommendations_generated(self):
        """Test that recommendations are always generated."""
        result = self.detector.analyze("https://google.com")
        
        assert len(result['recommendations']) > 0
    
    def test_score_capped_at_100(self):
        """Test that risk score is capped at 100."""
        # Create a URL with many phishing indicators
        result = self.detector.analyze(
            "http://192.168.1.1@login-secure-verify.account.bank.xyz:8080/"
            "@evil.com//phishing?cmd=urgent&verify=account"
        )
        
        assert result['risk_score'] <= 100


# ==================== RUN TESTS ====================

if __name__ == '__main__':
    import pytest
    
    print("=" * 60)
    print("Running Phishing URL Detector Tests")
    print("=" * 60)
    
    # Run tests with verbose output
    pytest.main([__file__, '-v'])

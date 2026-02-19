"""
URL Feature Extraction Module
=============================
This module extracts various features from URLs that help identify phishing attempts.
These features are based on common patterns found in malicious URLs.

Author: [Your Name]
Purpose: Cybersecurity Portfolio Project
"""

import re
from urllib.parse import urlparse
import ipaddress


class URLFeatureExtractor:
    """
    A class to extract features from URLs for phishing detection.
    
    Each feature is designed to detect a specific characteristic that is
    commonly found in phishing URLs.
    """
    
    def __init__(self, url):
        """
        Initialize the extractor with a URL.
        
        Args:
            url (str): The URL to analyze
        """
        # Add scheme if missing (for proper parsing)
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        self.url = url
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.path = self.parsed.path
        
    def get_all_features(self):
        """
        Extract all features and return as a dictionary.
        
        Returns:
            dict: Dictionary containing all extracted features
        """
        features = {
            # Basic URL properties
            'url_length': self.get_url_length(),
            'domain_length': self.get_domain_length(),
            'path_length': self.get_path_length(),
            
            # Character-based features
            'has_ip_address': self.has_ip_address(),
            'has_at_symbol': self.has_at_symbol(),
            'has_double_slash': self.has_double_slash_redirect(),
            'has_dash_in_domain': self.has_dash_in_domain(),
            'has_multiple_dots': self.has_multiple_dots(),
            'has_suspicious_tld': self.has_suspicious_tld(),
            
            # Security-related features
            'uses_https': self.uses_https(),
            'has_https_in_domain': self.has_https_in_domain(),
            
            # Content features
            'has_suspicious_keywords': self.has_suspicious_keywords(),
            'num_subdomains': self.count_subdomains(),
            'has_port_number': self.has_port_number(),
            'has_encoded_chars': self.has_encoded_chars(),
        }
        
        return features
    
    # ==================== BASIC LENGTH FEATURES ====================
    
    def get_url_length(self):
        """
        Get the total length of the URL.
        
        Phishing URLs are often very long because they contain:
        - Encoded data
        - Redirect paths
        - Tracking parameters
        
        Returns:
            int: Length of URL
        """
        return len(self.url)
    
    def get_domain_length(self):
        """
        Get the length of the domain name.
        
        Legitimate domains are usually short and memorable.
        Phishing domains might be long to mimic legitimate ones.
        
        Returns:
            int: Length of domain
        """
        return len(self.domain)
    
    def get_path_length(self):
        """
        Get the length of the URL path.
        
        Long paths might indicate attempts to hide the true destination.
        
        Returns:
            int: Length of path
        """
        return len(self.path)
    
    # ==================== CHARACTER-BASED FEATURES ====================
    
    def has_ip_address(self):
        """
        Check if the domain is an IP address instead of a domain name.
        
        Legitimate websites rarely use IP addresses directly.
        Phishing sites often use IP addresses to:
        - Hide the domain registration
        - Quickly change hosting
        
        Returns:
            bool: True if IP address found, False otherwise
        """
        try:
            # Remove port number if present
            domain_to_check = self.domain.split(':')[0]
            ipaddress.ip_address(domain_to_check)
            return True
        except ValueError:
            return False
    
    def has_at_symbol(self):
        """
        Check if URL contains the @ symbol.
        
        The @ symbol can be used to:
        - Hide the actual domain (e.g., http://legitimate.com@phishing.com)
        - The browser ignores everything before @
        
        This is a strong phishing indicator.
        
        Returns:
            bool: True if @ symbol found
        """
        return '@' in self.url
    
    def has_double_slash_redirect(self):
        """
        Check for double slash in path (not including http://).
        
        Attackers use // to redirect to another domain:
        - http://legitimate.com//phishing.com
        
        Returns:
            bool: True if suspicious double slash found
        """
        # Remove the protocol part (http:// or https://)
        url_without_protocol = self.url.replace('://', '', 1)
        return '//' in url_without_protocol
    
    def has_dash_in_domain(self):
        """
        Check if domain contains dash (-) character.
        
        Phishing domains often use dashes to mimic legitimate domains:
        - amazon-secure.com (fake)
        - amazon.com (real)
        
        Returns:
            bool: True if dash found in domain
        """
        return '-' in self.domain
    
    def has_multiple_dots(self):
        """
        Check if domain has many dots (subdomains).
        
        Phishing sites might use many subdomains to:
        - Confuse the user
        - Make URL look legitimate
        
        Example: secure.login.account.bank.com.phishing.com
        
        Returns:
            bool: True if more than 3 dots in domain
        """
        return self.domain.count('.') > 3
    
    def has_suspicious_tld(self):
        """
        Check for suspicious top-level domains (TLDs).
        
        Some TLDs are commonly used for phishing:
        - .xyz, .tk, .ml, .ga, .cf (often free or cheap)
        
        Returns:
            bool: True if suspicious TLD found
        """
        suspicious_tlds = [
            '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw',
            '.cc', '.top', '.work', '.click', '.link', '.info'
        ]
        
        domain_lower = self.domain.lower()
        return any(domain_lower.endswith(tld) for tld in suspicious_tlds)
    
    # ==================== SECURITY FEATURES ====================
    
    def uses_https(self):
        """
        Check if URL uses HTTPS protocol.
        
        While HTTPS is good, many phishing sites now also use HTTPS
        to appear legitimate. This alone is not a reliable indicator.
        
        Returns:
            bool: True if HTTPS is used
        """
        return self.parsed.scheme == 'https'
    
    def has_https_in_domain(self):
        """
        Check if 'https' appears in the domain name itself.
        
        Attackers might include 'https' in domain to trick users:
        - https-secure-bank.com (fake)
        
        Returns:
            bool: True if 'https' found in domain
        """
        return 'https' in self.domain.lower()
    
    # ==================== CONTENT FEATURES ====================
    
    def has_suspicious_keywords(self):
        """
        Check for suspicious keywords in URL.
        
        Phishing URLs often contain words designed to:
        - Create urgency (urgent, immediate)
        - Request sensitive info (login, verify, secure)
        - Mimic legitimate services
        
        Returns:
            bool: True if suspicious keywords found
        """
        suspicious_keywords = [
            'login', 'signin', 'verify', 'account', 'secure',
            'update', 'confirm', 'password', 'banking', 'alert',
            'urgent', 'immediate', 'suspended', 'limited',
            'authenticate', 'validation', 'security', 'wallet',
            'verify', 'confirm', 'webscr', 'cmd', '_login'
        ]
        
        url_lower = self.url.lower()
        found_keywords = [kw for kw in suspicious_keywords if kw in url_lower]
        
        return len(found_keywords) > 0
    
    def count_subdomains(self):
        """
        Count the number of subdomains.
        
        Phishing sites often use multiple subdomains:
        - secure.account.login.legitimate-site.com
        
        Returns:
            int: Number of subdomains
        """
        if not self.domain:
            return 0
        
        # Split domain and subtract 2 for domain + TLD
        parts = self.domain.split('.')
        subdomain_count = len(parts) - 2
        
        return max(0, subdomain_count)
    
    def has_port_number(self):
        """
        Check if URL explicitly includes a port number.
        
        Legitimate sites rarely show port numbers in URLs.
        Phishing sites might use non-standard ports.
        
        Returns:
            bool: True if port number is specified
        """
        return ':' in self.domain
    
    def has_encoded_chars(self):
        """
        Check for URL encoded characters.
        
        Attackers encode characters to:
        - Hide suspicious content
        - Bypass filters
        
        Common encodings: %20 (space), %3A (:), %2F (/)
        
        Returns:
            bool: True if encoded characters found
        """
        # Look for percent encoding pattern
        return '%' in self.url


# ==================== TESTING ====================
# This code runs when you test the module directly

if __name__ == '__main__':
    # Test URLs
    test_urls = [
        'https://www.google.com',  # Legitimate
        'http://192.168.1.1/login',  # IP address
        'http://amazon-secure-account.com/verify',  # Suspicious
        'https://bank.com@phishing-site.com',  # @ symbol trick
    ]
    
    print("=" * 60)
    print("URL Feature Extraction Test")
    print("=" * 60)
    
    for url in test_urls:
        print(f"\nURL: {url}")
        print("-" * 40)
        extractor = URLFeatureExtractor(url)
        features = extractor.get_all_features()
        
        for feature, value in features.items():
            print(f"  {feature}: {value}")

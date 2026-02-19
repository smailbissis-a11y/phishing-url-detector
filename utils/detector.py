"""
Phishing Detection Engine
=========================
This module analyzes URLs and determines the likelihood of them being phishing.

The detection uses a scoring system based on multiple factors:
- Each suspicious feature adds points to the risk score
- Higher score = Higher risk of being phishing

Author: [Your Name]
Purpose: Cybersecurity Portfolio Project
"""

from utils.url_features import URLFeatureExtractor


class PhishingDetector:
    """
    Main phishing detection class that analyzes URLs and provides
    a risk assessment with detailed explanations.
    """
    
    def __init__(self):
        """
        Initialize the detector with scoring weights.
        
        Each feature has a weight based on how strongly it indicates phishing:
        - High weight: Strong phishing indicator
        - Medium weight: Common in phishing but not conclusive
        - Low weight: Minor indicator
        """
        # Define weights for each feature
        # Higher weight = stronger indicator of phishing
        self.weights = {
            # High-risk indicators (strong phishing signals)
            'has_ip_address': 25,           # Very suspicious
            'has_at_symbol': 30,            # Classic phishing trick
            'has_double_slash': 20,         # Redirect attempt
            'has_https_in_domain': 25,      # Deception attempt
            
            # Medium-risk indicators
            'has_suspicious_keywords': 15,  # Common in phishing
            'has_suspicious_tld': 15,       # Cheap TLDs often used
            'has_dash_in_domain': 10,       # Mimicking legitimate sites
            'has_multiple_dots': 12,        # Confusion technique
            
            # Low-risk indicators (need context)
            'has_port_number': 8,           # Unusual but not always bad
            'has_encoded_chars': 10,        # Could be legitimate
            'url_length': 0,                # Weight calculated dynamically
            'domain_length': 0,             # Weight calculated dynamically
        }
        
        # Risk thresholds
        self.thresholds = {
            'safe': 15,        # Score below this = likely safe
            'suspicious': 35,  # Score below this = suspicious
            # Score above this = likely phishing
        }
        
    def analyze(self, url):
        """
        Analyze a URL and return a complete report.
        
        Args:
            url (str): The URL to analyze
            
        Returns:
            dict: Complete analysis report with:
                - risk_score: Total risk score
                - risk_level: safe/suspicious/phishing
                - features: All extracted features
                - warnings: List of specific warnings
                - recommendations: Advice for the user
        """
        # Extract features
        extractor = URLFeatureExtractor(url)
        features = extractor.get_all_features()
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(features)
        
        # Determine risk level
        risk_level = self._get_risk_level(risk_score)
        
        # Generate warnings
        warnings = self._generate_warnings(features)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(features, risk_level)
        
        return {
            'url': url,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'features': features,
            'warnings': warnings,
            'recommendations': recommendations,
            'analysis_summary': self._get_summary(risk_level, risk_score)
        }
    
    def _calculate_risk_score(self, features):
        """
        Calculate the total risk score based on features.
        
        Args:
            features (dict): Extracted URL features
            
        Returns:
            int: Total risk score
        """
        score = 0
        
        # Apply weights for boolean features
        for feature, weight in self.weights.items():
            if feature in features and features[feature]:
                score += weight
        
        # Special handling for URL length
        # Phishing URLs are often longer than 75 characters
        url_length = features.get('url_length', 0)
        if url_length > 75:
            score += min(15, (url_length - 75) // 10)
        
        # Special handling for domain length
        # Phishing domains might be longer to mimic real ones
        domain_length = features.get('domain_length', 0)
        if domain_length > 30:
            score += min(10, (domain_length - 30) // 5)
        
        # Number of subdomains adds risk
        subdomains = features.get('num_subdomains', 0)
        if subdomains > 2:
            score += subdomains * 3
        
        # Penalize for not using HTTPS (but not heavily)
        if not features.get('uses_https', True):
            score += 5
        
        return min(score, 100)  # Cap at 100
    
    def _get_risk_level(self, score):
        """
        Determine the risk level based on score.
        
        Args:
            score (int): Risk score
            
        Returns:
            str: Risk level (safe/suspicious/phishing)
        """
        if score < self.thresholds['safe']:
            return 'safe'
        elif score < self.thresholds['suspicious']:
            return 'suspicious'
        else:
            return 'phishing'
    
    def _generate_warnings(self, features):
        """
        Generate human-readable warnings based on detected features.
        
        Args:
            features (dict): Extracted URL features
            
        Returns:
            list: List of warning messages
        """
        warnings = []
        
        if features.get('has_ip_address'):
            warnings.append({
                'severity': 'high',
                'message': 'URL uses IP address instead of domain name',
                'explanation': 'Legitimate websites rarely use IP addresses directly. '
                              'This is a common phishing technique to hide the true identity of the site.'
            })
        
        if features.get('has_at_symbol'):
            warnings.append({
                'severity': 'high',
                'message': 'URL contains @ symbol',
                'explanation': 'The @ symbol can be used to hide the actual destination. '
                              'Everything before @ is ignored by browsers. '
                              'Example: "bank.com@phishing.com" actually goes to phishing.com'
            })
        
        if features.get('has_double_slash'):
            warnings.append({
                'severity': 'high',
                'message': 'URL contains suspicious double slash',
                'explanation': 'Double slashes can be used to redirect to another website '
                              'while making the URL look legitimate.'
            })
        
        if features.get('has_https_in_domain'):
            warnings.append({
                'severity': 'high',
                'message': 'Domain name contains "https" - possible deception',
                'explanation': 'Attackers sometimes put "https" in the domain name '
                              'to trick users into thinking the site is secure.'
            })
        
        if features.get('has_suspicious_keywords'):
            warnings.append({
                'severity': 'medium',
                'message': 'URL contains suspicious keywords',
                'explanation': 'Common phishing keywords like "login", "verify", "secure" '
                              'are often used to create urgency and trick users.'
            })
        
        if features.get('has_suspicious_tld'):
            warnings.append({
                'severity': 'medium',
                'message': 'Domain uses a suspicious top-level domain (TLD)',
                'explanation': 'Some TLDs like .xyz, .tk, .ml are often used by phishers '
                              'because they are cheap or free to register.'
            })
        
        if features.get('has_dash_in_domain'):
            warnings.append({
                'severity': 'medium',
                'message': 'Domain contains dashes (-)',
                'explanation': 'Phishing domains often use dashes to mimic legitimate sites. '
                              'Example: "amazon-secure.com" is NOT Amazon!'
            })
        
        if features.get('has_multiple_dots'):
            warnings.append({
                'severity': 'medium',
                'message': 'Domain has many subdomains',
                'explanation': 'Multiple subdomains can be used to confuse users about '
                              'which domain they are actually visiting.'
            })
        
        if features.get('has_encoded_chars'):
            warnings.append({
                'severity': 'low',
                'message': 'URL contains encoded characters',
                'explanation': 'Encoded characters (%) might be used to hide malicious content, '
                              'though they can also appear in legitimate URLs.'
            })
        
        if features.get('has_port_number'):
            warnings.append({
                'severity': 'low',
                'message': 'URL specifies a port number',
                'explanation': 'Explicit port numbers are unusual for normal websites. '
                              'Legitimate sites rarely need to show the port.'
            })
        
        if features.get('url_length', 0) > 75:
            warnings.append({
                'severity': 'low',
                'message': 'URL is unusually long',
                'explanation': 'Phishing URLs are often very long to hide their true purpose '
                              'or to include tracking and redirect parameters.'
            })
        
        if not features.get('uses_https'):
            warnings.append({
                'severity': 'low',
                'message': 'URL does not use HTTPS encryption',
                'explanation': 'Modern legitimate websites typically use HTTPS. '
                              'Be careful when entering sensitive information on HTTP sites.'
            })
        
        return warnings
    
    def _generate_recommendations(self, features, risk_level):
        """
        Generate recommendations based on the analysis.
        
        Args:
            features (dict): Extracted features
            risk_level (str): Determined risk level
            
        Returns:
            list: List of recommendations
        """
        recommendations = []
        
        if risk_level == 'phishing':
            recommendations.append({
                'priority': 'critical',
                'action': 'Do NOT visit this URL',
                'details': 'This URL shows multiple signs of being a phishing attempt. '
                          'Visiting it could put your personal information at risk.'
            })
            recommendations.append({
                'priority': 'high',
                'action': 'Report this URL',
                'details': 'If you received this URL in an email or message, '
                          'report it to your IT security team or email provider.'
            })
        
        elif risk_level == 'suspicious':
            recommendations.append({
                'priority': 'high',
                'action': 'Proceed with caution',
                'details': 'This URL shows some suspicious characteristics. '
                          'Verify the source before visiting.'
            })
            recommendations.append({
                'priority': 'medium',
                'action': 'Check the domain manually',
                'details': 'If you expected this link from a known source, '
                          'type their website address directly in your browser instead.'
            })
        
        else:  # safe
            recommendations.append({
                'priority': 'low',
                'action': 'URL appears safe',
                'details': 'This URL did not show significant phishing indicators. '
                          'However, always stay vigilant when clicking links.'
            })
        
        # General recommendation
        recommendations.append({
            'priority': 'info',
            'action': 'Best practice',
            'details': 'Never enter passwords or sensitive information on pages '
                      'linked from emails. Always navigate directly to known websites.'
        })
        
        return recommendations
    
    def _get_summary(self, risk_level, score):
        """
        Get a summary message for the analysis.
        
        Args:
            risk_level (str): Risk level
            score (int): Risk score
            
        Returns:
            str: Summary message
        """
        summaries = {
            'safe': f"This URL appears to be safe (Risk Score: {score}/100). "
                   f"No significant phishing indicators were detected.",
            
            'suspicious': f"This URL is SUSPICIOUS (Risk Score: {score}/100). "
                         f"Some concerning characteristics were found. Proceed with caution.",
            
            'phishing': f"WARNING: This URL is likely PHISHING (Risk Score: {score}/100). "
                       f"Multiple dangerous indicators detected. Do not visit this URL!"
        }
        
        return summaries.get(risk_level, "Unable to determine risk level.")


# ==================== TESTING ====================

if __name__ == '__main__':
    print("=" * 60)
    print("Phishing Detector Test")
    print("=" * 60)
    
    detector = PhishingDetector()
    
    # Test URLs with expected results
    test_cases = [
        ('https://www.google.com', 'Should be safe'),
        ('https://amazon.com', 'Should be safe'),
        ('http://192.168.1.1/login', 'IP address - suspicious'),
        ('http://secure-bank-login.com@evil-site.com', 'Phishing with @ symbol'),
        ('http://amazon-verify-account.xyz/urgent', 'Multiple phishing signs'),
        ('https://login.secure.account.bank.com.phishing.tk', 'Subdomain abuse'),
    ]
    
    for url, expected in test_cases:
        print(f"\n{'='*60}")
        print(f"URL: {url}")
        print(f"Expected: {expected}")
        print("-" * 40)
        
        result = detector.analyze(url)
        
        print(f"Risk Level: {result['risk_level'].upper()}")
        print(f"Risk Score: {result['risk_score']}/100")
        print(f"\nSummary: {result['analysis_summary']}")
        
        if result['warnings']:
            print("\nWarnings:")
            for warning in result['warnings']:
                print(f"  [{warning['severity'].upper()}] {warning['message']}")

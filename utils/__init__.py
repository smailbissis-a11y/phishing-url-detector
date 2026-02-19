"""
Utilities Package
=================
This package contains the core modules for phishing detection.

Modules:
    - url_features: Extract features from URLs
    - detector: Analyze URLs for phishing indicators
"""

from utils.url_features import URLFeatureExtractor
from utils.detector import PhishingDetector

__all__ = ['URLFeatureExtractor', 'PhishingDetector']

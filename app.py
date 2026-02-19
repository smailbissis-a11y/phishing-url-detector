"""
Phishing URL Detector - Flask Web Application
==============================================
A web-based tool to analyze URLs for phishing indicators.

Author: [Your Name]
Purpose: Cybersecurity Portfolio Project

How to run:
    1. Install dependencies: pip install -r requirements.txt
    2. Run this file: python app.py
    3. Open browser: http://localhost:5000
"""

from flask import Flask, render_template, request, jsonify
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.detector import PhishingDetector

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'phishing-detector-secret-key-change-in-production'

# Initialize the detector
detector = PhishingDetector()


@app.route('/')
def index():
    """
    Render the main page with URL input form.
    """
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    """
    API endpoint to analyze a URL.
    
    Expects JSON body with 'url' field.
    Returns analysis results as JSON.
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'success': False,
                'error': 'Please provide a URL to analyze'
            }), 400
        
        url = data['url'].strip()
        
        if not url:
            return jsonify({
                'success': False,
                'error': 'URL cannot be empty'
            }), 400
        
        # Perform analysis
        result = detector.analyze(url)
        
        return jsonify({
            'success': True,
            'result': result
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'An error occurred: {str(e)}'
        }), 500


@app.route('/batch', methods=['POST'])
def batch_analyze():
    """
    API endpoint to analyze multiple URLs at once.
    
    Expects JSON body with 'urls' array.
    Returns array of analysis results.
    """
    try:
        data = request.get_json()
        
        if not data or 'urls' not in data:
            return jsonify({
                'success': False,
                'error': 'Please provide URLs to analyze'
            }), 400
        
        urls = data['urls']
        
        if not isinstance(urls, list) or len(urls) == 0:
            return jsonify({
                'success': False,
                'error': 'Please provide a list of URLs'
            }), 400
        
        # Limit batch size
        if len(urls) > 50:
            return jsonify({
                'success': False,
                'error': 'Maximum 50 URLs allowed per batch'
            }), 400
        
        # Analyze each URL
        results = []
        for url in urls:
            url = url.strip()
            if url:
                result = detector.analyze(url)
                results.append(result)
        
        return jsonify({
            'success': True,
            'results': results,
            'total': len(results)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'An error occurred: {str(e)}'
        }), 500


@app.route('/api/features/<path:url>')
def get_features(url):
    """
    API endpoint to get raw features for a URL.
    Useful for developers and debugging.
    """
    try:
        from utils.url_features import URLFeatureExtractor
        
        extractor = URLFeatureExtractor(url)
        features = extractor.get_all_features()
        
        return jsonify({
            'success': True,
            'url': url,
            'features': features
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    return render_template('index.html', error='Page not found'), 404


@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 errors."""
    return jsonify({
        'success': False,
        'error': 'Internal server error'
    }), 500


# ==================== MAIN ====================

if __name__ == '__main__':
    print("=" * 50)
    print("  Phishing URL Detector")
    print("  Starting server on http://localhost:5000")
    print("=" * 50)
    print("\nPress Ctrl+C to stop the server\n")
    
    # Run the Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)

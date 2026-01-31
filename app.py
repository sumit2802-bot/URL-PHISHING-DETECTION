from flask import Flask, request, render_template_string
import joblib
import re
import numpy as np

app = Flask(__name__)

# --- Load the Trained Model ---
# Ensure 'phishing_model.pkl' is in the same directory
try:
    model = joblib.load('phishing_model.pkl')
    print("✅ Model loaded successfully.")
except FileNotFoundError:
    print("❌ Error: 'phishing_model.pkl' not found. Run the training script first.")
    model = None

# --- Feature Extraction (Must Match Training Script Exactly) ---
def extract_features(url):
    """
    Extracts the exact 18 features used during model training.
    """
    url = str(url).lower()
    return [
        len(url),                                                    # 1. url_length
        url.count('.'),                                              # 2. dot_count
        1 if '@' in url else 0,                                      # 3. has_at_symbol
        1 if '-' in url else 0,                                      # 4. has_dash
        1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,           # 5. is_ip
        1 if url.startswith('https') else 0,                         # 6. is_https
        1 if 'login' in url else 0,                                  # 7. has_login
        1 if 'verify' in url else 0,                                 # 8. has_verify
        1 if 'bank' in url else 0,                                   # 9. has_bank
        1 if re.search(r'bit\.ly|goo\.gl|tinyurl', url) else 0,      # 10. has_shortener
        sum(c.isdigit() for c in url),                               # 11. digit_count
        1 if url.count('.') > 3 else 0,                              # 12. heavy_subdomains
        1 if ';' in url else 0,                                      # 13. has_semicolon
        1 if '_' in url else 0,                                      # 14. has_underscore
        1 if '?' in url else 0,                                      # 15. has_query_param
        1 if '=' in url else 0,                                      # 16. has_equal_sign
        url.count('/'),                                              # 17. slash_count
        1 if 'https' in url.replace('https://', '') else 0           # 18. fake_https_token
    ]

# --- Human-Readable Reasoning (For the Dashboard) ---
def get_reasons(url):
    reasons = []
    url = url.lower()
    if 'login' in url or 'verify' in url or 'bank' in url:
        reasons.append("Contains sensitive keywords (login/bank/verify)")
    if re.search(r'\d+\.\d+\.\d+\.\d+', url):
        reasons.append("URL uses raw IP address instead of domain")
    if '-' in url:
        reasons.append("Suspicious hyphenation in domain")
    if len(url) > 75:
        reasons.append("URL is abnormally long")
    if '@' in url:
        reasons.append("Contains '@' symbol (often used to mask true domain)")
    if not url.startswith('https'):
        reasons.append("Connection is not secure (No HTTPS)")
    return reasons

# --- Trusted Domain Whitelist ---
# Bypasses the model for known safe sites to reduce false positives
TRUSTED_DOMAINS = [
    "google.com", "gov.in", "gov", "gouv.fr", "gov.uk", "microsoft.com", 
    "apple.com", "amazon.com", "facebook.com", "linkedin.com"
]

def is_trusted_domain(url):
    for domain in TRUSTED_DOMAINS:
        if url.endswith(domain) or f".{domain}/" in url or f".{domain}" == url:
            return True
    return False

# --- HTML Template ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<title>Cyber Security - Phishing Detector</title>
<style>
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f6f9; text-align: center; padding: 40px; }
    .container { background: white; padding: 40px; border-radius: 15px; box-shadow: 0 10px 25px rgba(0,0,0,0.1); width: 600px; margin:auto; }
    h1 { color: #2c3e50; margin-bottom: 20px; }
    input { width: 90%; padding: 15px; margin-bottom: 20px; border-radius: 8px; border: 1px solid #ddd; font-size: 16px; }
    button { padding: 15px 30px; background: #3498db; color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 16px; width: 100%; transition: background 0.3s; }
    button:hover { background: #2980b9; }
    .report { margin-top: 30px; padding: 20px; border-radius: 8px; background: #fafafa; border: 1px solid #eee; text-align: left; }
    .meter-container { height: 25px; background: #e0e0e0; border-radius: 12px; overflow: hidden; margin-top: 15px; position: relative; }
    .meter-fill { height: 100%; transition: width 0.5s ease-in-out; }
    .safe { background: #27ae60; }     /* Green */
    .warning { background: #f39c12; }  /* Orange */
    .critical { background: #c0392b; } /* Red */
    .score-text { font-weight: bold; font-size: 18px; margin-top: 10px; display: block; text-align: center; }
    ul { color: #555; }
</style>
</head>
<body>
<div class="container">
    <h1>🛡️ Phishing Detection Gateway</h1>
    <form method="POST">
        <input type="text" name="url" placeholder="Enter URL to scan (e.g., http://suspicious-site.com/login)" required>
        <button type="submit">Analyze URL</button>
    </form>
    
    {% if report %}
    <div class="report">
        <h3>Analysis Report</h3>
        
        {% if report.is_trusted %}
            <h2 style="color: #27ae60;">✅ Trusted Domain</h2>
            <p>This domain is in our whitelist of verified safe organizations.</p>
        {% else %}
            <div class="meter-container">
                <div class="meter-fill {{ 'critical' if report.score > 70 else ('warning' if report.score > 40 else 'safe') }}" 
                     style="width: {{ report.score }}%;"></div>
            </div>
            <span class="score-text">Phishing Probability: {{ report.score }}%</span>
            
            {% if report.reasons %}
                <h4>Detected Threats:</h4>
                <ul>
                    {% for r in report.reasons %}
                        <li>{{ r }}</li>
                    {% endfor %}
                </ul>
            {% else %}
                <p style="color: #27ae60; margin-top: 10px;">No obvious heuristic threats detected, but ML analysis places risk at {{ report.score }}%.</p>
            {% endif %}
        {% endif %}
    </div>
    {% endif %}
</div>
</body>
</html>
"""

# --- Flask Routes ---
@app.route('/', methods=['GET','POST'])
def home():
    report = None
    if request.method == 'POST':
        url = request.form.get('url','').strip()
        
        if not url:
            return render_template_string(HTML_TEMPLATE, report=None)

        # 1. Check Whitelist first
        if is_trusted_domain(url.lower()):
            report = {'is_trusted': True, 'score': 0, 'reasons': []}
        
        # 2. If not trusted, run ML Model
        elif model:
            # Extract features exactly as the model expects
            features = extract_features(url)
            
            # Predict (reshape to 2D array for sklearn)
            prediction_prob = model.predict_proba([features])[0][1]
            score = int(prediction_prob * 100)
            
            # Get human-readable reasons
            reasons = get_reasons(url)
            
            report = {
                'is_trusted': False,
                'score': score,
                'reasons': reasons
            }
        else:
            report = {'error': "Model not loaded."}

    return render_template_string(HTML_TEMPLATE, report=report)

if __name__ == "__main__":
    app.run(debug=True, port=5000)

import os
import joblib
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from feature_extractor import extract_features
from urllib.parse import urlparse

# --- 1. Initialize the Flask App ---
app = Flask(__name__)
CORS(app)

# --- 2. Define the Expanded Allowlist of Safe Domains ---
SAFE_DOMAINS = [
    'google.com', 'youtube.com', 'twitter.com', 'x.com', 'facebook.com', 'instagram.com', 'linkedin.com', 'reddit.com',
    'pinterest.com', 'tiktok.com', 'amazon.com', 'ebay.com', 'walmart.com', 'microsoft.com', 'apple.com', 'github.com',
    'stackoverflow.com', 'wikipedia.org', 'phishtank.org'
]

# --- 3. Load GitHub Token and Fetch Blocklist ---
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
PHISHING_BLOCKLIST = set()

def fetch_github_blocklist(token):
    if not token:
        print("⚠️ GITHUB_TOKEN not set. Skipping blocklist check.")
        return set()
    api_url = "https://api.github.com/repos/Phishing-Database/Phishing.Database/contents/phishing-links-ACTIVE.txt"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3.raw"}
    print("Fetching latest blocklist from GitHub...")
    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        response.raise_for_status()
        url_list = [line for line in response.text.splitlines() if line]
        blocklist = set(url_list)
        print(f"✅ Successfully fetched {len(blocklist)} URLs for the blocklist.")
        return blocklist
    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching blocklist from GitHub: {e}")
        return set()

# --- 4. Load the Trained Model ---
MODEL_PATH = 'phishing_model.pkl'
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model file not found at '{MODEL_PATH}'. Run model.py to create it.")
model = joblib.load(MODEL_PATH)
print(f"✅ Model '{MODEL_PATH}' loaded successfully.")

EXPECTED_FEATURE_ORDER = [
    'PctExtHyperlinks', 'PctExtResourceUrls', 'PctNullSelfRedirectHyperlinks', 'PctExtNullSelfRedirectHyperlinksRT', 'NumNumericChars', 
    'FrequentDomainNameMismatch', 'ExtMetaScriptLinkRT', 'NumDash', 'SubmitInfoToEmail', 'NumDots', 'PathLength', 'QueryLength', 'PathLevel', 
    'InsecureForms', 'UrlLength', 'NumSensitiveWords', 'NumQueryComponents', 'PctExtResourceUrlsRT', 'IframeOrFrame', 'HostnameLength', 
    'NumAmpersand', 'AbnormalExtFormActionR', 'UrlLengthRT', 'NumDashInHostname', 'IpAddress', 'AbnormalFormAction', 'EmbeddedBrandName', 
    'NumUnderscore', 'MissingTitle', 'DomainInPaths', 'SubdomainLevel', 'ExtFormAction'
]

# --- 5. Helper function to print analysis to the terminal ---
def print_analysis_to_terminal(analysis_data):
    print("-" * 60)
    print(f"🔎 Analyzing URL: {analysis_data['url']}")
    if analysis_data.get('is_on_blocklist'):
        print("\n❗️ Pre-check Result: PHISHING (Found on GitHub blocklist)")
    if analysis_data.get('model_analysis_skipped'):
        reason_text = f" ({analysis_data.get('reason', '')})" if analysis_data.get('reason') else ""
        print(f"\n🤖 Machine Learning Model Analysis: SKIPPED{reason_text}")
        print("-" * 60)
        return
    print("\n🤖 Machine Learning Model Analysis:")
    if analysis_data['is_phishing']:
        print(f"    - Probability of Phishing: {analysis_data['prob_phishing']}")
        print("\n  Result: Phishing")
        print("  Reasoning (Phishing features detected with a value of 1):")
        if not analysis_data['risky_features']:
            print("    - Verdict based on a combination of factors.")
        else:
            for feature in analysis_data['risky_features']:
                print(f"    - {feature}")
    else: # Benign
        print(f"    - Probability of Phishing: {analysis_data['prob_phishing']}")
        print(f"    - Probability of Legitimate: {analysis_data['prob_legitimate']}")
        print("\n  Result: Benign")
        print("  Reasoning (Benign features detected with a value of -1):")
        for feature in analysis_data['safe_features'][:5]:
            print(f"    - {feature}")
    print("-" * 60)

# --- 6. Create the API Endpoint for Analysis ---
@app.route("/analyze", methods=["POST"])
def analyze_url():
    payload = request.get_json()
    url = payload.get("url")
    if not url: return jsonify({"error": "URL not provided"}), 400

    try:
        hostname = urlparse(url).hostname
        if hostname and any(hostname.endswith(safe_domain) for safe_domain in SAFE_DOMAINS):
            analysis_result = {"url": url, "is_phishing": False, "reason": "On Allowlist", "model_analysis_skipped": True, "safe_features": ["This domain is on the allowlist."], "prob_phishing": "0.00%", "prob_legitimate": "100.00%"}
            print_analysis_to_terminal(analysis_result)
            return jsonify(analysis_result)

        is_on_blocklist = url in PHISHING_BLOCKLIST
        features = extract_features(url)
        
        if features is None:
            analysis_result = {"url": url, "is_phishing": True, "is_on_blocklist": is_on_blocklist, "reason": "Site Unresponsive", "model_analysis_skipped": True, "risky_features": ["Site is unresponsive or actively blocking connections."], "prob_phishing": "100.00%"}
            print_analysis_to_terminal(analysis_result)
            return jsonify(analysis_result)

        feature_list = [features.get(col, 0) for col in EXPECTED_FEATURE_ORDER]
        probabilities = model.predict_proba([feature_list])[0]
        prob_phishing = probabilities[1]
        model_prediction_is_phishing = prob_phishing > 0.5
        final_verdict_is_phishing = is_on_blocklist or model_prediction_is_phishing
        
        analysis_result = {
            "url": url, "is_phishing": bool(final_verdict_is_phishing), "is_on_blocklist": bool(is_on_blocklist),
            "prob_phishing": f"{prob_phishing:.2%}", "prob_legitimate": f"{probabilities[0]:.2%}",
            "risky_features": [f for f in EXPECTED_FEATURE_ORDER if features.get(f, 0) > 0],
            "safe_features": [f for f in EXPECTED_FEATURE_ORDER if features.get(f, 0) == 0]
        }
        
        print_analysis_to_terminal(analysis_result)
        return jsonify(analysis_result)

    except Exception as e:
        print(f"Critical error in /analyze endpoint for URL {url}: {e}")
        return jsonify({"error": "A critical server error occurred"}), 500

# --- 7. Run the Server ---
if __name__ == "__main__":
    PHISHING_BLOCKLIST = fetch_github_blocklist(GITHUB_TOKEN)
    app.run(debug=True)
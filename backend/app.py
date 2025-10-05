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
    # Social Media
    'facebook.com', 'twitter.com', 'x.com', 'instagram.com', 'linkedin.com',
    'reddit.com', 'pinterest.com', 'tiktok.com', 'tumblr.com',

    # E-commerce
    'amazon.com', 'ebay.com', 'walmart.com', 'etsy.com', 'target.com',
    'bestbuy.com', 'alibaba.com', 'aliexpress.com',

    # Search Engines
    'google.com', 'bing.com', 'yahoo.com', 'duckduckgo.com',

    # News & Media
    'bbc.com', 'nytimes.com', 'theguardian.com', 'reuters.com', 'cnn.com', 'forbes.com',

    # Streaming & Entertainment
    'youtube.com', 'netflix.com', 'spotify.com', 'twitch.tv', 'imdb.com',

    # Productivity & Cloud Services
    'microsoft.com', 'apple.com', 'office.com', 'dropbox.com',
    'salesforce.com', 'adobe.com', 'zoom.us',

    # Developer & Tech
    'github.com', 'stackoverflow.com', 'wikipedia.org', 'medium.com', 'quora.com'
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

# --- 5. Create the API Endpoint for Analysis ---
@app.route("/analyze", methods=["POST"])
def analyze_url():
    payload = request.get_json()
    url = payload.get("url")
    if not url:
        return jsonify({"error": "URL not provided"}), 400

    try:
        # --- Allowlist Check ---
        hostname = urlparse(url).hostname
        if hostname and any(hostname.endswith(safe_domain) for safe_domain in SAFE_DOMAINS):
            print(f"✔️ Allowlist HIT for {url}")
            return jsonify({"is_phishing": False})

        # Stage 1: Check against the live blocklist
        if url in PHISHING_BLOCKLIST:
            print(f"✔️ Blocklist HIT for {url}")
            return jsonify({
                "url": url, "is_phishing": True,
                "reasons": ["URL is present on a live phishing blocklist."]
            })

        # Stage 2: If not on blocklist, use the ML model
        features = extract_features(url)
        if features is None:
            print(f"⚠️ Warning: Feature extraction failed for {url}. Flagging as phishing by default.")
            return jsonify({
                "url": url, "is_phishing": True,
                "reasons": ["Analysis failed because the site is unresponsive."]
            })

        feature_list = [features.get(col, 0) for col in EXPECTED_FEATURE_ORDER]
        prediction = model.predict([feature_list])[0]
        is_phishing = bool(prediction == 1)
        reasons = [f for f in EXPECTED_FEATURE_ORDER if features.get(f, 0) > 0] if is_phishing else []
        
        return jsonify({
            "url": url, "is_phishing": is_phishing, "reasons": reasons
        })

    except Exception as e:
        print(f"Critical error in /analyze endpoint for URL {url}: {e}")
        return jsonify({"error": "A critical server error occurred"}), 500

# --- 6. Run the Server ---
if __name__ == "__main__":
    PHISHING_BLOCKLIST = fetch_github_blocklist(GITHUB_TOKEN)
    app.run(debug=True)
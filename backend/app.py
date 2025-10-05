import os
import joblib
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from feature_extractor import extract_features

# --- 1. Initialize the Flask App ---
app = Flask(__name__)
CORS(app)

# --- 2. Load GitHub Token and Fetch Blocklist ---
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
PHISHING_BLOCKLIST = set()

def fetch_github_blocklist(token):
    if not token:
        print("⚠️ GITHUB_TOKEN not set. Skipping blocklist check.")
        return set()
    
    api_url = "https://api.github.com/repos/Phishing-Database/Phishing.Database/contents/phishing-links-ACTIVE.txt"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3.raw"
    }
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

# --- 3. Load the Trained Model ---
MODEL_PATH = 'phishing_model.pkl'
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model file not found at '{MODEL_PATH}'. Run model.py to create it.")

model = joblib.load(MODEL_PATH)
print(f"✅ Model '{MODEL_PATH}' loaded successfully.")

EXPECTED_FEATURE_ORDER = [
    'PctExtHyperlinks', 'PctExtResourceUrls', 'PctNullSelfRedirectHyperlinks',
    'PctExtNullSelfRedirectHyperlinksRT', 'NumNumericChars', 'FrequentDomainNameMismatch',
    'ExtMetaScriptLinkRT', 'NumDash', 'SubmitInfoToEmail', 'NumDots', 'PathLength',
    'QueryLength', 'PathLevel', 'InsecureForms', 'UrlLength', 'NumSensitiveWords',
    'NumQueryComponents', 'PctExtResourceUrlsRT', 'IframeOrFrame', 'HostnameLength',
    'NumAmpersand', 'AbnormalExtFormActionR', 'UrlLengthRT', 'NumDashInHostname',
    'IpAddress', 'AbnormalFormAction', 'EmbeddedBrandName', 'NumUnderscore',
    'MissingTitle', 'DomainInPaths', 'SubdomainLevel', 'ExtFormAction'
]

# --- 4. Create the API Endpoint for Analysis ---
@app.route("/analyze", methods=["POST"])
def analyze_url():
    payload = request.get_json()
    url = payload.get("url")
    if not url:
        return jsonify({"error": "URL not provided"}), 400

    # --- Two-Stage Detection Logic ---
    # Stage 1: Check against the live blocklist (fastest)
    if url in PHISHING_BLOCKLIST:
        print(f"✔️ Blocklist HIT for {url}")
        return jsonify({
            "url": url,
            "is_phishing": True,
            "reasons": ["URL is present on a live phishing blocklist."]
        })

    # Stage 2: If not on blocklist, use the ML model
    try:
        features = extract_features(url)
        
        # This correctly handles cases where feature extraction might fail
        if features is None:
             return jsonify({
                "url": url,
                "is_phishing": True,
                "reasons": ["Analysis failed: Site is unresponsive or blocking connections."]
            })

        feature_list = [features.get(col, 0) for col in EXPECTED_FEATURE_ORDER]
        prediction = model.predict([feature_list])[0]
        is_phishing = bool(prediction == 1)

        reasons = []
        if is_phishing:
            reasons = [f for f in EXPECTED_FEATURE_ORDER if features.get(f, 0) > 0]

        return jsonify({"url": url, "is_phishing": is_phishing, "reasons": reasons})

    except Exception as e:
        print(f"Critical error in /analyze endpoint for URL {url}: {e}")
        return jsonify({"error": "A critical server error occurred", "details": str(e)}), 500

# --- 5. Run the Server ---
if __name__ == "__main__":
    # Fetch the blocklist once on startup
    PHISHING_BLOCKLIST = fetch_github_blocklist(GITHUB_TOKEN)
    app.run(debug=True)
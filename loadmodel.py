# loadmodel.py

import joblib
import os
import requests
import base64
from feature_extractor import extract_features

def fetch_github_blocklist(token):
    """
    Fetches the list of active phishing URLs from the Phishing.Database repository.
    Returns a set of URLs for fast checking.
    """
    # This is the correct API URL to use your token with.
    api_url = "https://api.github.com/repos/Phishing-Database/Phishing.Database/contents/phishing-links-ACTIVE.txt"
    
    # Using the .raw media type gets the file content directly without Base64 encoding.
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3.raw" 
    }
    
    print("Fetching latest blocklist from GitHub...")
    try:
        response = requests.get(api_url, headers=headers)
        # This will raise an error for bad responses (e.g., 401 Unauthorized for a bad token)
        response.raise_for_status()
        
        # Split the text content into a list of lines, removing any empty ones.
        url_list = [line for line in response.text.splitlines() if line]
        
        # A 'set' is much faster than a 'list' for checking if an item exists.
        blocklist_set = set(url_list)
        print(f"✅ Successfully fetched {len(blocklist_set)} unique URLs for the blocklist.")
        return blocklist_set

    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching blocklist from GitHub: {e}")
        print("Continuing without the GitHub blocklist. Predictions will rely only on the ML model.")
        return set() # Return an empty set on failure so the program doesn't crash


def predict_url_status(url, model, blocklist, feature_order):
    """
    Checks a URL first against the blocklist, then uses the ML model if not found.
    """
    print("-" * 50)
    print(f"🔎 Analyzing URL: {url}")

    # Step 1: Pre-check against the GitHub blocklist (very fast)
    if url in blocklist:
        print("❗️ Result: PHISHING (Found on GitHub blocklist)")
        return 1  # 1 indicates Phishing
        
    # Step 2: If not on the blocklist, analyze with your ML model
    print("➡️ URL not on blocklist. Analyzing with ML model...")
    try:
        # Extract features using your existing function
        features_dict = extract_features(url)
        
        # IMPORTANT: Create the feature list in the exact order the model was trained on
        feature_list = [features_dict[col] for col in feature_order]
        
        # Predict using the loaded model
        prediction = model.predict([feature_list])
        
        if prediction[0] == 1:
            print("❗️ Result: PHISHING (Predicted by ML model)")
        else:
            print("✅ Result: LEGITIMATE (Predicted by ML model)")
            
        return prediction[0]

    except Exception as e:
        print(f"❌ Could not analyze URL with ML model. Error: {e}")
        return -1 # Represents an error or unknown status


# --- Main Execution Block ---
if __name__ == "__main__":
    
    # 🔐 For security, load your GitHub Token from an environment variable.
    # Before running the script, open your terminal and execute:
    # export GITHUB_TOKEN="paste_your_token_here"
    GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
    
    if not GITHUB_TOKEN:
        print("FATAL ERROR: The 'GITHUB_TOKEN' environment variable is not set.")
        print("Please set it to your GitHub Personal Access Token to continue.")
    else:
        # 1. Fetch the live blocklist from GitHub using your token
        PHISHING_BLOCKLIST = fetch_github_blocklist(GITHUB_TOKEN)

        # 2. Load your trained phishing model
        MODEL_PATH = 'phishing_model.pkl'
        if not os.path.exists(MODEL_PATH):
            print(f"FATAL ERROR: Model file not found at '{MODEL_PATH}'")
        else:
            phishing_model = joblib.load(MODEL_PATH)
            print("🧠 Model 'phishing_model.joblib' loaded successfully.")

            # 3. This list of feature names MUST be in the same order as when you trained your model
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

            # --- Test with some example URLs ---
            url_to_test_phishing = "http://0.0.0.0forum.cryptonight.net"
            predict_url_status(url_to_test_phishing, phishing_model, PHISHING_BLOCKLIST, EXPECTED_FEATURE_ORDER)

            url_to_test_legit = "https://www.google.com"
            predict_url_status(url_to_test_legit, phishing_model, PHISHING_BLOCKLIST, EXPECTED_FEATURE_ORDER)

            url_from_blocklist_test = "http://000agreementmail.weebly.com" # Replace with a URL from the list for testing
            predict_url_status(url_from_blocklist_test, phishing_model, PHISHING_BLOCKLIST, EXPECTED_FEATURE_ORDER)
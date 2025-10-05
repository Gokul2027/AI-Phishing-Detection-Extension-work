# loadmodel.py

import joblib
import os
import requests
from feature_extractor import extract_features

def fetch_github_blocklist(token):
    """
    Fetches the list of active phishing URLs from the Phishing.Database repository.
    """
    api_url = "https://api.github.com/repos/Phishing-Database/Phishing.Database/contents/phishing-links-ACTIVE.txt"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3.raw"
    }
    print("Fetching latest blocklist from GitHub...")
    try:
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()
        url_list = [line for line in response.text.splitlines() if line]
        blocklist_set = set(url_list)
        print(f"✅ Successfully fetched {len(blocklist_set)} unique URLs for the blocklist.")
        return blocklist_set
    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching blocklist from GitHub: {e}")
        return set()


def analyze_and_present(url, model, blocklist, features, feature_order):
    """
    Analyzes the URL and presents the findings in the required format.
    """
    is_on_blocklist = url in blocklist

    # Get the model's prediction and probabilities regardless of blocklist status
    feature_list = [features[col] for col in feature_order]
    probabilities = model.predict_proba([feature_list])[0]
    prob_phishing = probabilities[1]
    prob_legitimate = probabilities[0]
    model_prediction_is_phishing = prob_phishing > 0.5

    # The final verdict is PHISHING if the blocklist says so OR if the model says so.
    final_verdict_is_phishing = is_on_blocklist or model_prediction_is_phishing

    print("-" * 60)
    print(f"🔎 Analyzing URL: {url}")

    if is_on_blocklist:
        print("\n❗️ Pre-check Result: PHISHING (Found on GitHub blocklist)")

    print("\n🤖 Machine Learning Model Analysis:")

    if final_verdict_is_phishing:
        print(f"    - Probability of Phishing: {prob_phishing:.2%}")
        print("\n  Result: Phishing")
        print("  Reasoning (Phishing features detected with a value of 1):")
        # Find all features with a "risky" value (greater than 0)
        risky_features = [f for f in feature_order if features.get(f, 0) > 0]
        if not risky_features:
            print("    - No single dominant phishing feature found; verdict based on a combination of factors.")
        else:
            for feature in risky_features:
                print(f"    - {feature}")
    else: # Benign
        print(f"    - Probability of Phishing: {prob_phishing:.2%}")
        print(f"    - Probability of Legitimate: {prob_legitimate:.2%}")
        print("\n  Result: Benign")
        # --- THIS IS THE LINE THAT HAS BEEN CHANGED ---
        print("  Reasoning (Benign features detected with a value of -1):")
        # Find all features with a "safe" value (equal to 0)
        safe_features = [f for f in feature_order if features.get(f, 0) == 0]
        for feature in safe_features[:5]: # Show the first 5 for brevity
            print(f"    - {feature}")


# --- Main Execution Block ---
if __name__ == "__main__":
    GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
    if not GITHUB_TOKEN:
        print("FATAL ERROR: 'GITHUB_TOKEN' environment variable is not set.")
    else:
        PHISHING_BLOCKLIST = fetch_github_blocklist(GITHUB_TOKEN)
        MODEL_PATH = 'phishing_model.pkl'
        if not os.path.exists(MODEL_PATH):
            print(f"FATAL ERROR: Model file not found at '{MODEL_PATH}'")
        else:
            phishing_model = joblib.load(MODEL_PATH)
            print(f"🧠 Model '{MODEL_PATH}' loaded successfully.")

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

            # --- Test URLs ---
            urls_to_test = [
                "https://github.com/Gokul2027/AI-Phishing-Detection-Extension-work" 
                
            ]

            for test_url in urls_to_test:
                try:
                    extracted_features = extract_features(test_url)
                    analyze_and_present(test_url, phishing_model, PHISHING_BLOCKLIST, extracted_features, EXPECTED_FEATURE_ORDER)
                except Exception as e:
                    print("-" * 60)
                    print(f"🔎 Analyzing URL: {test_url}")
                    print(f"\n❌ Could not process URL. Error: {e}")
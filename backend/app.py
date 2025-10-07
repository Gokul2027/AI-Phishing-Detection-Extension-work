# app.py
import os
import logging
import joblib
import sqlite3
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse
from feature_extractor import extract_features
from phish_list import init_db, lookup_url, update_all_sources, to_raw_github_url

# --- Config & Logging ---
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

DB_PATH = os.getenv("PHISH_DB_PATH", "phish_urls_simple.db")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # optional, helps with GitHub rate limits
MODEL_PATH = os.getenv("MODEL_PATH", "phishing_model.pkl")

SAFE_DOMAINS = {
    "google.com", "youtube.com", "twitter.com", "x.com", "facebook.com",
    "instagram.com", "linkedin.com", "reddit.com", "pinterest.com",
    "tiktok.com", "amazon.com", "ebay.com", "walmart.com", "microsoft.com",
    "apple.com", "github.com", "stackoverflow.com", "wikipedia.org", "phishtank.org"
}

# Expected feature order from your model training pipeline:
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

# --- Initialize Flask App ---
app = Flask(__name__)
CORS(app)

# --- Load model ---
if not os.path.exists(MODEL_PATH):
    logger.critical("Model file not found at '%s'. Run model.py to create it.", MODEL_PATH)
    raise FileNotFoundError(f"Model file not found at '{MODEL_PATH}'. Run model.py to create it.")
model = joblib.load(MODEL_PATH)
logger.info("✅ Model '%s' loaded successfully.", MODEL_PATH)

# --- Initialize DB connection (sqlite connection per request pattern) ---
def get_db_conn():
    return sqlite3.connect(DB_PATH, timeout=60, check_same_thread=False)

# --- Utility: canonicalize hostname and url ---
def canonical_hostname(url: str):
    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        hostname = parsed.hostname or ""
        return hostname.lower().strip()
    except Exception:
        return ""

# --- Helper: print analysis to server logs (kept readable) ---
def print_analysis_to_terminal(analysis_data: dict):
    logger.info("------------------------------------------------------------")
    logger.info("🔎 Analyzing URL: %s", analysis_data.get("url"))
    if analysis_data.get("is_on_blocklist"):
        logger.info("❗️ Pre-check Result: PHISHING (Found on blocklist)")
    if analysis_data.get("model_analysis_skipped"):
        reason = analysis_data.get("reason", "")
        logger.info("🤖 Machine Learning Model Analysis: SKIPPED %s", f"({reason})" if reason else "")
        logger.info("------------------------------------------------------------")
        return

    logger.info("🤖 Machine Learning Model Analysis:")
    if analysis_data.get("is_phishing"):
        logger.info(" - Probability of Phishing: %s", analysis_data.get("prob_phishing"))
        logger.info(" Result: Phishing")
        risky = analysis_data.get("risky_features", [])
        if risky:
            logger.info(" Reasoning (Phishing features detected):")
            for f in risky:
                logger.info("  - %s", f)
        else:
            logger.info(" - Verdict based on combined factors.")
    else:
        logger.info(" - Probability of Phishing: %s", analysis_data.get("prob_phishing"))
        logger.info(" - Probability of Legitimate: %s", analysis_data.get("prob_legitimate"))
        logger.info(" Result: Benign")
        safe = analysis_data.get("safe_features", [])[:5]
        if safe:
            logger.info(" Reasoning (Benign features detected):")
            for f in safe:
                logger.info("  - %s", f)
    logger.info("------------------------------------------------------------")

# --- Endpoint ---
@app.route("/analyze", methods=["POST"])
def analyze_url():
    try:
        payload = request.get_json(force=True)
        url = payload.get("url")
        if not url:
            return jsonify({"error": "URL not provided"}), 400

        # canonicalize
        hostname = canonical_hostname(url)
        if not hostname:
            return jsonify({"error": "Could not parse hostname from provided URL"}), 400

        # Allowlist check using hostname suffix match
        if any(hostname == sd or hostname.endswith("." + sd) for sd in SAFE_DOMAINS):
            analysis_result = {
                "url": url, "is_phishing": False, "reason": "On Allowlist",
                "model_analysis_skipped": True,
                "safe_features": ["This domain is on the allowlist."],
                "prob_phishing": "0.00%", "prob_legitimate": "100.00%"
            }
            print_analysis_to_terminal(analysis_result)
            return jsonify(analysis_result)

        # Blocklist lookup (sqlite): check by hostname and full URL
        conn = get_db_conn()
        try:
            # prefer hostname lookup, fall back to full url
            res_host = lookup_url(conn, hostname)
            res_url = lookup_url(conn, url)
            is_on_blocklist = bool(res_host.get("matched") or res_url.get("matched"))
        finally:
            conn.close()

        if is_on_blocklist:
            analysis_result = {
                "url": url, "is_phishing": True, "is_on_blocklist": True,
                "model_analysis_skipped": True,
                "risky_features": ["Found on blocklist"], "prob_phishing": "100.00%", "prob_legitimate": "0.00%"
            }
            print_analysis_to_terminal(analysis_result)
            return jsonify(analysis_result)

        # Feature extraction
        features = extract_features(url)
        if features is None:
            analysis_result = {
                "url": url, "is_phishing": True, "is_on_blocklist": False,
                "reason": "Site Unresponsive", "model_analysis_skipped": True,
                "risky_features": ["Site is unresponsive or blocked connections."],
                "prob_phishing": "100.00%"
            }
            print_analysis_to_terminal(analysis_result)
            return jsonify(analysis_result)

        # Ensure feature ordering and missing-feature defaults
        feature_list = [features.get(col, 0) for col in EXPECTED_FEATURE_ORDER]

        # Predict probabilities with the model
        probabilities = model.predict_proba([feature_list])[0]
        prob_phishing = float(probabilities[1])
        prob_legit = float(probabilities[0])
        model_prediction_is_phishing = prob_phishing > 0.5

        final_verdict_is_phishing = model_prediction_is_phishing

        analysis_result = {
            "url": url,
            "is_phishing": bool(final_verdict_is_phishing),
            "is_on_blocklist": False,
            "prob_phishing": f"{prob_phishing:.2%}",
            "prob_legitimate": f"{prob_legit:.2%}",
            "risky_features": [f for f in EXPECTED_FEATURE_ORDER if features.get(f, 0) > 0],
            "safe_features": [f for f in EXPECTED_FEATURE_ORDER if features.get(f, 0) == 0],
            "model_threshold": 0.5
        }
        print_analysis_to_terminal(analysis_result)
        return jsonify(analysis_result)

    except Exception as e:
        logger.exception("Critical error in /analyze endpoint")
        return jsonify({"error": "A critical server error occurred", "details": str(e)}), 500


# --- Admin / maintenance endpoints (optional, disable in production) ---
@app.route("/admin/update_blocklist", methods=["POST"])
def admin_update_blocklist():
    # Keep this endpoint protected in real deployments
    try:
        conn = init_db(DB_PATH)
        count = update_all_sources(conn)
        conn.close()
        return jsonify({"status": "ok", "lines_processed": count})
    except Exception as e:
        logger.exception("Failed to update blocklist")
        return jsonify({"status": "error", "details": str(e)}), 500


if __name__ == "__main__":
    # Do not run production servers with debug=True; use gunicorn or similar.
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")

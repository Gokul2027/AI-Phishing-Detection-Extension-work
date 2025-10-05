import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

SENSITIVE_WORDS = ["login", "secure", "account", "update", "verify", "password", "bank"]
BRAND_NAMES = ["paypal", "sbi", "hdfc", "amazon", "apple", "microsoft", "google"]

def extract_features(url):
    features = {f: 0 for f in [
        'PctExtHyperlinks', 'PctExtResourceUrls', 'PctNullSelfRedirectHyperlinks',
        'PctExtNullSelfRedirectHyperlinksRT', 'NumNumericChars', 'FrequentDomainNameMismatch',
        'ExtMetaScriptLinkRT', 'NumDash', 'SubmitInfoToEmail', 'NumDots', 'PathLength',
        'QueryLength', 'PathLevel', 'InsecureForms', 'UrlLength', 'NumSensitiveWords',
        'NumQueryComponents', 'PctExtResourceUrlsRT', 'IframeOrFrame', 'HostnameLength',
        'NumAmpersand', 'AbnormalExtFormActionR', 'UrlLengthRT', 'NumDashInHostname',
        'IpAddress', 'AbnormalFormAction', 'EmbeddedBrandName', 'NumUnderscore',
        'MissingTitle', 'DomainInPaths', 'SubdomainLevel', 'ExtFormAction'
    ]}

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        
        # URL-based features that can be calculated even if the site is dead
        features['NumNumericChars'] = sum(c.isdigit() for c in url)
        features['NumDash'] = url.count('-')
        features['NumDots'] = url.count('.')
        features['PathLength'] = len(path)
        features['QueryLength'] = len(parsed.query)
        features['PathLevel'] = path.count('/')
        features['UrlLength'] = len(url)
        features['HostnameLength'] = len(hostname)
        features['IpAddress'] = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0
        features['EmbeddedBrandName'] = 1 if any(b in url.lower() for b in BRAND_NAMES) else 0
        
        # Content-based features - these require a successful connection
        resp = requests.get(url, timeout=5, headers={'User-Agent':'Mozilla/5.0'})
        html = resp.text
        soup = BeautifulSoup(html, "html.parser")
        
        features['NumSensitiveWords'] = sum(w in html.lower() for w in SENSITIVE_WORDS)
        features['IframeOrFrame'] = 1 if soup.find("iframe") or soup.find("frame") else 0
        
        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action") or ""
            if "mailto:" in action: features['SubmitInfoToEmail'] = 1
            if action.startswith("http://"): features['InsecureForms'] = 1
            if urlparse(action).hostname and hostname not in action:
                features['AbnormalFormAction'] = 1

        return features

    except Exception as e:
        # On any failure (dead link, timeout, etc.), print the error and return None
        print(f"Error extracting content-based features for {url}: {e}")
        # Return the URL-based features, as they are still valuable
        return features
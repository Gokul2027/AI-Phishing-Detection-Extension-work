import re
import socket
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# Common sensitive words and brands list
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
        query = parsed.query or ""

        # ---- URL-based Features ----
        features['NumNumericChars'] = sum(c.isdigit() for c in url)
        features['NumDash'] = url.count('-')
        features['NumDots'] = url.count('.')
        features['PathLength'] = len(path)
        features['QueryLength'] = len(query)
        features['PathLevel'] = path.count('/')
        features['UrlLength'] = len(url)
        features['NumQueryComponents'] = query.count('&') + 1 if query else 0
        features['HostnameLength'] = len(hostname)
        features['NumAmpersand'] = url.count('&')
        features['UrlLengthRT'] = len(url) / (len(hostname) + 1)
        features['NumDashInHostname'] = hostname.count('-')
        features['IpAddress'] = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0
        features['NumUnderscore'] = url.count('_')
        features['DomainInPaths'] = 1 if hostname.split('.')[0] in path else 0
        features['SubdomainLevel'] = hostname.count('.') - 1
        features['EmbeddedBrandName'] = any(b in url.lower() for b in BRAND_NAMES)

        # ---- Fetch page ----
        resp = requests.get(url, timeout=5, headers={'User-Agent':'Mozilla/5.0'})
        html = resp.text
        soup = BeautifulSoup(html, "html.parser")

        # Title check
        features['MissingTitle'] = 1 if not soup.title else 0

        # Hyperlinks
        links = [a.get("href") for a in soup.find_all("a", href=True)]
        if links:
            ext_links = [l for l in links if hostname not in l]
            null_self_links = [l for l in links if l in ["#", "javascript:void(0)"]]
            features['PctExtHyperlinks'] = len(ext_links) / len(links)
            features['PctNullSelfRedirectHyperlinks'] = len(null_self_links) / len(links)
            features['PctExtNullSelfRedirectHyperlinksRT'] = (len(ext_links)+len(null_self_links)) / len(links)

        # External resources
        resources = soup.find_all(["img", "script", "link"])
        if resources:
            ext_resources = [r for r in resources if r.get("src") and hostname not in r.get("src")]
            features['PctExtResourceUrls'] = len(ext_resources) / len(resources)
            features['PctExtResourceUrlsRT'] = len(ext_resources) / len(resources)

        # Meta/Script/Link external ratio
        metascripts = soup.find_all(["meta", "script", "link"])
        if metascripts:
            ext_meta = [m for m in metascripts if (m.get("src") or m.get("href")) and hostname not in str(m)]
            features['ExtMetaScriptLinkRT'] = len(ext_meta) / len(metascripts)

        # Forms
        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action") or ""
            if "mailto:" in action:
                features['SubmitInfoToEmail'] = 1
            if action.startswith("http://"):
                features['InsecureForms'] = 1
            if hostname not in action and action != "":
                features['AbnormalFormAction'] = 1
                features['AbnormalExtFormActionR'] += 1
            if "http" in action and hostname not in action:
                features['ExtFormAction'] = 1

        # Sensitive words in content
        features['NumSensitiveWords'] = sum(w in html.lower() for w in SENSITIVE_WORDS)

        # Iframe/Frame
        features['IframeOrFrame'] = 1 if soup.find("iframe") or soup.find("frame") else 0

    except Exception as e:
        print("Error extracting:", e)

    return features


# Example test
if __name__ == "__main__":
    test_url = "https://solthrone.com/"
    feats = extract_features(test_url)
    print(feats)

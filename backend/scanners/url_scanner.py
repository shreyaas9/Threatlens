from urllib.parse import urlparse
import ipaddress
import re


SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "link",
    "work",
    "gq",
    "tk"
}

SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "password",
    "banking",
    "confirm",
    "wallet"
}


def scan_url(url):

    findings = []

    parsed = urlparse(url)

    domain = parsed.hostname or ""
    full_url = url.lower()

    # -------------------------------------------------
    # 1. HTTPS CHECK
    # -------------------------------------------------
    if parsed.scheme != "https":

        findings.append({
            "id": "NO_HTTPS",
            "severity": "MEDIUM",
            "score": 10,
            "message": "This website is using an unencrypted HTTP connection."
        })

    # -------------------------------------------------
    # 2. IP ADDRESS CHECK
    # -------------------------------------------------
    try:

        ipaddress.ip_address(domain)

        findings.append({
            "id": "IP_ADDRESS",
            "severity": "HIGH",
            "score": 20,
            "message": "The website uses an IP address instead of a domain name."
        })

    except ValueError:
        pass

    # -------------------------------------------------
    # 3. LONG URL
    # -------------------------------------------------
    if len(url) > 75:

        findings.append({
            "id": "LONG_URL",
            "severity": "MEDIUM",
            "score": 10,
            "message": "The URL is unusually long, which can be used to hide malicious content."
        })

    # -------------------------------------------------
    # 4. Suspicious TLD
    # -------------------------------------------------
    tld = domain.split(".")[-1].lower() if domain else ""

    if tld in SUSPICIOUS_TLDS:

        findings.append({
            "id": "SUSPICIOUS_TLD",
            "severity": "MEDIUM",
            "score": 15,
            "message": f"The '.{tld}' domain extension is commonly seen in phishing campaigns."
        })

    # -------------------------------------------------
    # 5. Phishing Keywords
    # -------------------------------------------------
    detected_keywords = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in full_url
    ]

    if detected_keywords:

        findings.append({
            "id": "SUSPICIOUS_KEYWORDS",
            "severity": "MEDIUM",
            "score": 10,
            "message": "Sensitive keywords detected: " + ", ".join(detected_keywords)
        })

    # -------------------------------------------------
    # 6. @ Symbol
    # -------------------------------------------------
    if "@" in url:

        findings.append({
            "id": "AT_SYMBOL",
            "severity": "HIGH",
            "score": 20,
            "message": "The URL contains '@', which can hide the actual destination."
        })

    # -------------------------------------------------
    # 7. URL Encoding
    # -------------------------------------------------
    if re.search(r"%[0-9A-Fa-f]{2}", url):

        findings.append({
            "id": "ENCODED_URL",
            "severity": "MEDIUM",
            "score": 10,
            "message": "The URL contains encoded characters that may obscure its true destination."
        })

    # -------------------------------------------------
    # 8. Too Many Subdomains
    # -------------------------------------------------
    if domain.count(".") >= 3:

        findings.append({
            "id": "MULTIPLE_SUBDOMAINS",
            "severity": "MEDIUM",
            "score": 10,
            "message": "The website contains multiple subdomains, which can be used to imitate legitimate sites."
        })

    # -------------------------------------------------
    # 9. Multiple Hyphens
    # -------------------------------------------------
    if domain.count("-") >= 2:

        findings.append({
            "id": "MULTIPLE_HYPHENS",
            "severity": "LOW",
            "score": 5,
            "message": "The domain contains multiple hyphens, a pattern sometimes used in phishing domains."
        })

    return findings
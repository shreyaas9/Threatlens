import json
import os
from urllib.parse import urlparse
from difflib import SequenceMatcher

BASE_DIR = os.path.dirname(os.path.dirname(__file__))

DATA_FILE = os.path.join(
    BASE_DIR,
    "intelligence",
    "legitimate_domains.json"
)


def load_legitimate_domains():
    with open(DATA_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


LEGITIMATE_DOMAINS = load_legitimate_domains()

# -----------------------------------
# Character substitutions
# -----------------------------------

CHARACTER_SUBSTITUTIONS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a"
}

# -----------------------------------
# Common phishing words
# -----------------------------------

PHISHING_WORDS = {
    "login",
    "signin",
    "secure",
    "verify",
    "verification",
    "account",
    "update",
    "bank",
    "banking",
    "wallet",
    "payment",
    "support",
    "mail",
    "portal"
}


def normalize_domain(domain):

    domain = domain.lower()

    if domain.startswith("www."):
        domain = domain[4:]

    # Remove TLD
    domain = domain.split(".")[0]

    # Remove hyphens
    domain = domain.replace("-", "")

    # Character substitutions
    for fake, real in CHARACTER_SUBSTITUTIONS.items():
        domain = domain.replace(fake, real)

    # Remove phishing words
    for word in PHISHING_WORDS:
        domain = domain.replace(word, "")

    return domain.strip()


def similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()


def scan_brand(url):

    findings = []

    parsed = urlparse(url)

    domain = (parsed.hostname or "").lower()

    if not domain:
        return findings

    normalized_input = normalize_domain(domain)

    # -----------------------------------
    # Exact legitimate domain
    # -----------------------------------

    for website in LEGITIMATE_DOMAINS:

        if domain == website["domain"]:
            return findings

    # -----------------------------------
    # Exact normalized match
    # -----------------------------------

    for website in LEGITIMATE_DOMAINS:

        legitimate = normalize_domain(website["domain"])

        if normalized_input == legitimate:

            findings.append({
                "id": "BRAND_IMPERSONATION",
                "severity": "CRITICAL",
                "score": 50,
                "message":
                    f"This domain appears to impersonate "
                    f"{website['brand']}."
            })

            return findings

    # -----------------------------------
    # Similarity match
    # -----------------------------------

    best_match = None
    best_score = 0

    for website in LEGITIMATE_DOMAINS:

        legitimate = normalize_domain(website["domain"])

        score = similarity(
            normalized_input,
            legitimate
        )

        if score > best_score:
            best_score = score
            best_match = website

    if best_match and best_score >= 0.82:

        findings.append({
            "id": "POSSIBLE_TYPOSQUATTING",
            "severity": "CRITICAL",
            "score": 40,
            "message":
                f"This domain closely resembles "
                f"{best_match['brand']} "
                f"({best_match['domain']})."
        })

    return findings
def apply_rules(findings):

    ids = {finding["id"] for finding in findings}

    # ---------------------------------------
    # Rule 1
    # Brand impersonation + No HTTPS
    # ---------------------------------------
    if (
        "NO_HTTPS" in ids
        and (
            "BRAND_IMPERSONATION" in ids
            or "CHARACTER_SUBSTITUTION" in ids
            or "POSSIBLE_TYPOSQUATTING" in ids
        )
    ):
        findings.append({
            "id": "HIGH_PHISHING_CONFIDENCE",
            "severity": "CRITICAL",
            "score": 20,
            "message": (
                "This website appears to impersonate a trusted brand "
                "while using an insecure connection."
            )
        })

    # ---------------------------------------
    # Rule 2
    # Login page over HTTP
    # ---------------------------------------
    if "NO_HTTPS" in ids and "SUSPICIOUS_KEYWORDS" in ids:
        findings.append({
            "id": "LOGIN_OVER_HTTP",
            "severity": "HIGH",
            "score": 10,
            "message": (
                "Sensitive keywords were detected on a website that is "
                "not using HTTPS."
            )
        })

    # ---------------------------------------
    # Rule 3
    # Brand impersonation + phishing keywords
    # ---------------------------------------
    if (
        "SUSPICIOUS_KEYWORDS" in ids
        and (
            "BRAND_IMPERSONATION" in ids
            or "CHARACTER_SUBSTITUTION" in ids
            or "POSSIBLE_TYPOSQUATTING" in ids
        )
    ):
        findings.append({
            "id": "TARGETED_PHISHING",
            "severity": "CRITICAL",
            "score": 20,
            "message": (
                "This website closely resembles a trusted brand and "
                "contains phishing-related keywords."
            )
        })

    return findings
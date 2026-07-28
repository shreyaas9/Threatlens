def calculate_risk(findings):

    # Add all finding scores
    total_score = sum(
        finding["score"] for finding in findings
    )

    # Risk score cannot exceed 100
    risk_score = min(total_score, 100)

    # Normal score-based classification
    if risk_score <= 20:
        status = "LOW"

    elif risk_score <= 50:
        status = "MODERATE"

    elif risk_score <= 80:
        status = "HIGH"

    else:
        status = "CRITICAL"

    # Check the severity of individual findings
    severities = [
        finding["severity"]
        for finding in findings
    ]

    # A critical security finding should never
    # result in LOW or MODERATE overall status.
    if "CRITICAL" in severities and status in ["LOW", "MODERATE"]:
        status = "HIGH"

    return {
        "riskScore": risk_score,
        "status": status,
        "findings": findings
    }
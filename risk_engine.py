def calculate_overall_risk(
    ml_prediction,
    ml_confidence,
    url_risk,
    header_risk,
    features,
):
    """
    Calculate a unified phishing risk score.

    Score:
        0   = lowest risk
        100 = highest risk
    """

    # --------------------------------------------------------
    # ML COMPONENT
    # --------------------------------------------------------

    ml_confidence = float(ml_confidence)

    if ml_prediction == 1:
        ml_risk = ml_confidence * 100
    else:
        ml_risk = (1 - ml_confidence) * 100

    # --------------------------------------------------------
    # URL COMPONENT
    # --------------------------------------------------------

    try:
        url_risk = float(url_risk)
    except (TypeError, ValueError):
        url_risk = 0.0

    url_risk = max(
        0.0,
        min(url_risk, 100.0),
    )

    # --------------------------------------------------------
    # HEADER COMPONENT
    # --------------------------------------------------------

    try:
        header_risk = float(header_risk)
    except (TypeError, ValueError):
        header_risk = 0.0

    header_risk = max(
        0.0,
        min(header_risk, 100.0),
    )

    # --------------------------------------------------------
    # FEATURE-BASED RISK
    # --------------------------------------------------------

    feature_risk = 0.0

    if features.get(
        "has_ip_url",
        False,
    ):
        feature_risk += 20

    if features.get(
        "has_shortener",
        False,
    ):
        feature_risk += 10

    if features.get(
        "has_suspicious_tld",
        False,
    ):
        feature_risk += 10

    if features.get(
        "has_at_symbol",
        False,
    ):
        feature_risk += 15

    if features.get(
        "excessive_subdomains",
        False,
    ):
        feature_risk += 10

    if features.get(
        "excessive_hyphens",
        False,
    ):
        feature_risk += 5

    if features.get(
        "long_url",
        False,
    ):
        feature_risk += 5

    feature_risk = min(
        feature_risk,
        100,
    )

    # --------------------------------------------------------
    # WEIGHTED OVERALL SCORE
    # --------------------------------------------------------

    overall_score = (
        (ml_risk * 0.45)
        + (url_risk * 0.25)
        + (header_risk * 0.20)
        + (feature_risk * 0.10)
    )

    overall_score = round(
        min(
            max(
                overall_score,
                0,
            ),
            100,
        )
    )

    # --------------------------------------------------------
    # RISK LEVEL
    # --------------------------------------------------------

    if overall_score >= 75:
        risk_level = "CRITICAL"

    elif overall_score >= 50:
        risk_level = "HIGH"

    elif overall_score >= 25:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    # --------------------------------------------------------
    # RETURN RESULT
    # --------------------------------------------------------

    return {
        "overall_score": overall_score,
        "risk_level": risk_level,
        "ml_risk": round(
            ml_risk,
            2,
        ),
        "url_risk": round(
            url_risk,
            2,
        ),
        "header_risk": round(
            header_risk,
            2,
        ),
        "feature_risk": round(
            feature_risk,
            2,
        ),
    }
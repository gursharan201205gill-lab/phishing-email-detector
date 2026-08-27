import re


SUSPICIOUS_KEYWORDS = [
    "urgent",
    "verify",
    "verification",
    "password",
    "account",
    "suspended",
    "suspend",
    "login",
    "signin",
    "confirm",
    "confirmation",
    "security alert",
    "click here",
    "reset",
    "payment",
    "invoice",
    "bank",
    "credit card",
    "winner",
    "prize",
    "refund",
    "limited time",
    "action required",
]


SHORTENER_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
]


def extract_urls(text):
    pattern = r"https?://[^\s<>\"']+|www\.[^\s<>\"']+"
    return re.findall(pattern, text, flags=re.IGNORECASE)


def extract_features(text):
    text = str(text)
    lower_text = text.lower()

    urls = extract_urls(text)

    suspicious_keywords = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in lower_text
    ]

    has_https = any(url.lower().startswith("https://") for url in urls)

    has_ip_url = any(
        re.search(
            r"https?://(?:\d{1,3}\.){3}\d{1,3}",
            url,
            flags=re.IGNORECASE,
        )
        for url in urls
    )

    has_shortener = any(
        domain in url.lower()
        for url in urls
        for domain in SHORTENER_DOMAINS
    )

    return {
        "url_count": len(urls),
        "suspicious_keyword_count": len(suspicious_keywords),
        "suspicious_keywords": suspicious_keywords,
        "has_https": has_https,
        "has_ip_url": has_ip_url,
        "has_shortener": has_shortener,
        "text_length": len(text),
    }


def augment_text(text):
    features = extract_features(text)

    extra_tokens = []

    extra_tokens.append(
        f"URL_COUNT_{min(features['url_count'], 10)}"
    )

    extra_tokens.append(
        f"SUSPICIOUS_COUNT_"
        f"{min(features['suspicious_keyword_count'], 10)}"
    )

    if features["has_https"]:
        extra_tokens.append("HAS_HTTPS")

    if features["has_ip_url"]:
        extra_tokens.append("HAS_IP_URL")

    if features["has_shortener"]:
        extra_tokens.append("HAS_URL_SHORTENER")

    for keyword in features["suspicious_keywords"]:
        safe_keyword = keyword.replace(" ", "_")
        extra_tokens.append(f"SUSPICIOUS_{safe_keyword}")

    return f"{text} {' '.join(extra_tokens)}"
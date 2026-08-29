from pyexpat import features
import re
from turtle import st
from turtle import st
from urllib.parse import urlparse

from risk_engine import calculate_overall_risk


# ============================================================
# SUSPICIOUS KEYWORDS
# ============================================================

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


# ============================================================
# KNOWN URL SHORTENERS
# ============================================================

SHORTENER_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
]


# ============================================================
# SUSPICIOUS TOP-LEVEL DOMAINS
# ============================================================

SUSPICIOUS_TLDS = [
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".top",
    ".xyz",
    ".click",
    ".link",
    ".work",
    ".buzz",
]


# ============================================================
# URL EXTRACTION
# ============================================================

def extract_urls(text):
    """
    Extract HTTP, HTTPS and www URLs from text.
    """

    pattern = r"https?://[^\s<>\"']+|www\.[^\s<>\"']+"

    return re.findall(
        pattern,
        str(text),
        flags=re.IGNORECASE,
    )


# ============================================================
# IP ADDRESS DETECTION
# ============================================================

def is_ip_address(hostname):
    """
    Check whether a hostname is an IPv4 address.
    """

    if not hostname:
        return False

    return bool(
        re.fullmatch(
            r"(?:\d{1,3}\.){3}\d{1,3}",
            hostname,
        )
    )


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def extract_domain(url):
    """
    Extract hostname/domain from a URL.
    """

    try:

        parsed = urlparse(
            url if url.startswith(("http://", "https://"))
            else f"http://{url}"
        )

        return (
            parsed.hostname
            or ""
        ).lower()

    except Exception:

        return ""


# ============================================================
# URL SECURITY ANALYSIS
# ============================================================

def analyze_url(url):
    """
    Analyze an individual URL for suspicious indicators.
    """

    url_lower = url.lower()

    domain = extract_domain(url)

    parsed = None

    try:

        parsed = urlparse(
            url if url.startswith(("http://", "https://"))
            else f"http://{url}"
        )

    except Exception:

        pass

    # --------------------------------------------------------
    # HTTPS
    # --------------------------------------------------------

    has_https = url_lower.startswith(
        "https://"
    )

    # --------------------------------------------------------
    # IP address
    # --------------------------------------------------------

    has_ip = is_ip_address(
        domain
    )

    # --------------------------------------------------------
    # URL shortener
    # --------------------------------------------------------

    is_shortener = any(
        shortener == domain
        or domain.endswith(
            "." + shortener
        )
        for shortener in SHORTENER_DOMAINS
    )

    # --------------------------------------------------------
    # Suspicious TLD
    # --------------------------------------------------------

    suspicious_tld = any(
        domain.endswith(tld)
        for tld in SUSPICIOUS_TLDS
    )

    # --------------------------------------------------------
    # @ symbol
    # --------------------------------------------------------

    has_at_symbol = "@" in url

    # --------------------------------------------------------
    # Excessive hyphens
    # --------------------------------------------------------

    hyphen_count = domain.count("-")

    excessive_hyphens = (
        hyphen_count >= 3
    )

    # --------------------------------------------------------
    # Subdomain count
    # --------------------------------------------------------

    domain_parts = [
        part
        for part in domain.split(".")
        if part
    ]

    subdomain_count = max(
        len(domain_parts) - 2,
        0,
    )

    excessive_subdomains = (
        subdomain_count >= 3
    )

    # --------------------------------------------------------
    # URL length
    # --------------------------------------------------------

    long_url = len(url) >= 100

    # --------------------------------------------------------
    # Domain length
    # --------------------------------------------------------

    long_domain = len(domain) >= 40

    # --------------------------------------------------------
    # Suspicious characters
    # --------------------------------------------------------

    suspicious_characters = bool(
        re.search(
            r"[%{}|\\^`<>]",
            url,
        )
    )

    # --------------------------------------------------------
    # Port number
    # --------------------------------------------------------

    unusual_port = False

    if parsed:

        try:

            port = parsed.port

            if port is not None:

                unusual_port = port not in [
                    80,
                    443,
                ]

        except ValueError:

            unusual_port = True

    # --------------------------------------------------------
    # URL risk score
    # --------------------------------------------------------

    url_risk_score = 0

    indicators = []

    if not has_https:

        url_risk_score += 10

        indicators.append(
            "No HTTPS"
        )

    if has_ip:

        url_risk_score += 30

        indicators.append(
            "IP-based URL"
        )

    if is_shortener:

        url_risk_score += 20

        indicators.append(
            "URL shortener"
        )

    if suspicious_tld:

        url_risk_score += 15

        indicators.append(
            "Suspicious TLD"
        )

    if has_at_symbol:

        url_risk_score += 20

        indicators.append(
            "@ symbol in URL"
        )

    if excessive_hyphens:

        url_risk_score += 10

        indicators.append(
            "Excessive hyphens"
        )

    if excessive_subdomains:

        url_risk_score += 10

        indicators.append(
            "Many subdomains"
        )

    if long_url:

        url_risk_score += 5

        indicators.append(
            "Very long URL"
        )

    if long_domain:

        url_risk_score += 5

        indicators.append(
            "Very long domain"
        )

    if suspicious_characters:

        url_risk_score += 10

        indicators.append(
            "Suspicious URL characters"
        )

    if unusual_port:

        url_risk_score += 10

        indicators.append(
            "Unusual port"
        )

    url_risk_score = min(
        url_risk_score,
        100,
    )

    return {
        "url": url,
        "domain": domain,
        "has_https": has_https,
        "has_ip": has_ip,
        "is_shortener": is_shortener,
        "suspicious_tld": suspicious_tld,
        "has_at_symbol": has_at_symbol,
        "hyphen_count": hyphen_count,
        "subdomain_count": subdomain_count,
        "long_url": long_url,
        "long_domain": long_domain,
        "suspicious_characters": suspicious_characters,
        "unusual_port": unusual_port,
        "url_risk_score": url_risk_score,
        "indicators": indicators,
    }


# ============================================================
# COMPLETE URL ANALYSIS
# ============================================================

def analyze_urls(text):
    """
    Analyze all URLs found in text.
    """

    urls = extract_urls(text)

    results = [
        analyze_url(url)
        for url in urls
    ]

    if results:

        average_risk = round(
            sum(
                result["url_risk_score"]
                for result in results
            )
            / len(results)
        )

    else:

        average_risk = 0

    return {
        "urls": urls,
        "results": results,
        "url_count": len(urls),
        "average_url_risk": average_risk,
    }


# ============================================================
# EMAIL FEATURE EXTRACTION
# ============================================================

def extract_features(text):

    text = str(text)

    lower_text = text.lower()

    urls = extract_urls(
        text
    )

    suspicious_keywords = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in lower_text
    ]

    # --------------------------------------------------------
    # HTTPS
    # --------------------------------------------------------

    has_https = any(
        url.lower().startswith(
            "https://"
        )
        for url in urls
    )

    # --------------------------------------------------------
    # IP-based URL
    # --------------------------------------------------------

    has_ip_url = any(
        analyze_url(url)["has_ip"]
        for url in urls
    )

    # --------------------------------------------------------
    # URL shortener
    # --------------------------------------------------------

    has_shortener = any(
        analyze_url(url)["is_shortener"]
        for url in urls
    )

    # --------------------------------------------------------
    # Advanced URL analysis
    # --------------------------------------------------------

    url_analysis = analyze_urls(
        text
    )

    has_suspicious_tld = any(
        result["suspicious_tld"]
        for result in url_analysis["results"]
    )

    has_at_symbol = any(
        result["has_at_symbol"]
        for result in url_analysis["results"]
    )

    excessive_subdomains = any(
        result["subdomain_count"] >= 3
        for result in url_analysis["results"]
    )

    excessive_hyphens = any(
        result["excessive_hyphens"]
        if "excessive_hyphens" in result
        else result["hyphen_count"] >= 3
        for result in url_analysis["results"]
    )

    long_url = any(
        result["long_url"]
        for result in url_analysis["results"]
    )

    suspicious_characters = any(
        result["suspicious_characters"]
        for result in url_analysis["results"]
    )

    return {
        "url_count": len(urls),

        "suspicious_keyword_count":
            len(suspicious_keywords),

        "suspicious_keywords":
            suspicious_keywords,

        "has_https":
            has_https,

        "has_ip_url":
            has_ip_url,

        "has_shortener":
            has_shortener,

        "has_suspicious_tld":
            has_suspicious_tld,

        "has_at_symbol":
            has_at_symbol,

        "excessive_subdomains":
            excessive_subdomains,

        "excessive_hyphens":
            excessive_hyphens,

        "long_url":
            long_url,

        "suspicious_characters":
            suspicious_characters,

        "average_url_risk":
            url_analysis["average_url_risk"],

        "url_analysis":
            url_analysis,

        "text_length":
            len(text),
    }


# ============================================================
# TEXT AUGMENTATION FOR ML MODEL
# ============================================================

def augment_text(text):

    features = extract_features(
        text
    )

    extra_tokens = []

    # --------------------------------------------------------
    # URL count
    # --------------------------------------------------------

    extra_tokens.append(
        f"URL_COUNT_"
        f"{min(features['url_count'], 10)}"
    )

    # --------------------------------------------------------
    # Suspicious keyword count
    # --------------------------------------------------------

    extra_tokens.append(
        f"SUSPICIOUS_COUNT_"
        f"{min(features['suspicious_keyword_count'], 10)}"
    )

    # --------------------------------------------------------
    # HTTPS
    # --------------------------------------------------------

    if features["has_https"]:

        extra_tokens.append(
            "HAS_HTTPS"
        )

    # --------------------------------------------------------
    # IP URL
    # --------------------------------------------------------

    if features["has_ip_url"]:

        extra_tokens.append(
            "HAS_IP_URL"
        )

    # --------------------------------------------------------
    # URL shortener
    # --------------------------------------------------------

    if features["has_shortener"]:

        extra_tokens.append(
            "HAS_URL_SHORTENER"
        )

    # --------------------------------------------------------
    # Suspicious TLD
    # --------------------------------------------------------

    if features[
        "has_suspicious_tld"
    ]:

        extra_tokens.append(
            "HAS_SUSPICIOUS_TLD"
        )

    # --------------------------------------------------------
    # @ symbol
    # --------------------------------------------------------

    if features[
        "has_at_symbol"
    ]:

        extra_tokens.append(
            "HAS_AT_SYMBOL"
        )

    # --------------------------------------------------------
    # Excessive subdomains
    # --------------------------------------------------------

    if features[
        "excessive_subdomains"
    ]:

        extra_tokens.append(
            "HAS_EXCESSIVE_SUBDOMAINS"
        )

    # --------------------------------------------------------
    # Excessive hyphens
    # --------------------------------------------------------

    if features[
        "excessive_hyphens"
    ]:

        extra_tokens.append(
            "HAS_EXCESSIVE_HYPHENS"
        )

    # --------------------------------------------------------
    # Long URL
    # --------------------------------------------------------

    if features["long_url"]:

        extra_tokens.append(
            "HAS_LONG_URL"
        )

    # --------------------------------------------------------
    # Suspicious characters
    # --------------------------------------------------------

    if features[
        "suspicious_characters"
    ]:

        extra_tokens.append(
            "HAS_SUSPICIOUS_URL_CHARACTERS"
        )

    # --------------------------------------------------------
    # Suspicious keywords
    # --------------------------------------------------------

    for keyword in features[
        "suspicious_keywords"
    ]:

        safe_keyword = keyword.replace(
            " ",
            "_",
        )

        extra_tokens.append(
            f"SUSPICIOUS_{safe_keyword}"
        )

    return (
        f"{text} "
        f"{' '.join(extra_tokens)}"
    )

# ====================================================
# URL RISK
# ====================================================

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
        extra_tokens.append(
            f"SUSPICIOUS_{safe_keyword}"
        )

    return f"{text} {' '.join(extra_tokens)}"


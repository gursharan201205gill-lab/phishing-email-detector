import re
from email import policy
from email.parser import Parser
from urllib.parse import urlparse


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def extract_email_domain(email_address):
    """
    Extract domain from an email address.
    """

    if not email_address:
        return ""

    match = re.search(
        r"[\w.+-]+@([\w.-]+\.[A-Za-z]{2,})",
        email_address,
    )

    if match:
        return match.group(1).lower()

    return ""


# ============================================================
# HEADER VALUE CLEANING
# ============================================================

def clean_header(value):
    """
    Convert a header value into a clean string.
    """

    if value is None:
        return ""

    return str(value).strip()


# ============================================================
# PARSE EMAIL HEADERS
# ============================================================

def parse_headers(raw_headers):
    """
    Parse raw email headers.
    """

    raw_headers = str(raw_headers).strip()

    if not raw_headers:
        return {}

    try:

        message = Parser(
            policy=policy.default
        ).parsestr(raw_headers)

    except Exception:

        return {}

    headers = {}

    for key, value in message.items():

        headers[key.lower()] = clean_header(
            value
        )

    return headers


# ============================================================
# RECEIVED HEADER COUNT
# ============================================================

def count_received_headers(headers):
    """
    Count Received headers from raw header text.
    """

    if not headers:
        return 0

    received = headers.get(
        "received",
        ""
    )

    if not received:
        return 0

    if isinstance(received, list):
        return len(received)

    return received.count(
        "Received:"
    ) + 1


# ============================================================
# AUTHENTICATION STATUS
# ============================================================

def get_authentication_status(
    headers
):

    authentication_results = headers.get(
        "authentication-results",
        ""
    )

    received_spf = headers.get(
        "received-spf",
        ""
    )

    result = {
        "spf": "Not Provided",
        "dkim": "Not Provided",
        "dmarc": "Not Provided",
    }

    combined = (
        authentication_results
        + " "
        + received_spf
    ).lower()

    # SPF

    if re.search(
        r"\bspf\s*=\s*pass\b",
        combined,
    ):

        result["spf"] = "Pass"

    elif re.search(
        r"\bspf\s*=\s*(fail|softfail|neutral|none|temperror|permerror)\b",
        combined,
    ):

        result["spf"] = "Fail / Not Passed"

    # DKIM

    if re.search(
        r"\bdkim\s*=\s*pass\b",
        combined,
    ):

        result["dkim"] = "Pass"

    elif re.search(
        r"\bdkim\s*=\s*(fail|none|neutral|temperror|permerror)\b",
        combined,
    ):

        result["dkim"] = "Fail / Not Passed"

    # DMARC

    if re.search(
        r"\bdmarc\s*=\s*pass\b",
        combined,
    ):

        result["dmarc"] = "Pass"

    elif re.search(
        r"\bdmarc\s*=\s*(fail|none|temperror|permerror)\b",
        combined,
    ):

        result["dmarc"] = "Fail / Not Passed"

    return result


# ============================================================
# HEADER SECURITY ANALYSIS
# ============================================================

def analyze_headers(raw_headers):

    headers = parse_headers(
        raw_headers
    )

    if not headers:

        return {
            "valid": False,
            "error": "No valid email headers detected.",
        }

    from_header = headers.get(
        "from",
        ""
    )

    reply_to = headers.get(
        "reply-to",
        ""
    )

    return_path = headers.get(
        "return-path",
        ""
    )

    message_id = headers.get(
        "message-id",
        ""
    )

    from_domain = extract_email_domain(
        from_header
    )

    reply_domain = extract_email_domain(
        reply_to
    )

    return_domain = extract_email_domain(
        return_path
    )

    # --------------------------------------------------------
    # Domain mismatch checks
    # --------------------------------------------------------

    reply_to_mismatch = (
        bool(from_domain)
        and bool(reply_domain)
        and from_domain != reply_domain
    )

    return_path_mismatch = (
        bool(from_domain)
        and bool(return_domain)
        and from_domain != return_domain
    )

    # --------------------------------------------------------
    # Authentication
    # --------------------------------------------------------

    authentication = get_authentication_status(
        headers
    )

    # --------------------------------------------------------
    # Risk scoring
    # --------------------------------------------------------

    risk_score = 0

    indicators = []

    if reply_to_mismatch:

        risk_score += 30

        indicators.append(
            "From and Reply-To domains do not match"
        )

    if return_path_mismatch:

        risk_score += 20

        indicators.append(
            "From and Return-Path domains do not match"
        )

    if authentication["spf"] == "Fail / Not Passed":

        risk_score += 20

        indicators.append(
            "SPF authentication failed or was not passed"
        )

    if authentication["dkim"] == "Fail / Not Passed":

        risk_score += 15

        indicators.append(
            "DKIM authentication failed or was not passed"
        )

    if authentication["dmarc"] == "Fail / Not Passed":

        risk_score += 25

        indicators.append(
            "DMARC authentication failed or was not passed"
        )

    if not message_id:

        risk_score += 5

        indicators.append(
            "Message-ID header is missing"
        )

    risk_score = min(
        risk_score,
        100,
    )

    return {
        "valid": True,

        "from": from_header,

        "reply_to": reply_to,

        "return_path": return_path,

        "message_id": message_id,

        "from_domain": from_domain,

        "reply_to_domain": reply_domain,

        "return_path_domain": return_domain,

        "reply_to_mismatch":
            reply_to_mismatch,

        "return_path_mismatch":
            return_path_mismatch,

        "authentication":
            authentication,

        "received_count":
            count_received_headers(
                headers
            ),

        "risk_score":
            risk_score,

        "indicators":
            indicators,

        "headers":
            headers,
    }
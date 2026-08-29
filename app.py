import json
import os

import joblib
import matplotlib.pyplot as plt
import streamlit as st

from feature_engineering import (
    extract_features,
    augment_text,
)

from email_header_analysis import (
    analyze_headers,
)

from risk_engine import (
    calculate_overall_risk,
)


# ============================================================
# PATHS
# ============================================================

MODEL_PATH = "model/phishing_model.joblib"

METRICS_PATH = "model/metrics.json"


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Phishing Email Detector",
    page_icon="🛡️",
    layout="wide",
)


# ============================================================
# LOAD MODEL
# ============================================================

@st.cache_resource
def load_model():

    if not os.path.exists(MODEL_PATH):

        raise FileNotFoundError(
            f"Model file not found: {MODEL_PATH}"
        )

    return joblib.load(
        MODEL_PATH
    )


# ============================================================
# LOAD METRICS
# ============================================================

@st.cache_data
def load_metrics():

    if not os.path.exists(METRICS_PATH):

        raise FileNotFoundError(
            f"Metrics file not found: {METRICS_PATH}"
        )

    with open(
        METRICS_PATH,
        "r",
        encoding="utf-8",
    ) as file:

        return json.load(file)


# ============================================================
# LOAD RESOURCES
# ============================================================

model = load_model()

metrics = load_metrics()


# ============================================================
# HEADER
# ============================================================

st.title(
    "🛡️ Phishing Email Detection System"
)

st.markdown(
    """
    ### Machine Learning Based Email Security

    Analyze an email and determine whether it is
    likely to be **Phishing** or **Safe** using a
    Scikit-learn machine learning model.

    The system also analyzes:

    - 🔗 URLs
    - 📨 Email headers
    - 🔐 SPF
    - 🔏 DKIM
    - 🛡️ DMARC
    - ⚠️ Suspicious keywords
    - 🎯 Overall security risk
    """
)


st.divider()


# ============================================================
# EMAIL INFORMATION
# ============================================================

st.subheader(
    "📧 Email Information"
)


col1, col2 = st.columns(2)


with col1:

    sender = st.text_input(
        "Sender Email",
        placeholder="example@domain.com",
    )


with col2:

    subject = st.text_input(
        "Email Subject",
        placeholder="Enter email subject",
    )


email_body = st.text_area(
    "Email Content",
    height=250,
    placeholder=(
        "Paste the complete email content here..."
    ),
)


# ============================================================
# EMAIL HEADERS
# ============================================================

st.subheader(
    "📨 Email Headers"
)

st.caption(
    "Optional: paste the raw email headers to perform "
    "SPF, DKIM, DMARC and sender-domain analysis."
)


raw_headers = st.text_area(
    "Raw Email Headers",
    height=220,
    placeholder=(
        "From: support@example.com\n"
        "Reply-To: attacker@example.xyz\n"
        "Return-Path: attacker@example.xyz\n"
        "Message-ID: <123@example.com>\n"
        "Authentication-Results: example.com; "
        "spf=fail; dkim=fail; dmarc=fail"
    ),
)


# ============================================================
# ANALYZE BUTTON
# ============================================================

analyze = st.button(
    "🔍 Analyze Email",
    type="primary",
    use_container_width=True,
)


# ============================================================
# ANALYSIS
# ============================================================

if analyze:

    # --------------------------------------------------------
    # INPUT VALIDATION
    # --------------------------------------------------------

    if not email_body.strip():

        st.warning(
            "Please enter the email content."
        )

    else:

        # ----------------------------------------------------
        # COMBINE EMAIL DATA
        # ----------------------------------------------------

        combined_text = f"""
Sender: {sender}
Subject: {subject}
Email Body: {email_body}
"""


        # ----------------------------------------------------
        # FEATURE ENGINEERING
        # ----------------------------------------------------

        processed_text = augment_text(
            combined_text
        )


        # ----------------------------------------------------
        # MACHINE LEARNING PREDICTION
        # ----------------------------------------------------

        prediction = model.predict(
            [processed_text]
        )[0]


        probabilities = model.predict_proba(
            [processed_text]
        )[0]


        # ----------------------------------------------------
        # PROBABILITIES
        # ----------------------------------------------------

        safe_probability = float(
            probabilities[0]
        )

        phishing_probability = float(
            probabilities[1]
        )


        # ----------------------------------------------------
        # CONFIDENCE
        # ----------------------------------------------------

        if prediction == 1:

            confidence = phishing_probability

        else:

            confidence = safe_probability


        # ----------------------------------------------------
        # FEATURE ANALYSIS
        # ----------------------------------------------------

        features = extract_features(
            combined_text
        )


        # ----------------------------------------------------
        # HEADER ANALYSIS
        # ----------------------------------------------------

        header_result = None

        header_risk = 0.0


        if raw_headers.strip():

            header_result = analyze_headers(
                raw_headers
            )


            if header_result.get(
                "valid",
                False,
            ):

                header_risk = float(
                    header_result.get(
                        "risk_score",
                        0,
                    )
                )


        # ----------------------------------------------------
        # URL RISK
        # ----------------------------------------------------

        url_risk = float(
            features.get(
                "average_url_risk",
                0,
            )
        )


        # ----------------------------------------------------
        # UNIFIED RISK ENGINE
        # ----------------------------------------------------

        risk_result = calculate_overall_risk(

            ml_prediction=prediction,

            ml_confidence=confidence,

            url_risk=url_risk,

            header_risk=header_risk,

            features=features,
        )


        # ====================================================
        # DETECTION RESULT
        # ====================================================

        st.divider()

        st.header(
            "🎯 Detection Result"
        )


        if prediction == 1:

            st.error(
                "🚨 PHISHING EMAIL DETECTED"
            )

        else:

            st.success(
                "✅ EMAIL APPEARS SAFE"
            )


        st.metric(
            "Model Confidence",
            f"{confidence * 100:.2f}%",
        )


        st.progress(
            float(confidence)
        )


        # ====================================================
        # OVERALL SECURITY ASSESSMENT
        # ====================================================

        st.divider()

        st.header(
            "🛡️ Overall Security Assessment"
        )


        overall_score = risk_result[
            "overall_score"
        ]


        risk_level = risk_result[
            "risk_level"
        ]


        # ----------------------------------------------------
        # RISK LEVEL
        # ----------------------------------------------------

        if risk_level == "CRITICAL":

            st.error(
                f"🚨 CRITICAL RISK — "
                f"{overall_score}/100"
            )

        elif risk_level == "HIGH":

            st.error(
                f"🔴 HIGH RISK — "
                f"{overall_score}/100"
            )

        elif risk_level == "MEDIUM":

            st.warning(
                f"🟠 MEDIUM RISK — "
                f"{overall_score}/100"
            )

        else:

            st.success(
                f"🟢 LOW RISK — "
                f"{overall_score}/100"
            )


        st.progress(
            float(overall_score) / 100
        )


        # ====================================================
        # RISK BREAKDOWN
        # ====================================================

        st.subheader(
            "📊 Risk Breakdown"
        )


        r1, r2, r3, r4 = st.columns(4)


        with r1:

            st.metric(
                "🤖 ML Risk",
                f"{risk_result['ml_risk']:.1f}/100",
            )


        with r2:

            st.metric(
                "🔗 URL Risk",
                f"{risk_result['url_risk']:.1f}/100",
            )


        with r3:

            st.metric(
                "📨 Header Risk",
                f"{risk_result['header_risk']:.1f}/100",
            )


        with r4:

            st.metric(
                "⚠️ Feature Risk",
                f"{risk_result['feature_risk']:.1f}/100",
            )


        # ====================================================
        # EMAIL FEATURE ANALYSIS
        # ====================================================

        st.divider()

        st.subheader(
            "🔎 Email Feature Analysis"
        )


        c1, c2, c3, c4 = st.columns(4)


        with c1:

            st.metric(
                "URLs Found",
                features.get(
                    "url_count",
                    0,
                ),
            )


        with c2:

            st.metric(
                "Suspicious Keywords",
                features.get(
                    "suspicious_keyword_count",
                    0,
                ),
            )


        with c3:

            st.metric(
                "HTTPS",
                (
                    "Yes"
                    if features.get(
                        "has_https",
                        False,
                    )
                    else "No"
                ),
            )


        with c4:

            st.metric(
                "IP URL",
                (
                    "Yes"
                    if features.get(
                        "has_ip_url",
                        False,
                    )
                    else "No"
                ),
            )


        # ====================================================
        # SUSPICIOUS KEYWORDS
        # ====================================================

        suspicious_keywords = features.get(
            "suspicious_keywords",
            [],
        )


        if suspicious_keywords:

            st.write(
                "**Suspicious keywords detected:**"
            )


            st.write(
                ", ".join(
                    suspicious_keywords
                )
            )


        # ====================================================
        # URL SHORTENER WARNING
        # ====================================================

        if features.get(
            "has_shortener",
            False,
        ):

            st.warning(
                "⚠️ A URL shortener was detected."
            )


        # ====================================================
        # URL RISK INFORMATION
        # ====================================================

        if "average_url_risk" in features:

            st.metric(
                "Average URL Risk",
                f"{features['average_url_risk']:.1f}/100",
            )


        # ====================================================
        # HEADER ANALYSIS RESULTS
        # ====================================================

        if header_result:

            st.divider()

            st.subheader(
                "📨 Email Header Security Analysis"
            )


            if not header_result.get(
                "valid",
                False,
            ):

                st.warning(
                    header_result.get(
                        "error",
                        "Unable to analyze headers.",
                    )
                )

            else:

                h1, h2, h3 = st.columns(3)


                with h1:

                    st.metric(
                        "Header Risk",
                        f"{header_result.get('risk_score', 0)}/100",
                    )


                with h2:

                    st.metric(
                        "Received Headers",
                        header_result.get(
                            "received_count",
                            0,
                        ),
                    )


                with h3:

                    st.metric(
                        "Header Indicators",
                        len(
                            header_result.get(
                                "indicators",
                                [],
                            )
                        ),
                    )


                # ------------------------------------------------
                # SENDER INFORMATION
                # ------------------------------------------------

                st.write(
                    "**Sender:** "
                    + header_result.get(
                        "from",
                        "Not provided",
                    )
                )


                st.write(
                    "**Reply-To:** "
                    + header_result.get(
                        "reply_to",
                        "Not provided",
                    )
                )


                st.write(
                    "**Return-Path:** "
                    + header_result.get(
                        "return_path",
                        "Not provided",
                    )
                )


                st.write(
                    "**Message-ID:** "
                    + header_result.get(
                        "message_id",
                        "Not provided",
                    )
                )


                # ------------------------------------------------
                # DOMAIN ANALYSIS
                # ------------------------------------------------

                st.subheader(
                    "🌐 Domain Analysis"
                )


                d1, d2, d3 = st.columns(3)


                with d1:

                    st.write(
                        "**From Domain**"
                    )

                    st.code(
                        header_result.get(
                            "from_domain",
                            "Not detected",
                        )
                    )


                with d2:

                    st.write(
                        "**Reply-To Domain**"
                    )

                    st.code(
                        header_result.get(
                            "reply_to_domain",
                            "Not detected",
                        )
                    )


                with d3:

                    st.write(
                        "**Return-Path Domain**"
                    )

                    st.code(
                        header_result.get(
                            "return_path_domain",
                            "Not detected",
                        )
                    )


                # ------------------------------------------------
                # DOMAIN MISMATCH
                # ------------------------------------------------

                if header_result.get(
                    "reply_to_mismatch",
                    False,
                ):

                    st.error(
                        "🔴 From and Reply-To domains do not match."
                    )


                if header_result.get(
                    "return_path_mismatch",
                    False,
                ):

                    st.error(
                        "🔴 From and Return-Path domains do not match."
                    )


                # ------------------------------------------------
                # AUTHENTICATION
                # ------------------------------------------------

                st.subheader(
                    "🔐 Email Authentication"
                )


                authentication = (
                    header_result.get(
                        "authentication",
                        {},
                    )
                )


                a1, a2, a3 = st.columns(3)


                with a1:

                    spf = authentication.get(
                        "spf",
                        "Not Provided",
                    )

                    if spf == "Pass":

                        st.success(
                            f"SPF: {spf}"
                        )

                    elif spf == "Not Provided":

                        st.warning(
                            f"SPF: {spf}"
                        )

                    else:

                        st.error(
                            f"SPF: {spf}"
                        )


                with a2:

                    dkim = authentication.get(
                        "dkim",
                        "Not Provided",
                    )

                    if dkim == "Pass":

                        st.success(
                            f"DKIM: {dkim}"
                        )

                    elif dkim == "Not Provided":

                        st.warning(
                            f"DKIM: {dkim}"
                        )

                    else:

                        st.error(
                            f"DKIM: {dkim}"
                        )


                with a3:

                    dmarc = authentication.get(
                        "dmarc",
                        "Not Provided",
                    )

                    if dmarc == "Pass":

                        st.success(
                            f"DMARC: {dmarc}"
                        )

                    elif dmarc == "Not Provided":

                        st.warning(
                            f"DMARC: {dmarc}"
                        )

                    else:

                        st.error(
                            f"DMARC: {dmarc}"
                        )


                # ------------------------------------------------
                # HEADER INDICATORS
                # ------------------------------------------------

                indicators = header_result.get(
                    "indicators",
                    [],
                )


                if indicators:

                    st.subheader(
                        "🚨 Header Security Indicators"
                    )


                    for indicator in indicators:

                        st.write(
                            f"🔴 {indicator}"
                        )


        # ====================================================
        # WHY WAS EMAIL FLAGGED?
        # ====================================================

        st.divider()

        st.subheader(
            "🔎 Why Was This Email Flagged?"
        )


        findings = []


        # ----------------------------------------------------
        # ML FINDING
        # ----------------------------------------------------

        if prediction == 1:

            findings.append(
                "🤖 Machine-learning model classified "
                "the email as phishing with "
                f"{phishing_probability * 100:.1f}% confidence."
            )


        # ----------------------------------------------------
        # IP URL
        # ----------------------------------------------------

        if features.get(
            "has_ip_url",
            False,
        ):

            findings.append(
                "🔴 An IP-based URL was detected."
            )


        # ----------------------------------------------------
        # URL SHORTENER
        # ----------------------------------------------------

        if features.get(
            "has_shortener",
            False,
        ):

            findings.append(
                "🟠 A URL shortening service was detected."
            )


        # ----------------------------------------------------
        # SUSPICIOUS KEYWORDS
        # ----------------------------------------------------

        if features.get(
            "suspicious_keyword_count",
            0,
        ) > 0:

            findings.append(
                "🟠 "
                f"{features['suspicious_keyword_count']} "
                "suspicious keyword(s) were detected."
            )


        # ----------------------------------------------------
        # HEADER FINDINGS
        # ----------------------------------------------------

        if header_result and header_result.get(
            "valid",
            False,
        ):

            if header_result.get(
                "reply_to_mismatch",
                False,
            ):

                findings.append(
                    "🔴 From and Reply-To domains do not match."
                )


            if header_result.get(
                "return_path_mismatch",
                False,
            ):

                findings.append(
                    "🔴 From and Return-Path domains do not match."
                )


            authentication = (
                header_result.get(
                    "authentication",
                    {},
                )
            )


            if authentication.get(
                "spf"
            ) == "Fail / Not Passed":

                findings.append(
                    "🔴 SPF authentication failed."
                )


            if authentication.get(
                "dkim"
            ) == "Fail / Not Passed":

                findings.append(
                    "🔴 DKIM authentication failed."
                )


            if authentication.get(
                "dmarc"
            ) == "Fail / Not Passed":

                findings.append(
                    "🔴 DMARC authentication failed."
                )


        # ----------------------------------------------------
        # DISPLAY FINDINGS
        # ----------------------------------------------------

        if findings:

            for finding in findings:

                st.write(
                    finding
                )

        else:

            st.success(
                "No significant security indicators were detected."
            )


        # ====================================================
        # RECOMMENDED ACTIONS
        # ====================================================

        st.divider()

        st.subheader(
            "🛡️ Recommended Actions"
        )


        if overall_score >= 75:

            st.error(
                """
                **High-priority action recommended**

                - Do not click links in this email.
                - Do not provide passwords or financial information.
                - Do not download attachments.
                - Verify the sender through an independent channel.
                - Report the message as phishing.
                """
            )

        elif overall_score >= 50:

            st.warning(
                """
                **Caution recommended**

                - Verify the sender.
                - Avoid clicking suspicious links.
                - Check the destination domain carefully.
                - Do not provide sensitive information.
                """
            )

        elif overall_score >= 25:

            st.info(
                """
                **Some suspicious indicators were detected.**

                Review the sender, links and email content
                carefully before taking action.
                """
            )

        else:

            st.success(
                """
                No major risk indicators were detected.

                Continue following normal email-security
                practices.
                """
            )


# ============================================================
# MODEL PERFORMANCE
# ============================================================

st.divider()

st.header(
    "📊 Model Performance"
)


accuracy = metrics.get(
    "accuracy",
    0,
)


st.metric(
    "Test Accuracy",
    f"{accuracy * 100:.2f}%",
)


# ============================================================
# TRAINING / TESTING INFORMATION
# ============================================================

m1, m2 = st.columns(2)


with m1:

    st.metric(
        "Training Samples",
        metrics.get(
            "training_samples",
            "N/A",
        ),
    )


with m2:

    st.metric(
        "Testing Samples",
        metrics.get(
            "testing_samples",
            "N/A",
        ),
    )


# ============================================================
# CONFUSION MATRIX
# ============================================================

cm = metrics.get(
    "confusion_matrix",
    [],
)


if (
    isinstance(cm, list)
    and len(cm) == 2
    and all(
        isinstance(row, list)
        and len(row) == 2
        for row in cm
    )
):

    st.subheader(
        "📈 Confusion Matrix"
    )


    fig, ax = plt.subplots()


    ax.imshow(
        cm
    )


    ax.set_title(
        "Confusion Matrix"
    )


    ax.set_xlabel(
        "Predicted Label"
    )


    ax.set_ylabel(
        "Actual Label"
    )


    ax.set_xticks(
        [0, 1]
    )


    ax.set_yticks(
        [0, 1]
    )


    ax.set_xticklabels(
        [
            "Safe",
            "Phishing",
        ]
    )


    ax.set_yticklabels(
        [
            "Safe",
            "Phishing",
        ]
    )


    for i in range(2):

        for j in range(2):

            ax.text(
                j,
                i,
                cm[i][j],
                ha="center",
                va="center",
            )


    st.pyplot(
        fig
    )


# ============================================================
# SECURITY DISCLAIMER
# ============================================================

st.divider()

st.info(
    """
    ⚠️ This application is a machine-learning
    demonstration and should not be treated as a
    definitive security verdict.

    Always verify suspicious emails manually and
    follow your organization's security procedures.
    """
)
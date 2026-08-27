import json
import os

import joblib
import matplotlib.pyplot as plt
import streamlit as st

from feature_engineering import (
    extract_features,
    augment_text,
    extract_urls,
)


# ============================================================
# CONFIGURATION
# ============================================================

MODEL_PATH = "model/phishing_model.joblib"
METRICS_PATH = "model/metrics.json"


st.set_page_config(
    page_title="Phishing Email Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# CUSTOM STYLING
# ============================================================

st.markdown(
    """
    <style>

    .main-title {
        font-size: 42px;
        font-weight: 800;
        margin-bottom: 5px;
    }

    .subtitle {
        font-size: 18px;
        opacity: 0.8;
        margin-bottom: 25px;
    }

    .risk-card {
        padding: 25px;
        border-radius: 15px;
        text-align: center;
        border: 1px solid rgba(128,128,128,0.25);
        margin: 10px 0;
    }

    .risk-score {
        font-size: 48px;
        font-weight: 800;
    }

    .risk-label {
        font-size: 22px;
        font-weight: 700;
    }

    .section-title {
        font-size: 25px;
        font-weight: 700;
        margin-top: 20px;
    }

    .indicator {
        padding: 10px;
        border-radius: 8px;
        margin: 5px 0;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# LOAD MODEL
# ============================================================

@st.cache_resource
def load_model():
    if not os.path.exists(MODEL_PATH):
        st.error(
            "Model file not found. "
            "Please make sure model/phishing_model.joblib exists."
        )
        st.stop()

    return joblib.load(MODEL_PATH)


@st.cache_data
def load_metrics():
    if not os.path.exists(METRICS_PATH):
        st.error(
            "Metrics file not found. "
            "Please make sure model/metrics.json exists."
        )
        st.stop()

    with open(
        METRICS_PATH,
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


model = load_model()
metrics = load_metrics()


# ============================================================
# RISK SCORE FUNCTION
# ============================================================

def calculate_risk_score(
    phishing_probability,
    features,
):
    """
    Calculates a 0-100 risk score.

    The score combines:
    - ML phishing probability
    - suspicious keywords
    - number of URLs
    - IP-based URLs
    - URL shorteners
    """

    score = phishing_probability * 70

    # Suspicious keywords
    keyword_count = features[
        "suspicious_keyword_count"
    ]

    score += min(keyword_count * 3, 15)

    # URLs
    url_count = features["url_count"]

    if url_count >= 1:
        score += min(url_count * 2, 6)

    # IP-based URL
    if features["has_ip_url"]:
        score += 6

    # URL shortener
    if features["has_shortener"]:
        score += 5

    score = min(round(score), 100)

    return score


def get_risk_level(score):

    if score >= 81:
        return "CRITICAL", "🚨"

    if score >= 61:
        return "HIGH", "🔴"

    if score >= 31:
        return "MEDIUM", "🟡"

    return "LOW", "🟢"


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">🛡️ Phishing Email Detection System</div>',
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="subtitle">
    AI-powered email security analysis using
    Machine Learning, NLP and URL-based indicators.
    </div>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.header("🛡️ About")

    st.write(
        """
        This application analyzes email content and
        predicts whether an email is likely to be
        **Safe** or **Phishing**.
        """
    )

    st.divider()

    st.subheader("🤖 Machine Learning")

    st.write("TF-IDF + Logistic Regression")

    st.subheader("🔎 Analysis")

    st.write(
        """
        • Email text  
        • Suspicious keywords  
        • URLs  
        • IP-based URLs  
        • URL shorteners  
        • ML probability
        """
    )

    st.divider()

    st.caption(
        "Phishing Email Detection Project"
    )


# ============================================================
# EMAIL INPUT
# ============================================================

st.markdown(
    '<div class="section-title">📧 Email Analysis</div>',
    unsafe_allow_html=True,
)

col1, col2 = st.columns(2)


with col1:

    sender = st.text_input(
        "Sender Email",
        placeholder="security@example.com",
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


analyze = st.button(
    "🔍 Analyze Email",
    type="primary",
    use_container_width=True,
)


# ============================================================
# ANALYSIS
# ============================================================

if analyze:

    if not email_body.strip():

        st.warning(
            "⚠️ Please enter the email content before analyzing."
        )

    else:

        # ----------------------------------------------------
        # Combine email information
        # ----------------------------------------------------

        combined_text = f"""
        Sender: {sender}
        Subject: {subject}
        Email Body: {email_body}
        """

        # ----------------------------------------------------
        # Feature Engineering
        # ----------------------------------------------------

        processed_text = augment_text(
            combined_text
        )

        features = extract_features(
            combined_text
        )

        # ----------------------------------------------------
        # ML Prediction
        # ----------------------------------------------------

        prediction = model.predict(
            [processed_text]
        )[0]

        probabilities = model.predict_proba(
            [processed_text]
        )[0]

        safe_probability = float(
            probabilities[0]
        )

        phishing_probability = float(
            probabilities[1]
        )

        # ----------------------------------------------------
        # Risk Score
        # ----------------------------------------------------

        risk_score = calculate_risk_score(
            phishing_probability,
            features,
        )

        risk_level, risk_icon = get_risk_level(
            risk_score
        )

        # ----------------------------------------------------
        # Result
        # ----------------------------------------------------

        st.divider()

        if prediction == 1:

            st.error(
                "🚨 PHISHING EMAIL DETECTED"
            )

            confidence = phishing_probability

        else:

            st.success(
                "✅ EMAIL APPEARS SAFE"
            )

            confidence = safe_probability

        # ----------------------------------------------------
        # Main Metrics
        # ----------------------------------------------------

        c1, c2, c3 = st.columns(3)

        with c1:

            st.metric(
                "Risk Score",
                f"{risk_score}/100",
            )

        with c2:

            st.metric(
                "ML Confidence",
                f"{confidence * 100:.2f}%",
            )

        with c3:

            st.metric(
                "Prediction",
                "Phishing"
                if prediction == 1
                else "Safe",
            )

        # ----------------------------------------------------
        # Risk Dashboard
        # ----------------------------------------------------

        st.markdown(
            f"""
            <div class="risk-card">

                <div class="risk-score">
                    {risk_score}/100
                </div>

                <div class="risk-label">
                    {risk_icon} {risk_level} RISK
                </div>

            </div>
            """,
            unsafe_allow_html=True,
        )

        st.progress(
            risk_score / 100
        )

        # ----------------------------------------------------
        # Probability Breakdown
        # ----------------------------------------------------

        st.subheader(
            "📊 Prediction Probability"
        )

        p1, p2 = st.columns(2)

        with p1:

            st.metric(
                "🟢 Safe Probability",
                f"{safe_probability * 100:.2f}%",
            )

        with p2:

            st.metric(
                "🔴 Phishing Probability",
                f"{phishing_probability * 100:.2f}%",
            )

        # ----------------------------------------------------
        # Email Feature Analysis
        # ----------------------------------------------------

        st.divider()

        st.subheader(
            "🔎 Email Feature Analysis"
        )

        c1, c2, c3, c4, c5 = st.columns(5)

        with c1:

            st.metric(
                "URLs Found",
                features["url_count"],
            )

        with c2:

            st.metric(
                "Suspicious Keywords",
                features[
                    "suspicious_keyword_count"
                ],
            )

        with c3:

            st.metric(
                "HTTPS",
                "Yes"
                if features["has_https"]
                else "No",
            )

        with c4:

            st.metric(
                "IP URL",
                "Yes"
                if features["has_ip_url"]
                else "No",
            )

        with c5:

            st.metric(
                "Shortener",
                "Yes"
                if features["has_shortener"]
                else "No",
            )

        # ----------------------------------------------------
        # Suspicious Keywords
        # ----------------------------------------------------

        st.subheader(
            "🚩 Suspicious Indicators"
        )

        suspicious_keywords = features[
            "suspicious_keywords"
        ]

        if suspicious_keywords:

            st.warning(
                f"{len(suspicious_keywords)} "
                "suspicious keyword(s) detected."
            )

            for keyword in suspicious_keywords:

                st.markdown(
                    f"- ⚠️ **{keyword}**"
                )

        else:

            st.success(
                "No suspicious keywords detected."
            )

        # ----------------------------------------------------
        # URL Analysis
        # ----------------------------------------------------

        st.subheader(
            "🔗 URL Security Analysis"
        )

        urls = extract_urls(
            combined_text
        )

        if urls:

            for index, url in enumerate(
                urls,
                start=1,
            ):

                st.write(
                    f"**URL {index}:** `{url}`"
                )

            if features["has_ip_url"]:

                st.warning(
                    "⚠️ One or more URLs use an IP address."
                )

            else:

                st.success(
                    "✓ No IP-based URL detected."
                )

            if features["has_shortener"]:

                st.warning(
                    "⚠️ A URL shortener was detected."
                )

            else:

                st.success(
                    "✓ No known URL shortener detected."
                )

            if features["has_https"]:

                st.info(
                    "🔐 At least one HTTPS URL was detected."
                )

            else:

                st.warning(
                    "⚠️ No HTTPS URL was detected."
                )

        else:

            st.info(
                "No URLs were detected in this email."
            )

        # ----------------------------------------------------
        # Security Recommendations
        # ----------------------------------------------------

        st.subheader(
            "🛡️ Security Recommendations"
        )

        recommendations = []

        if prediction == 1:

            recommendations.append(
                "Do not click links in this email."
            )

            recommendations.append(
                "Do not provide passwords, OTPs or banking information."
            )

            recommendations.append(
                "Verify the sender through an independent channel."
            )

        if features["has_ip_url"]:

            recommendations.append(
                "Avoid visiting IP-based URLs."
            )

        if features["has_shortener"]:

            recommendations.append(
                "Be cautious with shortened URLs because the final destination may be hidden."
            )

        if features[
            "suspicious_keyword_count"
        ] >= 3:

            recommendations.append(
                "The email contains multiple suspicious or urgency-related terms."
            )

        if not recommendations:

            recommendations.append(
                "No major automated warning indicators were detected."
            )

        for recommendation in recommendations:

            st.markdown(
                f"• {recommendation}"
            )

        # ----------------------------------------------------
        # Download Report
        # ----------------------------------------------------

        st.divider()

        st.subheader(
            "📄 Security Report"
        )

        report = f"""
PHISHING EMAIL SECURITY REPORT
========================================

Prediction:
{"PHISHING" if prediction == 1 else "SAFE"}

Risk Score:
{risk_score}/100

Risk Level:
{risk_level}

ML Confidence:
{confidence * 100:.2f}%

Safe Probability:
{safe_probability * 100:.2f}%

Phishing Probability:
{phishing_probability * 100:.2f}%


EMAIL INFORMATION
========================================

Sender:
{sender}

Subject:
{subject}


URL ANALYSIS
========================================

URLs Detected:
{features["url_count"]}

HTTPS Detected:
{"Yes" if features["has_https"] else "No"}

IP-Based URL:
{"Yes" if features["has_ip_url"] else "No"}

URL Shortener:
{"Yes" if features["has_shortener"] else "No"}


SUSPICIOUS KEYWORDS
========================================

{", ".join(suspicious_keywords) if suspicious_keywords else "None detected"}


DETECTED URLS
========================================

{"".join(f"{i}. {url}\n" for i, url in enumerate(urls, 1)) if urls else "None detected"}


MODEL
========================================

Algorithm:
TF-IDF + Logistic Regression

Test Accuracy:
{metrics["accuracy"] * 100:.2f}%


DISCLAIMER
========================================

This report is generated by an automated machine-learning
system and should not be considered a definitive security
verdict. Always verify suspicious emails manually.
"""

        st.download_button(
            label="📥 Download Security Report",
            data=report,
            file_name="phishing_email_security_report.txt",
            mime="text/plain",
            use_container_width=True,
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

classification_report_data = metrics.get(
    "classification_report",
    {},
)


precision = classification_report_data.get(
    "weighted avg",
    {},
).get(
    "precision",
    0,
)

recall = classification_report_data.get(
    "weighted avg",
    {},
).get(
    "recall",
    0,
)

f1_score = classification_report_data.get(
    "weighted avg",
    {},
).get(
    "f1-score",
    0,
)


m1, m2, m3, m4 = st.columns(4)


with m1:

    st.metric(
        "Accuracy",
        f"{accuracy * 100:.2f}%",
    )


with m2:

    st.metric(
        "Precision",
        f"{precision * 100:.2f}%",
    )


with m3:

    st.metric(
        "Recall",
        f"{recall * 100:.2f}%",
    )


with m4:

    st.metric(
        "F1 Score",
        f"{f1_score * 100:.2f}%",
    )


# ============================================================
# CONFUSION MATRIX
# ============================================================

st.subheader(
    "📈 Confusion Matrix"
)


cm = metrics.get(
    "confusion_matrix",
    [],
)


if len(cm) == 2:

    fig, ax = plt.subplots()

    ax.imshow(cm)

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
        ["Safe", "Phishing"]
    )

    ax.set_yticklabels(
        ["Safe", "Phishing"]
    )

    for i in range(2):

        for j in range(2):

            ax.text(
                j,
                i,
                cm[i][j],
                ha="center",
                va="center",
                fontsize=14,
            )

    st.pyplot(
        fig,
        use_container_width=True,
    )

else:

    st.warning(
        "Confusion matrix data is unavailable."
    )


# ============================================================
# FOOTER / DISCLAIMER
# ============================================================

st.divider()

st.info(
    """
    ⚠️ **Security Notice**

    This application provides an automated machine-learning
    risk assessment. It may produce false positives or false
    negatives and should not be treated as a definitive
    security verdict.

    Never click suspicious links or provide credentials based
    solely on this prediction.
    """
)


st.caption(
    "Phishing Email Detection System • "
    "TF-IDF + Logistic Regression • Scikit-learn"
)
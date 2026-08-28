import json
import joblib
import matplotlib.pyplot as plt
import streamlit as st

from feature_engineering import extract_features, augment_text
from email_header_analysis import analyze_headers


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

    return joblib.load(
        MODEL_PATH
    )


# ============================================================
# LOAD METRICS
# ============================================================

@st.cache_data
def load_metrics():

    with open(
        METRICS_PATH,
        "r",
        encoding="utf-8",
    ) as file:

        return json.load(file)


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
    ### Machine Learning based Email Security

    Analyze an email and determine whether it is
    likely to be **Phishing** or **Safe** using
    machine learning, URL security analysis and
    email header inspection.
    """
)


st.divider()


# ============================================================
# EMAIL INPUT
# ============================================================

st.header(
    "📧 Email Analysis"
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
# EMAIL HEADER INPUT
# ============================================================

st.subheader(
    "📨 Advanced Email Header Analysis"
)

st.caption(
    "Optional: Paste the raw email headers below "
    "to analyze From, Reply-To, Return-Path, SPF, "
    "DKIM and DMARC indicators."
)


raw_headers = st.text_area(
    "Raw Email Headers",
    height=180,
    placeholder=(
        "From: support@example.com\n"
        "Reply-To: support@example.com\n"
        "Return-Path: support@example.com\n"
        "Message-ID: <123@example.com>\n"
        "Authentication-Results: example.com; "
        "spf=pass; dkim=pass; dmarc=pass"
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
# EMAIL ANALYSIS
# ============================================================

if analyze:

    if not email_body.strip():

        st.warning(
            "Please enter the email content."
        )

    else:

        # ----------------------------------------------------
        # Combine email content
        # ----------------------------------------------------

        combined_text = f"""
        Sender: {sender}
        Subject: {subject}
        Email Body: {email_body}
        """


        # ----------------------------------------------------
        # Machine learning prediction
        # ----------------------------------------------------

        processed_text = augment_text(
            combined_text
        )


        prediction = model.predict(
            [processed_text]
        )[0]


        probabilities = model.predict_proba(
            [processed_text]
        )[0]


        phishing_probability = probabilities[1]

        safe_probability = probabilities[0]


        # ----------------------------------------------------
        # Feature extraction
        # ----------------------------------------------------

        features = extract_features(
            combined_text
        )


        st.divider()


        # ====================================================
        # ML RESULT
        # ====================================================

        st.header(
            "🤖 Machine Learning Result"
        )


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


        st.metric(
            "Model Confidence",
            f"{confidence * 100:.2f}%",
        )


        st.progress(
            float(confidence)
        )


        # ====================================================
        # EMAIL FEATURES
        # ====================================================

        st.subheader(
            "🔎 Email Feature Analysis"
        )


        c1, c2, c3, c4 = st.columns(4)


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


        # ====================================================
        # SUSPICIOUS KEYWORDS
        # ====================================================

        if features[
            "suspicious_keywords"
        ]:

            st.write(
                "**Suspicious keywords detected:**"
            )

            st.write(
                ", ".join(
                    features[
                        "suspicious_keywords"
                    ]
                )
            )


        # ====================================================
        # URL SECURITY
        # ====================================================

        st.subheader(
            "🔗 URL Security Analysis"
        )


        url_risk = features[
            "average_url_risk"
        ]


        st.metric(
            "Average URL Risk Score",
            f"{url_risk}/100",
        )


        url_results = features[
            "url_analysis"
        ]["results"]


        if url_results:

            for index, result in enumerate(
                url_results,
                start=1,
            ):

                with st.expander(
                    f"URL {index}: {result['url']}"
                ):

                    st.write(
                        f"**Domain:** "
                        f"{result['domain']}"
                    )

                    st.write(
                        f"**Risk Score:** "
                        f"{result['url_risk_score']}/100"
                    )

                    st.write(
                        f"**HTTPS:** "
                        f"{'Yes' if result['has_https'] else 'No'}"
                    )

                    st.write(
                        f"**IP Address:** "
                        f"{'Yes' if result['has_ip'] else 'No'}"
                    )

                    st.write(
                        f"**URL Shortener:** "
                        f"{'Yes' if result['is_shortener'] else 'No'}"
                    )

                    st.write(
                        f"**Suspicious TLD:** "
                        f"{'Yes' if result['suspicious_tld'] else 'No'}"
                    )

                    st.write(
                        f"**@ Symbol:** "
                        f"{'Yes' if result['has_at_symbol'] else 'No'}"
                    )

                    st.write(
                        f"**Subdomains:** "
                        f"{result['subdomain_count']}"
                    )

                    if result[
                        "indicators"
                    ]:

                        st.warning(
                            "⚠️ Security indicators: "
                            + ", ".join(
                                result[
                                    "indicators"
                                ]
                            )
                        )


        # ====================================================
        # URL SHORTENER WARNING
        # ====================================================

        if features[
            "has_shortener"
        ]:

            st.warning(
                "⚠️ A URL shortener was detected."
            )


        # ====================================================
        # EMAIL HEADER ANALYSIS
        # ====================================================

        st.divider()

        st.header(
            "📨 Email Header Security Analysis"
        )


        if raw_headers.strip():

            header_result = analyze_headers(
                raw_headers
            )


            if not header_result.get(
                "valid",
                False,
            ):

                st.warning(
                    "Unable to parse the supplied "
                    "email headers."
                )

            else:

                header_score = header_result[
                    "risk_score"
                ]


                # ------------------------------------------------
                # Header risk result
                # ------------------------------------------------

                if header_score >= 70:

                    st.error(
                        f"🚨 HIGH HEADER RISK — "
                        f"{header_score}/100"
                    )

                elif header_score >= 40:

                    st.warning(
                        f"⚠️ MEDIUM HEADER RISK — "
                        f"{header_score}/100"
                    )

                else:

                    st.success(
                        f"✅ LOW HEADER RISK — "
                        f"{header_score}/100"
                    )


                st.progress(
                    header_score / 100
                )


                # ------------------------------------------------
                # Header domains
                # ------------------------------------------------

                h1, h2, h3 = st.columns(3)


                with h1:

                    st.metric(
                        "From Domain",
                        header_result[
                            "from_domain"
                        ]
                        or "Unknown",
                    )


                with h2:

                    st.metric(
                        "Reply-To Domain",
                        header_result[
                            "reply_to_domain"
                        ]
                        or "Unknown",
                    )


                with h3:

                    st.metric(
                        "Return-Path Domain",
                        header_result[
                            "return_path_domain"
                        ]
                        or "Unknown",
                    )


                # ------------------------------------------------
                # Domain mismatches
                # ------------------------------------------------

                st.subheader(
                    "🔍 Domain Consistency"
                )


                if header_result[
                    "reply_to_mismatch"
                ]:

                    st.error(
                        "⚠️ From and Reply-To "
                        "domains do not match."
                    )

                else:

                    st.success(
                        "✅ From and Reply-To domains match."
                    )


                if header_result[
                    "return_path_mismatch"
                ]:

                    st.error(
                        "⚠️ From and Return-Path "
                        "domains do not match."
                    )

                else:

                    st.success(
                        "✅ From and Return-Path domains match."
                    )


                # ------------------------------------------------
                # Authentication
                # ------------------------------------------------

                st.subheader(
                    "🔐 Email Authentication"
                )


                authentication = header_result[
                    "authentication"
                ]


                a1, a2, a3 = st.columns(3)


                with a1:

                    if authentication[
                        "spf"
                    ] == "Pass":

                        st.success(
                            "SPF: PASS"
                        )

                    elif authentication[
                        "spf"
                    ] == "Not Provided":

                        st.info(
                            "SPF: NOT PROVIDED"
                        )

                    else:

                        st.error(
                            "SPF: FAILED"
                        )


                with a2:

                    if authentication[
                        "dkim"
                    ] == "Pass":

                        st.success(
                            "DKIM: PASS"
                        )

                    elif authentication[
                        "dkim"
                    ] == "Not Provided":

                        st.info(
                            "DKIM: NOT PROVIDED"
                        )

                    else:

                        st.error(
                            "DKIM: FAILED"
                        )


                with a3:

                    if authentication[
                        "dmarc"
                    ] == "Pass":

                        st.success(
                            "DMARC: PASS"
                        )

                    elif authentication[
                        "dmarc"
                    ] == "Not Provided":

                        st.info(
                            "DMARC: NOT PROVIDED"
                        )

                    else:

                        st.error(
                            "DMARC: FAILED"
                        )


                # ------------------------------------------------
                # Security indicators
                # ------------------------------------------------

                if header_result[
                    "indicators"
                ]:

                    st.subheader(
                        "⚠️ Header Security Indicators"
                    )

                    for indicator in header_result[
                        "indicators"
                    ]:

                        st.warning(
                            indicator
                        )

        else:

            st.info(
                "No email headers were provided. "
                "Header analysis was skipped."
            )


# ============================================================
# MODEL PERFORMANCE
# ============================================================

st.divider()

st.header(
    "📊 Model Performance"
)


accuracy = metrics[
    "accuracy"
]


st.metric(
    "Test Accuracy",
    f"{accuracy * 100:.2f}%",
)


cm = metrics[
    "confusion_matrix"
]


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
        )


st.pyplot(
    fig
)


# ============================================================
# DISCLAIMER
# ============================================================

st.divider()


st.info(
    """
    ⚠️ This application is a machine-learning
    demonstration and should not be treated as
    a definitive security verdict. Always verify
    suspicious emails manually.
    """
)
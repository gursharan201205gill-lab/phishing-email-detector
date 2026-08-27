import json
import os

import joblib
import matplotlib.pyplot as plt
import streamlit as st

from feature_engineering import extract_features, augment_text


MODEL_PATH = "model/phishing_model.joblib"
METRICS_PATH = "model/metrics.json"


st.set_page_config(
    page_title="Phishing Email Detector",
    page_icon="🛡️",
    layout="wide",
)


@st.cache_resource
def load_model():
    return joblib.load(MODEL_PATH)


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


st.title("🛡️ Phishing Email Detection System")

st.markdown(
    """
    ### Machine Learning based Email Security

    Analyze an email and determine whether it is
    likely to be **Phishing** or **Safe** using
    a Scikit-learn machine learning model.
    """
)


st.divider()


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


analyze = st.button(
    "🔍 Analyze Email",
    type="primary",
    use_container_width=True,
)


if analyze:

    if not email_body.strip():
        st.warning(
            "Please enter the email content."
        )

    else:

        combined_text = f"""
        Sender: {sender}
        Subject: {subject}
        Email Body: {email_body}
        """

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

        features = extract_features(
            combined_text
        )

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

        st.metric(
            "Model Confidence",
            f"{confidence * 100:.2f}%",
        )

        st.progress(
            float(confidence)
        )

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

        if features["suspicious_keywords"]:

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

        if features["has_shortener"]:

            st.warning(
                "A URL shortener was detected."
            )


st.divider()


st.header("📊 Model Performance")


accuracy = metrics["accuracy"]

st.metric(
    "Test Accuracy",
    f"{accuracy * 100:.2f}%",
)


cm = metrics["confusion_matrix"]


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

ax.set_xticks([0, 1])
ax.set_yticks([0, 1])

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


st.pyplot(fig)


st.divider()


st.info(
    """
    ⚠️ This application is a machine-learning
    demonstration and should not be treated as
    a definitive security verdict. Always verify
    suspicious emails manually.
    """
)
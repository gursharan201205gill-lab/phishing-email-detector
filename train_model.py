import json
import os

import joblib
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from download_dataset import download_dataset
from feature_engineering import augment_text


# ============================================================
# PATHS
# ============================================================

DATA_PATH = "data/Phishing_Email.csv"
MODEL_PATH = "model/phishing_model.joblib"
METRICS_PATH = "model/metrics.json"


# ============================================================
# LOAD DATASET
# ============================================================

def load_data():

    print("\n========================================")
    print("LOADING DATASET")
    print("========================================")

    if not os.path.exists(DATA_PATH):

        print("Dataset not found.")
        print("Downloading dataset...")

        download_dataset()

    if not os.path.exists(DATA_PATH):

        raise FileNotFoundError(
            f"Dataset could not be found at: {DATA_PATH}"
        )

    df = pd.read_csv(
        DATA_PATH
    )

    print(
        f"Dataset shape: {df.shape}"
    )

    required_columns = [
        "Email Text",
        "Email Type",
    ]

    for column in required_columns:

        if column not in df.columns:

            raise ValueError(
                f"Required column missing: {column}"
            )

    # Remove rows without email text/type
    df = df.dropna(
        subset=[
            "Email Text",
            "Email Type",
        ]
    ).copy()

    # Convert email type into binary label
    #
    # 0 = Safe
    # 1 = Phishing

    df["label"] = (
        df["Email Type"]
        .astype(str)
        .str.lower()
        .str.contains(
            "phishing"
        )
        .astype(int)
    )

    print("\nClass distribution:")

    print(
        df["label"].value_counts()
    )

    # --------------------------------------------------------
    # Advanced feature engineering
    # --------------------------------------------------------

    print(
        "\nApplying advanced feature engineering..."
    )

    df["processed_text"] = (
        df["Email Text"]
        .astype(str)
        .apply(augment_text)
    )

    print(
        "Feature engineering completed."
    )

    return df


# ============================================================
# BUILD MODEL
# ============================================================

def build_pipeline():

    pipeline = Pipeline(
        [
            (
                "tfidf",

                TfidfVectorizer(
                    lowercase=True,
                    strip_accents="unicode",

                    # Unigrams + bigrams
                    ngram_range=(1, 2),

                    # Ignore extremely rare terms
                    min_df=2,

                    # Limit vocabulary size
                    max_features=50000,

                    # Improve TF-IDF scaling
                    sublinear_tf=True,
                ),
            ),

            (
                "classifier",

                LogisticRegression(
                    max_iter=1000,

                    # Helps when classes are imbalanced
                    class_weight="balanced",

                    random_state=42,
                ),
            ),
        ]
    )

    return pipeline


# ============================================================
# TRAIN MODEL
# ============================================================

def train():

    print("\n========================================")
    print("PHISHING EMAIL MODEL TRAINING")
    print("========================================")

    # Create model directory
    os.makedirs(
        "model",
        exist_ok=True,
    )

    # Load dataset
    df = load_data()

    # Input and target
    X = df["processed_text"]
    y = df["label"]

    print("\nTotal samples:")
    print(len(df))

    # --------------------------------------------------------
    # Train/Test Split
    # --------------------------------------------------------

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,

        test_size=0.20,

        random_state=42,

        # Preserve class distribution
        stratify=y,
    )

    print("\nDataset split:")

    print(
        f"Training samples: {len(X_train)}"
    )

    print(
        f"Testing samples: {len(X_test)}"
    )

    # --------------------------------------------------------
    # Build pipeline
    # --------------------------------------------------------

    pipeline = build_pipeline()

    # --------------------------------------------------------
    # Train
    # --------------------------------------------------------

    print("\n========================================")
    print("TRAINING MODEL")
    print("========================================")

    pipeline.fit(
        X_train,
        y_train,
    )

    print(
        "Training completed successfully."
    )

    # --------------------------------------------------------
    # Predictions
    # --------------------------------------------------------

    print(
        "\nEvaluating model..."
    )

    predictions = pipeline.predict(
        X_test
    )

    # --------------------------------------------------------
    # Accuracy
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        predictions,
    )

    # --------------------------------------------------------
    # Confusion Matrix
    # --------------------------------------------------------

    cm = confusion_matrix(
        y_test,
        predictions,
    )

    # --------------------------------------------------------
    # Classification Report
    # --------------------------------------------------------

    report = classification_report(
        y_test,
        predictions,
        output_dict=True,
    )

    # ========================================================
    # DISPLAY RESULTS
    # ========================================================

    print("\n========================================")
    print("MODEL RESULTS")
    print("========================================")

    print(
        f"\nAccuracy: {accuracy:.4f}"
    )

    print(
        f"Accuracy Percentage: "
        f"{accuracy * 100:.2f}%"
    )

    print(
        "\nConfusion Matrix:"
    )

    print(cm)

    print(
        "\nClassification Report:"
    )

    print(
        classification_report(
            y_test,
            predictions,
        )
    )

    # ========================================================
    # SAVE MODEL
    # ========================================================

    print(
        "\nSaving trained model..."
    )

    joblib.dump(
        pipeline,
        MODEL_PATH,
    )

    print(
        f"Model saved successfully:"
    )

    print(
        MODEL_PATH
    )

    # ========================================================
    # SAVE METRICS
    # ========================================================

    metrics = {
        "accuracy": float(
            accuracy
        ),

        "confusion_matrix":
            cm.tolist(),

        "classification_report":
            report,

        "training_samples":
            int(len(X_train)),

        "testing_samples":
            int(len(X_test)),

        "model":
            "TF-IDF + Logistic Regression",

        "feature_engineering":
            "Advanced text + URL security features",
    }

    with open(
        METRICS_PATH,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            metrics,
            file,
            indent=4,
        )

    print(
        "\nMetrics saved successfully:"
    )

    print(
        METRICS_PATH
    )

    # ========================================================
    # FINAL MESSAGE
    # ========================================================

    print("\n========================================")
    print("TRAINING COMPLETE")
    print("========================================")

    print(
        "\nNew model:"
    )

    print(
        MODEL_PATH
    )

    print(
        "\nNew metrics:"
    )

    print(
        METRICS_PATH
    )

    print(
        "\nYou can now run the Streamlit application."
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    train()
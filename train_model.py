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


DATA_PATH = "data/Phishing_Email.csv"
MODEL_PATH = "model/phishing_model.joblib"
METRICS_PATH = "model/metrics.json"


def load_data():
    print("Loading dataset...")

    df = pd.read_csv(DATA_PATH)

    print(f"Dataset shape: {df.shape}")
    print(df.head())

    required_columns = ["Email Text", "Email Type"]

    for column in required_columns:
        if column not in df.columns:
            raise ValueError(
                f"Required column missing: {column}"
            )

    df = df.dropna(
        subset=["Email Text", "Email Type"]
    )

    df["label"] = (
        df["Email Type"]
        .astype(str)
        .str.lower()
        .str.contains("phishing")
        .astype(int)
    )

    df["processed_text"] = df["Email Text"].apply(
        augment_text
    )

    return df


def train():
    os.makedirs("model", exist_ok=True)

    download_dataset()

    df = load_data()

    X = df["processed_text"]
    y = df["label"]

    print("\nClass distribution:")
    print(y.value_counts())

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    pipeline = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    strip_accents="unicode",
                    ngram_range=(1, 2),
                    min_df=2,
                    max_features=50000,
                    sublinear_tf=True,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=1000,
                    class_weight="balanced",
                    random_state=42,
                ),
            ),
        ]
    )

    print("\nTraining model...")

    pipeline.fit(X_train, y_train)

    print("Training completed.")

    predictions = pipeline.predict(X_test)

    accuracy = accuracy_score(
        y_test,
        predictions,
    )

    cm = confusion_matrix(
        y_test,
        predictions,
    )

    report = classification_report(
        y_test,
        predictions,
        output_dict=True,
    )

    print("\n==============================")
    print("MODEL RESULTS")
    print("==============================")

    print(f"Accuracy: {accuracy:.4f}")

    print("\nConfusion Matrix:")
    print(cm)

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            predictions,
        )
    )

    joblib.dump(
        pipeline,
        MODEL_PATH,
    )

    metrics = {
        "accuracy": float(accuracy),
        "confusion_matrix": cm.tolist(),
        "classification_report": report,
        "training_samples": int(len(X_train)),
        "testing_samples": int(len(X_test)),
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

    print("\nModel saved:")
    print(MODEL_PATH)

    print("\nMetrics saved:")
    print(METRICS_PATH)


if __name__ == "__main__":
    train()
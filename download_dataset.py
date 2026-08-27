import os
import requests

DATA_DIR = "data"
DATA_PATH = os.path.join(DATA_DIR, "Phishing_Email.csv")

URL = (
    "https://huggingface.co/datasets/"
    "zefang-liu/phishing-email-dataset/"
    "resolve/main/Phishing_Email.csv?download=true"
)


def download_dataset():
    os.makedirs(DATA_DIR, exist_ok=True)

    if os.path.exists(DATA_PATH):
        print("Dataset already exists.")
        return

    print("Downloading dataset...")

    response = requests.get(URL, stream=True, timeout=60)
    response.raise_for_status()

    with open(DATA_PATH, "wb") as file:
        for chunk in response.iter_content(chunk_size=1024 * 1024):
            if chunk:
                file.write(chunk)

    print("Dataset downloaded successfully.")
    print(f"Saved to: {DATA_PATH}")


if __name__ == "__main__":
    download_dataset()
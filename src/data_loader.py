import os
import pandas as pd
from typing import Tuple
from src.feature_extraction import extract_features

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DATA_PATH = os.path.join(BASE_DIR, "data", "raw", "urls_dataset.csv")
PROCESSED_DATA_PATH = os.path.join(BASE_DIR, "data", "processed", "features_dataset.csv")


def load_raw_dataset(filepath: str = RAW_DATA_PATH) -> pd.DataFrame:
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Raw dataset file not found at: {filepath}")

    df = pd.read_csv(filepath)
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("Dataset must contain 'url' and 'label' columns.")

    df = df.dropna(subset=["url", "label"]).copy()
    df["label"] = df["label"].astype(int)
    df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)
    return df


def prepare_features_dataset(
    raw_path: str = RAW_DATA_PATH,
    processed_path: str = PROCESSED_DATA_PATH,
    force_recompute: bool = False
) -> pd.DataFrame:
    if os.path.exists(processed_path) and not force_recompute:
        print(f"[*] Loading cached features from {processed_path}")
        return pd.read_csv(processed_path)

    print(f"[*] Extracting features from {raw_path}...")
    df_raw = load_raw_dataset(raw_path)

    features_list = []
    labels = []
    urls = []

    total = len(df_raw)
    for idx, row in df_raw.iterrows():
        u = str(row["url"])
        lbl = int(row["label"])
        feats = extract_features(u)
        features_list.append(feats)
        labels.append(lbl)
        urls.append(u)

        if (idx + 1) % 2500 == 0 or (idx + 1) == total:
            print(f"    Processed {idx + 1}/{total} URLs...")

    df_feats = pd.DataFrame(features_list)
    df_feats["label"] = labels
    df_feats.insert(0, "url", urls)

    os.makedirs(os.path.dirname(processed_path), exist_ok=True)
    df_feats.to_csv(processed_path, index=False)
    print(f"[+] Feature matrix saved to {processed_path} (Shape: {df_feats.shape})")
    return df_feats


if __name__ == "__main__":
    df = prepare_features_dataset()
    print("Feature dataset sample shape:", df.shape)

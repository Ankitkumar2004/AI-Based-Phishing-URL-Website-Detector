import os
import joblib
import pandas as pd
import numpy as np
from typing import Tuple, List
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.joblib")
FEATURE_COLUMNS_PATH = os.path.join(MODELS_DIR, "feature_columns.joblib")


def split_data(
    df: pd.DataFrame,
    test_size: float = 0.2,
    random_state: int = 42
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, List[str]]:
    feature_cols = [c for c in df.columns if c not in ("url", "label")]
    X = df[feature_cols].copy()
    y = df["label"].copy()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    return X_train, X_test, y_train, y_test, feature_cols


def fit_scaler(X_train: pd.DataFrame) -> StandardScaler:
    scaler = StandardScaler()
    scaler.fit(X_train)
    return scaler


def transform_data(scaler: StandardScaler, X: pd.DataFrame) -> np.ndarray:
    return scaler.transform(X)


def save_preprocessing_artifacts(
    scaler: StandardScaler,
    feature_cols: List[str],
    models_dir: str = MODELS_DIR
) -> None:
    """Serializes scaler and feature column order to disk."""
    os.makedirs(models_dir, exist_ok=True)
    scaler_file = os.path.join(models_dir, "scaler.joblib")
    features_file = os.path.join(models_dir, "feature_columns.joblib")

    joblib.dump(scaler, scaler_file)
    joblib.dump(feature_cols, features_file)
    print(f"[+] Scaler saved to {scaler_file}")
    print(f"[+] Feature columns ({len(feature_cols)} features) saved to {features_file}")


def load_preprocessing_artifacts(
    models_dir: str = MODELS_DIR
) -> Tuple[StandardScaler, List[str]]:
    """Loads saved scaler and feature columns."""
    scaler_file = os.path.join(models_dir, "scaler.joblib")
    features_file = os.path.join(models_dir, "feature_columns.joblib")

    if not os.path.exists(scaler_file) or not os.path.exists(features_file):
        raise FileNotFoundError(
            f"Preprocessing artifacts not found in {models_dir}. Please train model first."
        )

    scaler = joblib.load(scaler_file)
    feature_cols = joblib.load(features_file)
    return scaler, feature_cols

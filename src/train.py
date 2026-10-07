import os
import joblib
from datetime import datetime
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier

from src.data_loader import prepare_features_dataset
from src.preprocessing import (
    split_data,
    fit_scaler,
    transform_data,
    save_preprocessing_artifacts
)
from src.evaluate import evaluate_classifier, save_metadata

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")
MODEL_PATH = os.path.join(MODELS_DIR, "phishing_model.joblib")


def train_models():
    print("[*] Starting model training pipeline...")

    df = prepare_features_dataset()
    print(f"[*] Dataset: {len(df)} samples (Legitimate: {len(df[df['label'] == 0])}, Phishing: {len(df[df['label'] == 1])})")

    X_train, X_test, y_train, y_test, feature_cols = split_data(
        df, test_size=0.2, random_state=42
    )
    print(f"[*] Train set: {len(X_train)} | Test set: {len(X_test)} | Features: {len(feature_cols)}")

    scaler = fit_scaler(X_train)
    X_train_scaled = transform_data(scaler, X_train)
    X_test_scaled = transform_data(scaler, X_test)

    print("\n[+] Training Logistic Regression baseline...")
    lr = LogisticRegression(max_iter=1000, random_state=42)
    lr.fit(X_train_scaled, y_train)
    lr_metrics = evaluate_classifier(lr, X_test_scaled, y_test, model_name="LogisticRegression")
    print(f"    LR Accuracy: {lr_metrics['accuracy'] * 100:.2f}% | F1: {lr_metrics['f1_score']:.4f}")

    print("\n[+] Training Random Forest...")
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_train_scaled, y_train)
    rf_metrics = evaluate_classifier(
        rf, X_test_scaled, y_test,
        model_name="RandomForestClassifier",
        feature_names=feature_cols
    )
    print(f"    RF Accuracy: {rf_metrics['accuracy'] * 100:.2f}% | F1: {rf_metrics['f1_score']:.4f}")
    print(f"    Recall: {rf_metrics['phishing_metrics']['recall'] * 100:.2f}% | Precision: {rf_metrics['phishing_metrics']['precision'] * 100:.2f}%")

    best_model = rf
    best_metrics = rf_metrics
    selected_name = "RandomForestClassifier"

    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(best_model, MODEL_PATH)
    print(f"\n[+] Saved model to {MODEL_PATH}")
    save_preprocessing_artifacts(scaler, feature_cols, MODELS_DIR)

    metadata = {
        "model": selected_name,
        "trained_at": datetime.now().isoformat(),
        "random_seed": 42,
        "dataset_split": "80% Train, 20% Test (Stratified)",
        "training_samples": len(X_train),
        "test_samples": len(X_test),
        "total_samples": len(df),
        "total_features": len(feature_cols),
        "feature_columns": feature_cols,
        "accuracy": best_metrics["accuracy"],
        "precision": best_metrics["precision"],
        "recall": best_metrics["recall"],
        "f1_score": best_metrics["f1_score"],
        "roc_auc": best_metrics["roc_auc"],
        "phishing_metrics": best_metrics["phishing_metrics"],
        "legitimate_metrics": best_metrics["legitimate_metrics"],
        "confusion_matrix": best_metrics["confusion_matrix"],
        "top_features": best_metrics["top_features"],
        "baseline_comparison": {
            "model": "LogisticRegression",
            "accuracy": lr_metrics["accuracy"],
            "precision": lr_metrics["precision"],
            "recall": lr_metrics["recall"],
            "f1_score": lr_metrics["f1_score"],
            "roc_auc": lr_metrics["roc_auc"],
            "confusion_matrix": lr_metrics["confusion_matrix"]
        }
    }

    save_metadata(metadata)
    print("[+] Training completed successfully")
    return metadata


if __name__ == "__main__":
    train_models()

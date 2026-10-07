import os
import sys
import json
import joblib

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.data_loader import prepare_features_dataset
from src.preprocessing import split_data, load_preprocessing_artifacts, transform_data
from src.evaluate import evaluate_classifier

METADATA_PATH = os.path.join(BASE_DIR, "models", "model_metadata.json")
MODEL_PATH = os.path.join(BASE_DIR, "models", "phishing_model.joblib")


def main():
    print("--- Model Evaluation Report ---")

    if not os.path.exists(MODEL_PATH):
        print(f"[-] Model not found at {MODEL_PATH}. Train the model first.")
        sys.exit(1)

    model = joblib.load(MODEL_PATH)
    scaler, feature_cols = load_preprocessing_artifacts()

    df = prepare_features_dataset()
    _, X_test, _, y_test, _ = split_data(df, test_size=0.2, random_state=42)
    X_test_scaled = transform_data(scaler, X_test)

    results = evaluate_classifier(model, X_test_scaled, y_test, model_name="RandomForestClassifier", feature_names=feature_cols)

    print(f"\nModel: {results['model']}")
    print(f"Overall Accuracy:  {results['accuracy'] * 100:.2f}%")
    print(f"Overall Precision: {results['precision'] * 100:.2f}%")
    print(f"Overall Recall:    {results['recall'] * 100:.2f}%")
    print(f"Overall F1-Score:  {results['f1_score']:.4f}")
    print(f"ROC-AUC Score:     {results['roc_auc']:.4f}")

    print("\n--- Phishing Class (Positive = 1) Metrics ---")
    print(f"Precision: {results['phishing_metrics']['precision'] * 100:.2f}%")
    print(f"Recall:    {results['phishing_metrics']['recall'] * 100:.2f}%")
    print(f"F1-Score:  {results['phishing_metrics']['f1_score']:.4f}")

    print("\n--- Confusion Matrix ---")
    cm = results["confusion_matrix"]
    print(f"True Negatives  (Legitimate as Legit):    {cm['true_negatives']}")
    print(f"False Positives (Legitimate as Phishing): {cm['false_positives']}")
    print(f"False Negatives (Phishing as Legit):      {cm['false_negatives']}")
    print(f"True Positives  (Phishing as Phishing):   {cm['true_positives']}")

    print("\n--- Top 10 Most Influential Features ---")
    for idx, item in enumerate(results.get("top_features", [])[:10], 1):
        print(f"  {idx:2d}. {item['feature']:<28} : {item['importance']:.4f}")

    if os.path.exists(METADATA_PATH):
        with open(METADATA_PATH, "r") as f:
            meta = json.load(f)
        if "baseline_comparison" in meta:
            base = meta["baseline_comparison"]
            print("\n--- Baseline vs Primary Comparison ---")
            print(f"Baseline ({base['model']}) Accuracy: {base['accuracy']*100:.2f}% | F1: {base['f1_score']:.4f}")
            print(f"Primary ({results['model']}) Accuracy: {results['accuracy']*100:.2f}% | F1: {results['f1_score']:.4f}")
    print("=" * 60)


if __name__ == "__main__":
    main()

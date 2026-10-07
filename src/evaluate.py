import os
import json
import numpy as np
from typing import Dict, Any, List
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")
METADATA_PATH = os.path.join(MODELS_DIR, "model_metadata.json")


def evaluate_classifier(
    model,
    X_test,
    y_test,
    model_name: str = "RandomForestClassifier",
    feature_names: List[str] = None
) -> Dict[str, Any]:
    y_pred = model.predict(X_test)
    
    # Probability estimates for ROC-AUC
    if hasattr(model, "predict_proba"):
        y_prob = model.predict_proba(X_test)[:, 1]
        auc_score = float(roc_auc_score(y_test, y_prob))
    else:
        auc_score = 0.0

    acc = float(accuracy_score(y_test, y_pred))
    prec_macro = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
    rec_macro = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
    f1_macro = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))

    # Class 1 (Phishing) specific
    phish_prec = float(precision_score(y_test, y_pred, pos_label=1, zero_division=0))
    phish_rec = float(recall_score(y_test, y_pred, pos_label=1, zero_division=0))
    phish_f1 = float(f1_score(y_test, y_pred, pos_label=1, zero_division=0))

    # Class 0 (Legitimate) specific
    legit_prec = float(precision_score(y_test, y_pred, pos_label=0, zero_division=0))
    legit_rec = float(recall_score(y_test, y_pred, pos_label=0, zero_division=0))
    legit_f1 = float(f1_score(y_test, y_pred, pos_label=0, zero_division=0))

    cm = confusion_matrix(y_test, y_pred).tolist()
    tn, fp, fn, tp = int(cm[0][0]), int(cm[0][1]), int(cm[1][0]), int(cm[1][1])

    # Top feature importances if tree-based model
    top_features = []
    if hasattr(model, "feature_importances_") and feature_names:
        importances = model.feature_importances_
        sorted_indices = np.argsort(importances)[::-1]
        for idx in sorted_indices[:15]:
            top_features.append({
                "feature": feature_names[idx],
                "importance": round(float(importances[idx]), 4)
            })

    results = {
        "model": model_name,
        "accuracy": round(acc, 4),
        "precision": round(prec_macro, 4),
        "recall": round(rec_macro, 4),
        "f1_score": round(f1_macro, 4),
        "roc_auc": round(auc_score, 4),
        "phishing_metrics": {
            "precision": round(phish_prec, 4),
            "recall": round(phish_rec, 4),
            "f1_score": round(phish_f1, 4)
        },
        "legitimate_metrics": {
            "precision": round(legit_prec, 4),
            "recall": round(legit_rec, 4),
            "f1_score": round(legit_f1, 4)
        },
        "confusion_matrix": {
            "matrix": cm,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp
        },
        "top_features": top_features
    }

    return results


def save_metadata(metadata: Dict[str, Any], filepath: str = METADATA_PATH) -> None:
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"[+] Saved metadata to {filepath}")

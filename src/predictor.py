import os
import time
import joblib
import pandas as pd
import numpy as np
from datetime import datetime
from typing import Dict, Any, List

from src.feature_extraction import extract_features, extract_security_indicators, sanitize_url

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")
MODEL_PATH = os.path.join(MODELS_DIR, "phishing_model.joblib")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.joblib")
FEATURE_COLUMNS_PATH = os.path.join(MODELS_DIR, "feature_columns.joblib")


class PhishingPredictor:
    _instance = None

    def __init__(self, models_dir: str = MODELS_DIR):
        self.models_dir = models_dir
        self.model = None
        self.scaler = None
        self.feature_columns = None
        self.is_loaded = False
        self.load_artifacts()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def load_artifacts(self):
        model_file = os.path.join(self.models_dir, "phishing_model.joblib")
        scaler_file = os.path.join(self.models_dir, "scaler.joblib")
        cols_file = os.path.join(self.models_dir, "feature_columns.joblib")

        if os.path.exists(model_file) and os.path.exists(scaler_file) and os.path.exists(cols_file):
            try:
                self.model = joblib.load(model_file)
                self.scaler = joblib.load(scaler_file)
                self.feature_columns = joblib.load(cols_file)
                self.is_loaded = True
                print("[+] Loaded model and preprocessor artifacts")
            except Exception as e:
                print(f"[-] Error loading model artifacts: {e}")
                self.is_loaded = False
        else:
            self.is_loaded = False
            print(f"[-] Model artifacts not found in {self.models_dir}")

    def compute_risk_score(self, phish_prob: float, features: Dict[str, Any]) -> int:
        base_score = phish_prob * 80.0
        heuristic_bonus = 0.0

        if features.get("has_ip_address", 0) == 1:
            heuristic_bonus += 15.0
        if features.get("is_shortened_url", 0) == 1:
            heuristic_bonus += 10.0
        if features.get("has_punycode", 0) == 1:
            heuristic_bonus += 10.0
        if features.get("number_of_at_symbols", 0) > 0:
            heuristic_bonus += 10.0
        if features.get("suspicious_port", 0) == 1:
            heuristic_bonus += 10.0
        if features.get("unusual_tld", 0) == 1:
            heuristic_bonus += 8.0

        if features.get("has_https", 0) == 1 and features.get("has_ip_address", 0) == 0:
            heuristic_bonus -= 5.0

        total_risk = base_score + heuristic_bonus
        return int(max(0, min(100, round(total_risk))))

    def predict(self, raw_url: str) -> Dict[str, Any]:
        start_time = time.perf_counter()

        if not self.is_loaded:
            self.load_artifacts()
            if not self.is_loaded:
                raise RuntimeError("ML model has not been trained or loaded yet. Run training pipeline first.")

        features = extract_features(raw_url)
        indicators = extract_security_indicators(raw_url, features)

        feature_vector = [features.get(col, 0) for col in self.feature_columns]
        X_df = pd.DataFrame([feature_vector], columns=self.feature_columns)
        X_scaled = self.scaler.transform(X_df)

        prob_array = self.model.predict_proba(X_scaled)[0]
        phish_prob = float(prob_array[1])
        legit_prob = float(prob_array[0])

        risk_score = self.compute_risk_score(phish_prob, features)

        if risk_score <= 30:
            prediction_label = "Legitimate"
            threat_level = "LOW"
            confidence = round(legit_prob * 100, 2)
        elif risk_score <= 70:
            prediction_label = "Suspicious"
            threat_level = "MEDIUM"
            confidence = round(max(phish_prob, legit_prob) * 100, 2)
        else:
            prediction_label = "Phishing"
            threat_level = "HIGH"
            confidence = round(phish_prob * 100, 2)

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return {
            "url": raw_url,
            "prediction": prediction_label,
            "risk_score": risk_score,
            "confidence": confidence,
            "threat_level": threat_level,
            "phishing_probability": round(phish_prob, 4),
            "indicators": indicators,
            "detection_time_ms": elapsed_ms,
            "features_summary": {
                "length": features["url_length"],
                "dots": features["number_of_dots"],
                "has_https": bool(features["has_https"]),
                "has_ip": bool(features["has_ip_address"]),
                "subdomains": features["subdomain_count"],
                "entropy": features["hostname_entropy"],
                "suspicious_keywords": features["total_suspicious_keywords"],
                "is_shortened": bool(features["is_shortened_url"])
            },
            "timestamp": datetime.now().isoformat()
        }


def predict_url(raw_url: str) -> Dict[str, Any]:
    predictor = PhishingPredictor.get_instance()
    return predictor.predict(raw_url)


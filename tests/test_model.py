import os
import pytest
from src.predictor import PhishingPredictor, predict_url

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_model_artifacts_exist():
    models_dir = os.path.join(BASE_DIR, "models")
    assert os.path.exists(os.path.join(models_dir, "phishing_model.joblib"))
    assert os.path.exists(os.path.join(models_dir, "scaler.joblib"))
    assert os.path.exists(os.path.join(models_dir, "feature_columns.joblib"))
    assert os.path.exists(os.path.join(models_dir, "model_metadata.json"))


def test_predictor_singleton_loaded():
    predictor = PhishingPredictor.get_instance()
    assert predictor.is_loaded is True
    assert predictor.model is not None
    assert predictor.scaler is not None
    assert len(predictor.feature_columns) > 0


def test_prediction_output_structure():
    result = predict_url("https://www.google.com")
    assert "url" in result
    assert "prediction" in result
    assert result["prediction"] in ("Legitimate", "Suspicious", "Phishing")
    assert "risk_score" in result
    assert 0 <= result["risk_score"] <= 100
    assert "confidence" in result
    assert 0 <= result["confidence"] <= 100
    assert "threat_level" in result
    assert result["threat_level"] in ("LOW", "MEDIUM", "HIGH")
    assert "detection_time_ms" in result
    assert result["detection_time_ms"] >= 0
    assert "indicators" in result
    assert isinstance(result["indicators"], list)
    assert "features_summary" in result


def test_high_risk_phishing_url_prediction():
    # URL exhibiting multiple prominent attack vectors: raw IP, suspicious keywords, non-standard port
    phish_url = "http://192.168.1.100:8080/paypal-security/login-verify.php?token=93821"
    result = predict_url(phish_url)

    assert result["prediction"] == "Phishing"
    assert result["threat_level"] == "HIGH"
    assert result["risk_score"] >= 70


def test_legitimate_url_prediction():
    legit_url = "https://www.wikipedia.org/wiki/Main_Page"
    result = predict_url(legit_url)

    assert result["prediction"] == "Legitimate"
    assert result["threat_level"] == "LOW"
    assert result["risk_score"] <= 30

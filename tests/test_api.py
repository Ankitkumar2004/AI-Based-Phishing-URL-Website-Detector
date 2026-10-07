import io
import json
import pytest
from app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_api_health(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "healthy"
    assert data["model_loaded"] is True
    assert data["database_connected"] is True


def test_api_predict_valid(client):
    payload = {"url": "https://www.wikipedia.org"}
    res = client.post("/api/predict", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["url"] == "https://www.wikipedia.org"
    assert "prediction" in data
    assert "risk_score" in data
    assert "confidence" in data
    assert "indicators" in data


def test_api_predict_missing_url(client):
    payload = {"wrong_key": "https://example.com"}
    res = client.post("/api/predict", json=payload)
    assert res.status_code == 400
    data = res.get_json()
    assert "error" in data


def test_api_predict_empty_url(client):
    payload = {"url": "   "}
    res = client.post("/api/predict", json=payload)
    assert res.status_code == 400
    data = res.get_json()
    assert "error" in data


def test_api_predict_non_json(client):
    res = client.post("/api/predict", data="plain text data")
    assert res.status_code == 400
    data = res.get_json()
    assert "error" in data


def test_api_predict_oversized_url(client):
    huge_url = "https://example.com/" + "x" * 2500
    res = client.post("/api/predict", json={"url": huge_url})
    assert res.status_code == 400
    data = res.get_json()
    assert "exceeds maximum allowed length" in data["message"]


def test_api_batch_predict_valid_csv(client):
    csv_content = b"url\nhttps://google.com\nhttp://192.168.1.1/login.php\nhttps://github.com\n"
    data = {
        "file": (io.BytesIO(csv_content), "test_urls.csv")
    }
    res = client.post("/api/batch-predict", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    res_data = res.get_json()
    assert res_data["total_processed"] == 3
    assert len(res_data["results"]) == 3
    assert "phishing_count" in res_data


def test_api_batch_predict_format_csv_download(client):
    csv_content = b"url\nhttps://google.com\n"
    data = {
        "file": (io.BytesIO(csv_content), "test_urls.csv")
    }
    res = client.post("/api/batch-predict?format=csv", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    assert "text/csv" in res.headers["Content-Type"]
    assert "attachment" in res.headers["Content-Disposition"]
    assert b"url,prediction,risk_score" in res.data


def test_api_batch_predict_invalid_extension(client):
    data = {
        "file": (io.BytesIO(b"malicious content"), "test.exe")
    }
    res = client.post("/api/batch-predict", data=data, content_type="multipart/form-data")
    assert res.status_code == 400


def test_api_history(client):
    res = client.get("/api/history?limit=10")
    assert res.status_code == 200
    data = res.get_json()
    assert "history" in data
    assert "count" in data


def test_api_statistics(client):
    res = client.get("/api/statistics")
    assert res.status_code == 200
    data = res.get_json()
    assert "total_scans" in data
    assert "phishing_count" in data
    assert "legitimate_count" in data


def test_api_model_info(client):
    res = client.get("/api/model-info")
    assert res.status_code == 200
    data = res.get_json()
    assert "accuracy" in data
    assert "f1_score" in data
    assert "confusion_matrix" in data
    assert "top_features" in data

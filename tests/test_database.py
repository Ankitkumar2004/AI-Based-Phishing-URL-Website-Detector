import os
import tempfile
import pytest
from database.database import (
    init_db,
    save_scan,
    get_history,
    get_statistics,
    clear_history
)


@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    yield path
    try:
        if os.path.exists(path):
            os.remove(path)
    except PermissionError:
        pass


def test_save_and_retrieve_scan(temp_db):
    row_id = save_scan(
        url="https://secure-bank-portal.com",
        prediction="Phishing",
        risk_score=85,
        confidence=95.5,
        threat_level="HIGH",
        detection_time_ms=1.2,
        db_path=temp_db
    )
    assert row_id is not None
    assert row_id > 0

    history = get_history(limit=10, db_path=temp_db)
    assert len(history) == 1
    record = history[0]
    assert record["url"] == "https://secure-bank-portal.com"
    assert record["prediction"] == "Phishing"
    assert record["risk_score"] == 85
    assert record["confidence"] == 95.5
    assert record["threat_level"] == "HIGH"


def test_database_filtering_and_search(temp_db):
    save_scan("https://alpha-legit.org", "Legitimate", 10, 99.0, db_path=temp_db)
    save_scan("https://beta-phish.xyz", "Phishing", 90, 98.0, db_path=temp_db)
    save_scan("https://gamma-suspicious.net", "Suspicious", 50, 75.0, db_path=temp_db)

    # Search filter
    search_res = get_history(search="beta", db_path=temp_db)
    assert len(search_res) == 1
    assert "beta-phish.xyz" in search_res[0]["url"]

    # Prediction filter
    phish_res = get_history(prediction_filter="Phishing", db_path=temp_db)
    assert len(phish_res) == 1
    assert phish_res[0]["prediction"] == "Phishing"


def test_statistics_aggregation(temp_db):
    save_scan("https://site1.com", "Legitimate", 10, 95.0, db_path=temp_db)
    save_scan("https://site2.com", "Legitimate", 20, 92.0, db_path=temp_db)
    save_scan("https://site3.com", "Phishing", 90, 98.0, db_path=temp_db)
    save_scan("https://site4.com", "Suspicious", 40, 70.0, db_path=temp_db)

    stats = get_statistics(db_path=temp_db)
    assert stats["total_scans"] == 4
    assert stats["legitimate_count"] == 2
    assert stats["phishing_count"] == 1
    assert stats["suspicious_count"] == 1
    assert stats["avg_risk_score"] == 40.0

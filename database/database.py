import os
import sqlite3
from datetime import datetime
from typing import List, Dict, Any, Optional
from database.models import ScanHistoryRecord

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "phishing_detector.db")


def get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = DB_PATH) -> None:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                prediction TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                confidence REAL NOT NULL,
                threat_level TEXT DEFAULT 'LOW',
                detection_time_ms REAL DEFAULT 0.0,
                scan_time TEXT NOT NULL
            );
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_time ON scan_history (scan_time DESC);
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_prediction ON scan_history (prediction);
        """)
        conn.commit()
    finally:
        conn.close()


def save_scan(
    url: str,
    prediction: str,
    risk_score: int,
    confidence: float,
    threat_level: str = "LOW",
    detection_time_ms: float = 0.0,
    scan_time: Optional[str] = None,
    db_path: str = DB_PATH
) -> int:
    if not scan_time:
        scan_time = datetime.now().isoformat()

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scan_history (url, prediction, risk_score, confidence, threat_level, detection_time_ms, scan_time)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (url, prediction, risk_score, confidence, threat_level, detection_time_ms, scan_time)
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def get_history(
    limit: int = 50,
    offset: int = 0,
    search: Optional[str] = None,
    prediction_filter: Optional[str] = None,
    db_path: str = DB_PATH
) -> List[Dict[str, Any]]:
    query = "SELECT * FROM scan_history WHERE 1=1"
    params: List[Any] = []

    if search:
        query += " AND url LIKE ?"
        params.append(f"%{search}%")

    if prediction_filter and prediction_filter.lower() != "all":
        query += " AND LOWER(prediction) = LOWER(?)"
        params.append(prediction_filter)

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [
            {
                "id": r["id"],
                "url": r["url"],
                "prediction": r["prediction"],
                "risk_score": r["risk_score"],
                "confidence": r["confidence"],
                "threat_level": r["threat_level"],
                "detection_time_ms": r["detection_time_ms"],
                "scan_time": r["scan_time"]
            }
            for r in rows
        ]
    finally:
        conn.close()


def get_statistics(db_path: str = DB_PATH) -> Dict[str, Any]:
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) AS total FROM scan_history")
        total_scans = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) AS c FROM scan_history WHERE LOWER(prediction) = 'phishing'")
        phishing_count = cursor.fetchone()["c"]

        cursor.execute("SELECT COUNT(*) AS c FROM scan_history WHERE LOWER(prediction) = 'suspicious'")
        suspicious_count = cursor.fetchone()["c"]

        cursor.execute("SELECT COUNT(*) AS c FROM scan_history WHERE LOWER(prediction) = 'legitimate'")
        legitimate_count = cursor.fetchone()["c"]

        cursor.execute("SELECT AVG(risk_score) AS avg_score FROM scan_history")
        avg_row = cursor.fetchone()["avg_score"]
        avg_risk_score = round(float(avg_row), 1) if avg_row is not None else 0.0

        today_prefix = datetime.now().strftime("%Y-%m-%d")
        cursor.execute("SELECT COUNT(*) AS c FROM scan_history WHERE scan_time LIKE ?", (f"{today_prefix}%",))
        today_scans = cursor.fetchone()["c"]

        return {
            "total_scans": total_scans,
            "phishing_count": phishing_count,
            "suspicious_count": suspicious_count,
            "legitimate_count": legitimate_count,
            "avg_risk_score": avg_risk_score,
            "today_scans": today_scans
        }
    finally:
        conn.close()


def clear_history(db_path: str = DB_PATH) -> None:
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_history")
        conn.commit()
    finally:
        conn.close()


init_db()

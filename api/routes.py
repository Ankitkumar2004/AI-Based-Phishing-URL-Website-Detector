import os
import io
import csv
import json
import logging
from datetime import datetime
from flask import Blueprint, request, jsonify, Response, current_app

from src.predictor import PhishingPredictor
from database.database import (
    save_scan,
    get_history,
    get_statistics,
    clear_history
)

logger = logging.getLogger("phishing_detector.api")
api_bp = Blueprint("api", __name__, url_prefix="/api")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
METADATA_PATH = os.path.join(BASE_DIR, "models", "model_metadata.json")

MAX_URL_LENGTH = 2048
MAX_BATCH_ROWS = 1000
MAX_CSV_BYTES = 5 * 1024 * 1024  # 5 MB


@api_bp.route("/health", methods=["GET"])
def health_check():
    predictor = PhishingPredictor.get_instance()
    db_ok = True
    try:
        get_statistics()
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        db_ok = False

    return jsonify({
        "status": "healthy" if (predictor.is_loaded and db_ok) else "degraded",
        "model_loaded": predictor.is_loaded,
        "database_connected": db_ok,
        "model_name": "RandomForestClassifier",
        "timestamp": datetime.now().isoformat()
    }), 200


@api_bp.route("/predict", methods=["POST"])
def predict():
    if not request.is_json:
        return jsonify({
            "error": "Bad Request",
            "message": "Request payload must be valid JSON with 'application/json' Content-Type."
        }), 400

    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({
            "error": "Bad Request",
            "message": "Missing required field 'url' in request payload."
        }), 400

    raw_url = data["url"]
    if not isinstance(raw_url, str):
        return jsonify({
            "error": "Bad Request",
            "message": "Field 'url' must be a string."
        }), 400

    raw_url = raw_url.strip()
    if not raw_url:
        return jsonify({
            "error": "Bad Request",
            "message": "URL field cannot be empty."
        }), 400

    if len(raw_url) > MAX_URL_LENGTH:
        return jsonify({
            "error": "Bad Request",
            "message": f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters."
        }), 400

    predictor = PhishingPredictor.get_instance()
    if not predictor.is_loaded:
        return jsonify({
            "error": "Service Unavailable",
            "message": "Machine learning model is not loaded. Train the model using 'python scripts/train_model.py'."
        }), 503

    try:
        result = predictor.predict(raw_url)

        try:
            save_scan(
                url=result["url"],
                prediction=result["prediction"],
                risk_score=result["risk_score"],
                confidence=result["confidence"],
                threat_level=result["threat_level"],
                detection_time_ms=result["detection_time_ms"]
            )
        except Exception as db_err:
            logger.error(f"Failed to record scan in database: {db_err}")

        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Prediction error for URL {raw_url[:50]}: {e}", exc_info=True)
        return jsonify({
            "error": "Internal Server Error",
            "message": "An error occurred while evaluating the URL."
        }), 500


@api_bp.route("/batch-predict", methods=["POST"])
def batch_predict():
    predictor = PhishingPredictor.get_instance()
    if not predictor.is_loaded:
        return jsonify({
            "error": "Service Unavailable",
            "message": "Machine learning model is not loaded."
        }), 503

    if "file" not in request.files:
        return jsonify({
            "error": "Bad Request",
            "message": "No file uploaded. Please upload a CSV file with field name 'file'."
        }), 400

    file = request.files["file"]
    if not file or not file.filename:
        return jsonify({
            "error": "Bad Request",
            "message": "Empty filename."
        }), 400

    if not file.filename.lower().endswith(".csv"):
        return jsonify({
            "error": "Bad Request",
            "message": "Invalid file type. Only CSV files (.csv) are accepted."
        }), 400

    content_bytes = file.read()
    if len(content_bytes) > MAX_CSV_BYTES:
        return jsonify({
            "error": "Payload Too Large",
            "message": f"CSV file exceeds maximum size limit of {MAX_CSV_BYTES // (1024 * 1024)}MB."
        }), 413

    try:
        decoded = content_bytes.decode("utf-8", errors="ignore")
        reader = csv.DictReader(io.StringIO(decoded))
        if not reader.fieldnames:
            return jsonify({
                "error": "Bad Request",
                "message": "CSV file is empty or corrupted."
            }), 400

        url_col = None
        for col in reader.fieldnames:
            if col.strip().lower() == "url":
                url_col = col
                break

        if not url_col:
            return jsonify({
                "error": "Bad Request",
                "message": f"Required column 'url' not found in CSV. Found columns: {reader.fieldnames}"
            }), 400

        results = []
        counts = {"Phishing": 0, "Suspicious": 0, "Legitimate": 0}

        row_count = 0
        for row in reader:
            row_count += 1
            if row_count > MAX_BATCH_ROWS:
                break

            raw_url = (row.get(url_col) or "").strip()
            if not raw_url:
                continue

            try:
                res = predictor.predict(raw_url)
                prediction = res["prediction"]
                counts[prediction] = counts.get(prediction, 0) + 1

                save_scan(
                    url=res["url"],
                    prediction=prediction,
                    risk_score=res["risk_score"],
                    confidence=res["confidence"],
                    threat_level=res["threat_level"],
                    detection_time_ms=res["detection_time_ms"]
                )

                results.append({
                    "url": raw_url,
                    "prediction": prediction,
                    "risk_score": res["risk_score"],
                    "confidence": res["confidence"],
                    "threat_level": res["threat_level"]
                })
            except Exception as item_err:
                logger.warning(f"Error predicting batch item {raw_url[:30]}: {item_err}")
                results.append({
                    "url": raw_url,
                    "prediction": "Error",
                    "risk_score": 0,
                    "confidence": 0.0,
                    "threat_level": "UNKNOWN"
                })

        format_param = request.args.get("format", "").lower()
        if format_param == "csv":
            output = io.StringIO()
            writer = csv.DictWriter(
                output,
                fieldnames=["url", "prediction", "risk_score", "confidence", "threat_level"]
            )
            writer.writeheader()
            for r in results:
                writer.writerow(r)
            output.seek(0)

            return Response(
                output.getvalue(),
                mimetype="text/csv",
                headers={
                    "Content-Disposition": "attachment; filename=phishing_scan_results.csv"
                }
            )

        return jsonify({
            "total_processed": len(results),
            "phishing_count": counts.get("Phishing", 0),
            "suspicious_count": counts.get("Suspicious", 0),
            "legitimate_count": counts.get("Legitimate", 0),
            "results": results
        }), 200

    except Exception as e:
        logger.error(f"Error processing CSV batch upload: {e}", exc_info=True)
        return jsonify({
            "error": "Bad Request",
            "message": "Failed to parse CSV file content."
        }), 400


@api_bp.route("/history", methods=["GET"])
def history():
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
        offset = max(int(request.args.get("offset", 0)), 0)
        search = request.args.get("search", None)
        prediction = request.args.get("prediction", None)

        records = get_history(limit=limit, offset=offset, search=search, prediction_filter=prediction)
        return jsonify({
            "count": len(records),
            "limit": limit,
            "offset": offset,
            "history": records
        }), 200
    except Exception as e:
        logger.error(f"Error fetching scan history: {e}")
        return jsonify({"error": "Failed to retrieve history"}), 500


@api_bp.route("/statistics", methods=["GET"])
def statistics():
    try:
        stats = get_statistics()
        return jsonify(stats), 200
    except Exception as e:
        logger.error(f"Error fetching statistics: {e}")
        return jsonify({"error": "Failed to retrieve statistics"}), 500


@api_bp.route("/model-info", methods=["GET"])
def model_info():
    if not os.path.exists(METADATA_PATH):
        return jsonify({
            "error": "Model metadata not found. Run model training pipeline first."
        }), 404

    try:
        with open(METADATA_PATH, "r", encoding="utf-8") as f:
            metadata = json.load(f)
        return jsonify(metadata), 200
    except Exception as e:
        logger.error(f"Error reading model metadata: {e}")
        return jsonify({"error": "Failed to read model metadata"}), 500

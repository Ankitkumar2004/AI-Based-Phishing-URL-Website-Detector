import os
import logging
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS

from api.routes import api_bp
from database.database import init_db
from src.predictor import PhishingPredictor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("phishing_detector.app")


def create_app():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    app = Flask(
        __name__,
        template_folder=os.path.join(base_dir, "templates"),
        static_folder=os.path.join(base_dir, "static")
    )

    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

    CORS(app, resources={r"/api/*": {"origins": "*"}})
    app.register_blueprint(api_bp)

    with app.app_context():
        try:
            init_db()
            predictor = PhishingPredictor.get_instance()
            logger.info(f"Predictor ready (loaded: {predictor.is_loaded})")
        except Exception as e:
            logger.warning(f"Startup init error: {e}")

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Not Found", "message": "The requested API endpoint does not exist."}), 404
        return render_template("index.html"), 404

    @app.errorhandler(500)
    def internal_error(e):
        logger.error(f"Internal server error: {e}", exc_info=True)
        if request.path.startswith("/api/"):
            return jsonify({"error": "Internal Server Error", "message": "An unexpected server error occurred."}), 500
        return jsonify({"error": "Internal Server Error"}), 500

    @app.errorhandler(413)
    def payload_too_large(e):
        return jsonify({"error": "Payload Too Large", "message": "File or payload size exceeds allowable limit."}), 413

    return app


app = create_app()

if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "False").lower() in ("true", "1", "yes")

    logger.info(f"Server running on http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)

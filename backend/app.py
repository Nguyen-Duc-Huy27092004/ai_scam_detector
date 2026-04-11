"""
Application factory and initialization module.

This is the main entry point for the Flask application.
"""

from flask import Flask, jsonify
from flask_cors import CORS
from datetime import datetime

from utils.config import HOST, PORT, DEBUG, CORS_ORIGINS, LOG_LEVEL
from utils.logger import logger, setup_logging
from routes.health import health_bp
from routes.url_routes import url_bp
from routes.image_routes import image_bp
from routes.text_routes import text_bp
from routes.history_routes import history_bp


def create_app(config=None):
    """
    Application factory function.
    
    Creates and configures the Flask application with all blueprints
    and middleware.
    """
    # Setup logging
    setup_logging(LOG_LEVEL)
    logger.info("Initializing Flask application...")
    
    # Create Flask app
    app = Flask(__name__)
    
    # Load configuration
    if config:
        app.config.update(config)
    
    # Configure CORS
    CORS(app, origins=CORS_ORIGINS, supports_credentials=True)
    logger.info("CORS configured for origins: %s", CORS_ORIGINS)
    
    # Register blueprints
    app.register_blueprint(health_bp)
    app.register_blueprint(url_bp)
    app.register_blueprint(image_bp)
    app.register_blueprint(text_bp)
    app.register_blueprint(history_bp)
    logger.info("All blueprints registered successfully")
    
    # Error handlers
    @app.errorhandler(400)
    def bad_request(error):
        """Handle 400 Bad Request errors."""
        return jsonify({
            "error": "Bad Request",
            "message": str(error),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }), 400
    
    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 Not Found errors."""
        return jsonify({
            "error": "Not Found",
            "message": "The requested resource was not found",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        """Handle 500 Internal Server errors."""
        logger.error("Internal server error: %s", str(error))
        return jsonify({
            "error": "Internal Server Error",
            "message": "An unexpected error occurred",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }), 500
    
    logger.info("Flask application initialized successfully")
    return app


def run_app():
    """Run the Flask development server."""
    app = create_app()
    logger.info("Starting Flask server on %s:%d", HOST, PORT)
    app.run(host=HOST, port=PORT, debug=DEBUG)


if __name__ == "__main__":
    run_app()

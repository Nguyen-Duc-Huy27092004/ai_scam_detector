from flask import Flask
from flask_cors import CORS
from backend.routes.health import health_bp
from backend.routes.analyze import analyze_bp

app = Flask(__name__)
CORS(app)

app.register_blueprint(health_bp)
app.register_blueprint(analyze_bp)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

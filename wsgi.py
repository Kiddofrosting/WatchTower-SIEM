"""
WatchTower SIEM - WSGI entry point
Used by Gunicorn: gunicorn wsgi:application
"""
import os
import sys

# Ensure the watchtower package is on the path
sys.path.insert(0, os.path.dirname(__file__))

from watchtower.app import create_app

application = create_app(os.getenv("FLASK_ENV", "production"))

if __name__ == "__main__":
    port = int(os.getenv("APP_PORT", 5000))
    host = os.getenv("APP_HOST", "0.0.0.0")
    debug = os.getenv("FLASK_ENV") == "development"
    application.run(host=host, port=port, debug=debug)

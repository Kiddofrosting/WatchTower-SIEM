#!/usr/bin/env python3
"""
WatchTower SIEM - Development Runner
Quick-start for local development only. Use Gunicorn + Docker for production.

Usage:
    python run.py
    FLASK_ENV=development python run.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from dotenv import load_dotenv
load_dotenv()

# Force dev mode
os.environ.setdefault("FLASK_ENV", "development")
os.environ.setdefault("SECRET_KEY", "dev-secret-key-change-in-production-!!!")
os.environ.setdefault("JWT_SECRET_KEY", "dev-jwt-key-change-in-production-!!!")
os.environ.setdefault("MONGO_URI", "mongodb://localhost:27017/watchtower_dev")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("SESSION_COOKIE_SECURE", "false")

from watchtower.app import create_app

app = create_app("development")

if __name__ == "__main__":
    port = int(os.getenv("APP_PORT", 5000))
    print(f"\n{'='*60}")
    print(f"  WatchTower SIEM - Development Server")
    print(f"  URL: http://localhost:{port}")
    print(f"  Default login: admin / Admin@WatchTower1!")
    print(f"{'='*60}\n")
    app.run(
        host="0.0.0.0",
        port=port,
        debug=True,
        use_reloader=True,
    )

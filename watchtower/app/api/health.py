"""WatchTower SIEM - Health Check (enhanced component detail)"""
import time
from flask import Blueprint, jsonify
from watchtower.app import mongo

health_bp = Blueprint("health", __name__)


@health_bp.get("/api/v1/health")
def health():
    checks = {}
    latencies = {}

    # MongoDB
    try:
        t0 = time.monotonic()
        mongo.db.command("ping")
        latencies["mongodb_ms"] = round((time.monotonic() - t0) * 1000, 1)
        checks["mongodb"] = "ok"
    except Exception as e:
        checks["mongodb"] = f"error: {str(e)[:50]}"

    # Redis
    try:
        from watchtower.app import limiter
        t0 = time.monotonic()
        storage = limiter._storage
        if hasattr(storage, "_storage"):
            storage._storage.ping()
        latencies["redis_ms"] = round((time.monotonic() - t0) * 1000, 1)
        checks["redis"] = "ok"
    except Exception as e:
        checks["redis"] = f"error: {str(e)[:50]}"

    # Celery worker count (non-blocking, best-effort)
    try:
        from watchtower.celery_workers.celery_app import celery_app
        inspector = celery_app.control.inspect(timeout=1.0)
        pong = inspector.ping() or {}
        checks["celery_workers"] = len(pong)
    except Exception:
        checks["celery_workers"] = "unavailable"

    overall = "ok" if checks.get("mongodb") == "ok" else "degraded"
    status_code = 200 if overall == "ok" else 503

    return jsonify({
        "status": overall,
        "checks": checks,
        "latencies": latencies,
        "service": "WatchTower SIEM",
    }), status_code

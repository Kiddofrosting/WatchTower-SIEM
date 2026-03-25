"""WatchTower SIEM - Celery Application"""
import os

from celery import Celery
from celery.signals import worker_init
from dotenv import load_dotenv

load_dotenv()

celery_app = Celery(
    "watchtower",
    broker=os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0"),
    backend=os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/1"),
    include=["watchtower.celery_workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    # FIX: prefetch=1 prevents queue starvation on long-running tasks with acks_late
    worker_prefetch_multiplier=1,
    task_routes={
        # FIX: corrected full module paths (previously missing "watchtower." prefix)
        "watchtower.celery_workers.tasks.process_events_batch": {"queue": "detection"},
        "watchtower.celery_workers.tasks.run_ai_triage": {"queue": "ai"},
        "watchtower.celery_workers.tasks.run_ai_remediation": {"queue": "ai"},
        "watchtower.celery_workers.tasks.run_correlation_pass": {"queue": "detection"},
        "watchtower.celery_workers.tasks.check_anomalies": {"queue": "detection"},
        "watchtower.celery_workers.tasks.compute_baselines": {"queue": "maintenance"},
        "watchtower.celery_workers.tasks.run_scheduled_reports": {"queue": "maintenance"},
        "watchtower.celery_workers.tasks.run_retention_cleanup": {"queue": "maintenance"},
        "watchtower.celery_workers.tasks.check_agent_heartbeats": {"queue": "maintenance"},
    },
    beat_schedule={
        # FIX: corrected task names (previously missing "watchtower." prefix — silent beat failures)
        "retention-cleanup-daily": {
            "task": "watchtower.celery_workers.tasks.run_retention_cleanup",
            "schedule": 86400.0,
        },
        "agent-heartbeat-check": {
            "task": "watchtower.celery_workers.tasks.check_agent_heartbeats",
            "schedule": 300.0,
        },
        "correlation-pass": {
            "task": "watchtower.celery_workers.tasks.run_correlation_pass",
            "schedule": 120.0,   # every 2 minutes
        },
        "anomaly-check": {
            "task": "watchtower.celery_workers.tasks.check_anomalies",
            "schedule": 1800.0,  # every 30 minutes
        },
        "baseline-compute-nightly": {
            "task": "watchtower.celery_workers.tasks.compute_baselines",
            "schedule": 86400.0, # daily
        },
        "scheduled-reports-check": {
            "task": "watchtower.celery_workers.tasks.run_scheduled_reports",
            "schedule": 3600.0,  # every hour
        },
    },
)

# ─────────────────────────────────────────────────────────────────────────────
# Worker-level Flask app singleton
# FIX: create_app() was previously called on every task invocation (expensive).
# Now created once per worker process and cached.
# ─────────────────────────────────────────────────────────────────────────────

_flask_app = None


@worker_init.connect
def init_worker(**kwargs):
    """Called once when a Celery worker process starts up."""
    global _flask_app
    from watchtower.app import create_app
    _flask_app = create_app()


def get_flask_app():
    """Return the cached Flask app, or create one if running outside a worker (e.g. tests)."""
    global _flask_app
    if _flask_app is None:
        from watchtower.app import create_app
        _flask_app = create_app()
    return _flask_app

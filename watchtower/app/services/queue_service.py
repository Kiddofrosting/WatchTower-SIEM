"""WatchTower SIEM - Queue Service"""
import logging

logger = logging.getLogger(__name__)


def enqueue_events_for_detection(event_ids: list, agent_id: str, hostname: str):
    """Enqueue event IDs for async detection engine processing."""
    if not event_ids:
        return
    try:
        from watchtower.celery_workers.tasks import process_events_batch
        process_events_batch.delay(event_ids, agent_id, hostname)
    except Exception as e:
        logger.warning(f"Failed to enqueue events for detection: {e}")


def enqueue_ai_remediation(incident_id: str):
    """Enqueue an incident for AI remediation generation."""
    try:
        from watchtower.celery_workers.tasks import run_ai_remediation
        run_ai_remediation.delay(incident_id)
    except Exception as e:
        logger.warning(f"Failed to enqueue AI remediation: {e}")

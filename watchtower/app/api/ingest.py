"""
WatchTower SIEM - Log Ingestion API
High-throughput event ingestion endpoint for Windows agents.
"""

import gzip
from datetime import datetime, timezone

from flask import Blueprint, current_app, g, jsonify, request

from watchtower.app import limiter, mongo
from watchtower.app.security import require_agent_auth
from watchtower.app.services.normalizer import normalize_event
from watchtower.app.services.queue_service import enqueue_events_for_detection

ingest_bp = Blueprint("ingest", __name__)


@ingest_bp.post("/ingest")
# FIX: key on full agent_id (unique) instead of first 16 chars of API key (collision-prone)
@limiter.limit("1000 per minute", key_func=lambda: str(getattr(g, "agent", {}).get("_id", request.headers.get("X-WatchTower-Key", "unknown")[:16])))
@require_agent_auth
def ingest_events():
    """
    Accept a batch of Windows event log entries from an authenticated agent.
    Validates, normalizes, bulk-inserts, and enqueues for detection.
    """
    # Support gzip-compressed payloads
    content_encoding = request.headers.get("Content-Encoding", "")
    raw_body = request.get_data()

    if "gzip" in content_encoding:
        try:
            raw_body = gzip.decompress(raw_body)
        except Exception:
            return jsonify({"error": "invalid_gzip_encoding"}), 400

    data = request.get_json(force=True, silent=True)
    if data is None:
        try:
            import json
            data = json.loads(raw_body)
        except Exception:
            return jsonify({"error": "invalid_json"}), 400

    if not isinstance(data, list):
        return jsonify({"error": "expected_array"}), 422

    if len(data) > 1000:
        return jsonify({"error": "batch_too_large", "max": 1000}), 422

    agent = g.agent
    agent_id = str(agent["_id"])
    hostname = agent["hostname"]

    accepted = []
    rejected = []

    for idx, raw_event in enumerate(data):
        if not isinstance(raw_event, dict):
            rejected.append({"index": idx, "reason": "not_an_object"})
            continue

        # Basic required field validation
        if "event_id" not in raw_event or "timestamp" not in raw_event:
            rejected.append({"index": idx, "reason": "missing_required_fields"})
            continue

        try:
            normalized = normalize_event(raw_event, hostname)
            from watchtower.app.models import new_event
            event_doc = new_event(raw_event, agent_id, hostname, normalized)
            accepted.append(event_doc)
        except Exception as e:
            current_app.logger.warning(f"Event normalization failed at index {idx}: {e}")
            rejected.append({"index": idx, "reason": "normalization_error"})

    inserted_ids = []
    if accepted:
        try:
            result = mongo.db.events.insert_many(accepted, ordered=False)
            inserted_ids = [str(i) for i in result.inserted_ids]

            # Update agent stats
            mongo.db.agents.update_one(
                {"_id": agent["_id"]},
                {
                    "$inc": {"events_received": len(inserted_ids), "events_today": len(inserted_ids)},
                    "$set": {"last_seen": datetime.now(timezone.utc), "last_ip": request.remote_addr}
                }
            )

            # Enqueue for async detection (non-blocking)
            enqueue_events_for_detection(inserted_ids, agent_id, hostname)

        except Exception as e:
            current_app.logger.error(f"Bulk insert failed: {e}")
            return jsonify({"error": "storage_error"}), 500

    return jsonify({
        "accepted": len(inserted_ids),
        "rejected": len(rejected),
        "rejection_details": rejected[:20] if rejected else [],
    }), 207 if rejected else 202


# NOTE: /api/v1/health is served by health_bp (watchtower/app/api/health.py).
# A duplicate route here was removed to prevent Flask endpoint conflicts.

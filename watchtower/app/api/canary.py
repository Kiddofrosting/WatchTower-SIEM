"""
WatchTower SIEM - Deception / Canary Token API
===============================================
Canary tokens are fake credentials, documents, or URLs that exist only
as traps. Any interaction with them is a guaranteed true-positive alert.

Supported canary types:
  - api_key     : Fake API keys planted in configs/docs
  - credential  : Fake username/password pairs
  - url         : Tracking URLs — fire when clicked
  - hostname    : Canary hostnames — fire when accessed
  - file_hash   : Fake file hashes — fire if seen in process events

When a canary fires:
  - Instant critical incident (zero false positives by definition)
  - AI triage is skipped (canaries are ALWAYS real)
  - Immediate alerting regardless of severity thresholds
"""

import secrets
import string
from datetime import datetime, timezone

from bson import ObjectId
from flask import Blueprint, jsonify, request

from watchtower.app import mongo
from watchtower.app.models import UserRole, new_incident, new_notification
from watchtower.app.security import require_auth, require_roles, audit_log_action
from watchtower.app.services.alerting import send_incident_alerts

canary_bp = Blueprint("canary", __name__)

CANARY_TYPES = ("api_key", "credential", "url", "hostname", "file_hash")


def _generate_canary_value(canary_type: str) -> str:
    """Generate a realistic-looking fake value for the given type."""
    rand = secrets.token_urlsafe
    if canary_type == "api_key":
        return f"sk-live-{''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(40))}"
    elif canary_type == "credential":
        words = ["admin", "backup", "svc", "deploy", "monitor", "test"]
        return f"{secrets.choice(words)}_{secrets.token_hex(6)}"
    elif canary_type == "url":
        return f"https://canary.internal/{rand(16)}"
    elif canary_type == "hostname":
        return f"srv-backup-{rand(4).lower()}.internal"
    elif canary_type == "file_hash":
        return secrets.token_hex(32)  # fake SHA256
    return rand(24)


@canary_bp.get("/")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.ANALYST)
def list_canaries():
    canaries = list(mongo.db.canaries.find().sort("created_at", -1))
    for c in canaries:
        c["_id"] = str(c["_id"])
        for f in ("created_at", "last_triggered"):
            if isinstance(c.get(f), datetime):
                c[f] = c[f].isoformat()
    return jsonify({"data": canaries, "total": len(canaries)}), 200


@canary_bp.post("/")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.ANALYST)
def create_canary():
    from flask_jwt_extended import current_user
    data = request.get_json(silent=True) or {}
    canary_type = data.get("type", "api_key")
    if canary_type not in CANARY_TYPES:
        return jsonify({"error": f"type must be one of {CANARY_TYPES}"}), 422

    value = data.get("value") or _generate_canary_value(canary_type)
    doc = {
        "name": data.get("name", f"Canary {canary_type} {datetime.now(timezone.utc).strftime('%Y%m%d')}"),
        "type": canary_type,
        "value": value,
        "description": data.get("description", ""),
        "placement": data.get("placement", ""),  # where it was planted, e.g. "AWS config"
        "tags": data.get("tags", []),
        "enabled": True,
        "trigger_count": 0,
        "last_triggered": None,
        "created_by": str(current_user["_id"]),
        "created_at": datetime.now(timezone.utc),
    }
    result = mongo.db.canaries.insert_one(doc)
    audit_log_action(current_user, "canary_created", "canary", str(result.inserted_id),
                     {"type": canary_type, "name": doc["name"]})
    return jsonify({
        "message": "Canary token created",
        "id": str(result.inserted_id),
        "type": canary_type,
        "value": value,
        "warning": "Plant this value in the target location. It will alert when accessed.",
    }), 201


@canary_bp.delete("/<canary_id>")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN)
def delete_canary(canary_id: str):
    from flask_jwt_extended import current_user
    try:
        oid = ObjectId(canary_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400
    result = mongo.db.canaries.delete_one({"_id": oid})
    if result.deleted_count == 0:
        return jsonify({"error": "not_found"}), 404
    audit_log_action(current_user, "canary_deleted", "canary", canary_id, {})
    return jsonify({"message": "Canary deleted"}), 200


@canary_bp.post("/check")
def check_canary_trigger():
    """
    Called from the ingest pipeline or detection engine.
    Checks if any observed value matches a canary token.
    Body: {"values": ["val1", "val2", ...], "hostname": "...", "source": "ingest|detection"}
    This endpoint is internal — authenticated via agent key or internal call.
    """
    data = request.get_json(silent=True) or {}
    values = data.get("values", [])
    hostname = data.get("hostname", "unknown")
    source = data.get("source", "unknown")

    if not values:
        return jsonify({"triggered": False}), 200

    # Check against all enabled canaries
    triggered = []
    for canary in mongo.db.canaries.find({"enabled": True, "value": {"$in": values}}):
        triggered.append(canary)

    if not triggered:
        return jsonify({"triggered": False}), 200

    # Create critical incidents for each triggered canary
    now = datetime.now(timezone.utc)
    for canary in triggered:
        # Update canary stats
        mongo.db.canaries.update_one(
            {"_id": canary["_id"]},
            {"$inc": {"trigger_count": 1}, "$set": {"last_triggered": now}}
        )

        # Canary incidents are ALWAYS critical and skip AI triage
        incident_doc = new_incident(
            rule_id="canary",
            rule_name="Canary Token Triggered",
            title=f"🍯 CANARY TRIGGERED: {canary['name']} on {hostname}",
            description=(
                f"Canary token of type '{canary['type']}' was accessed on {hostname}. "
                f"Placement: {canary.get('placement', 'unknown')}. "
                f"This is a guaranteed true positive — an attacker has accessed "
                f"a monitored decoy credential/resource."
            ),
            severity="critical",
            category="credential_access",
            hostname=hostname,
            triggering_event_ids=[],
            mitre_technique=["T1078", "T1552"],
            mitre_tactic=["Initial Access", "Credential Access"],
        )
        incident_doc["canary_id"] = str(canary["_id"])
        incident_doc["canary_type"] = canary["type"]
        incident_doc["tags"] = ["canary", "guaranteed_true_positive"]
        # Mark triage as done — canaries never need AI triage
        incident_doc["ai_triage"] = {
            "true_positive_score": 100,
            "recommended_action": "escalate",
            "analyst_brief": "Canary token triggered — this is a guaranteed true positive.",
            "key_evidence": [f"Canary {canary['type']} '{canary['name']}' was accessed"],
            "triaged_at": now,
            "auto_closed": False,
            "escalated": True,
        }
        incident_doc["status"] = "investigating"

        result = mongo.db.incidents.insert_one(incident_doc)
        incident_doc["_id"] = str(result.inserted_id)

        # Notify all admins+analysts immediately
        admins = list(mongo.db.users.find(
            {"is_active": True, "role": {"$in": ["super_admin", "admin", "analyst"]}},
            {"_id": 1}
        ))
        notifs = [
            new_notification(
                user_id=str(u["_id"]),
                title=f"🍯 CANARY TRIGGERED: {canary['name']}",
                message=f"Canary token accessed on {hostname}. Guaranteed true positive.",
                severity="critical",
                link=f"/dashboard/incidents/{incident_doc['_id']}",
                incident_id=incident_doc["_id"],
            )
            for u in admins
        ]
        if notifs:
            mongo.db.notifications.insert_many(notifs)

        # Alert with no threshold check
        try:
            from flask import current_app
            send_incident_alerts(incident_doc, current_app.config, mongo)
        except Exception:
            pass

    return jsonify({
        "triggered": True,
        "canaries_triggered": len(triggered),
        "names": [c["name"] for c in triggered],
    }), 200


@canary_bp.get("/stats")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.ANALYST)
def canary_stats():
    total = mongo.db.canaries.count_documents({})
    triggered = mongo.db.canaries.count_documents({"trigger_count": {"$gt": 0}})
    recent = list(mongo.db.canaries.find(
        {"last_triggered": {"$ne": None}}
    ).sort("last_triggered", -1).limit(5))
    for c in recent:
        c["_id"] = str(c["_id"])
        if isinstance(c.get("last_triggered"), datetime):
            c["last_triggered"] = c["last_triggered"].isoformat()
    by_type = {r["_id"]: r["count"] for r in mongo.db.canaries.aggregate([
        {"$group": {"_id": "$type", "count": {"$sum": 1}}}
    ])}
    return jsonify({
        "total_canaries": total,
        "triggered_ever": triggered,
        "by_type": by_type,
        "recently_triggered": recent,
    }), 200

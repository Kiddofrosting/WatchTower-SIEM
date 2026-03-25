"""WatchTower SIEM - Settings API (with maintenance window + webhook + audit export)"""
import csv
import io
from datetime import datetime, timezone

from flask import Blueprint, Response, jsonify, request, current_app, stream_with_context
from watchtower.app import mongo
from watchtower.app.security import require_roles, require_auth, audit_log_action
from watchtower.app.models import UserRole

settings_bp = Blueprint("settings", __name__)


@settings_bp.get("/")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN)
def get_settings():
    settings = mongo.db.settings.find_one({"_id": "global"}) or {}
    settings.pop("_id", None)
    return jsonify(settings), 200


@settings_bp.put("/")
@require_roles(UserRole.SUPER_ADMIN)
def update_settings():
    from flask_jwt_extended import current_user
    data = request.get_json(silent=True) or {}
    allowed_keys = {
        "retention_raw_events_days", "retention_incidents_days",
        "retention_audit_log_days", "slack_webhook_url",
        "email_alerts_enabled", "slack_alerts_enabled",
        "alert_min_severity", "auto_close_fp_days",
        "org_name", "org_contact_email",
        # NEW: webhook outbound
        "webhook_enabled", "webhook_url", "webhook_secret",
        # NEW: Teams
        "teams_webhook_url", "teams_alerts_enabled",
        # AI triage settings
        "ai_triage_enabled", "triage_auto_close_threshold", "triage_auto_escalate_threshold",
    }
    updates = {k: v for k, v in data.items() if k in allowed_keys}
    updates["updated_at"] = datetime.now(timezone.utc).isoformat()
    updates["updated_by"] = str(current_user["_id"])

    mongo.db.settings.update_one({"_id": "global"}, {"$set": updates}, upsert=True)
    audit_log_action(current_user, "settings_updated", "settings", "global",
                     {"fields": list(updates.keys())})
    return jsonify({"message": "Settings updated"}), 200


# ── Maintenance window (NEW) ──────────────────────────────────────────────────

@settings_bp.post("/maintenance-window")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN)
def set_maintenance_window():
    """
    Set a maintenance window during which alert dispatch is suppressed.
    Body: { "start": "2025-01-01T02:00:00Z", "end": "2025-01-01T04:00:00Z" }
    Pass null to clear.
    """
    from flask_jwt_extended import current_user
    data = request.get_json(silent=True) or {}
    start = data.get("start")
    end = data.get("end")

    if start is None and end is None:
        # Clear window
        mongo.db.settings.update_one({"_id": "global"}, {"$unset": {"maintenance_window": ""}}, upsert=True)
        return jsonify({"message": "Maintenance window cleared"}), 200

    try:
        start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
    except Exception:
        return jsonify({"error": "Invalid datetime format. Use ISO 8601."}), 422

    if end_dt <= start_dt:
        return jsonify({"error": "end must be after start"}), 422

    mongo.db.settings.update_one(
        {"_id": "global"},
        {"$set": {"maintenance_window": {"start": start_dt.isoformat(), "end": end_dt.isoformat()}}},
        upsert=True,
    )
    audit_log_action(current_user, "maintenance_window_set", "settings", "global",
                     {"start": start, "end": end})
    return jsonify({"message": "Maintenance window set", "start": start, "end": end}), 200


@settings_bp.get("/maintenance-window")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN)
def get_maintenance_window():
    settings = mongo.db.settings.find_one({"_id": "global"}) or {}
    mw = settings.get("maintenance_window")
    return jsonify({"maintenance_window": mw}), 200


# ── Audit log export (NEW) ────────────────────────────────────────────────────

@settings_bp.get("/audit-log")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN)
def get_audit_log():
    """Paginated audit log browser."""
    page = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 50)), 500)
    skip = (page - 1) * per_page

    query = {}
    if request.args.get("user_id"):
        query["user_id"] = request.args["user_id"]
    if request.args.get("action"):
        query["action"] = request.args["action"]

    total = mongo.db.audit_log.count_documents(query)
    entries = list(mongo.db.audit_log.find(query).sort("timestamp", -1).skip(skip).limit(per_page))
    for e in entries:
        e["_id"] = str(e["_id"])
        if isinstance(e.get("timestamp"), datetime):
            e["timestamp"] = e["timestamp"].isoformat()

    return jsonify({
        "data": entries,
        "pagination": {"page": page, "per_page": per_page, "total": total,
                       "pages": (total + per_page - 1) // per_page},
    }), 200


@settings_bp.get("/audit-log/export")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN)
def export_audit_log():
    """Stream audit log as CSV for compliance packages."""
    from flask_jwt_extended import current_user
    from python_dateutil import parser as dtparser

    query = {}
    if request.args.get("from"):
        try:
            query["timestamp"] = {"$gte": datetime.fromisoformat(request.args["from"].replace("Z", "+00:00"))}
        except Exception:
            pass
    if request.args.get("to"):
        ts_filter = query.get("timestamp", {})
        try:
            ts_filter["$lte"] = datetime.fromisoformat(request.args["to"].replace("Z", "+00:00"))
            query["timestamp"] = ts_filter
        except Exception:
            pass

    audit_log_action(current_user, "audit_log_exported", "audit_log", "csv", {})

    def generate():
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["timestamp", "username", "action", "resource_type", "resource_id",
                         "ip_address", "user_agent", "details"])
        yield out.getvalue()
        out.seek(0); out.truncate(0)

        for entry in mongo.db.audit_log.find(query).sort("timestamp", -1).limit(100_000):
            ts = entry.get("timestamp", "")
            if isinstance(ts, datetime):
                ts = ts.isoformat()
            writer.writerow([
                ts,
                entry.get("username", ""),
                entry.get("action", ""),
                entry.get("resource_type", ""),
                entry.get("resource_id", ""),
                entry.get("ip_address", ""),
                entry.get("user_agent", ""),
                str(entry.get("details", {})),
            ])
            yield out.getvalue()
            out.seek(0); out.truncate(0)

    return Response(
        stream_with_context(generate()),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=watchtower_audit_log.csv"},
    )

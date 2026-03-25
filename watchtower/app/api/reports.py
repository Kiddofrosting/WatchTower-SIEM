"""
WatchTower SIEM - Scheduled & On-Demand Reports API
====================================================
Generate and schedule automated reports:
  - Executive summary (weekly/monthly)
  - Incident trend reports
  - Agent health reports
  - Top threats report
  - Custom date-range reports

Reports are generated as structured JSON (renderable to PDF/email).
Scheduled reports use Celery Beat via DB-stored schedules.
"""

from datetime import datetime, timedelta, timezone

from bson import ObjectId
from flask import Blueprint, jsonify, request, current_app

from watchtower.app import mongo
from watchtower.app.models import UserRole
from watchtower.app.security import require_auth, require_roles, audit_log_action

reports_bp = Blueprint("reports", __name__)


def _build_executive_summary(days: int, mongo) -> dict:
    """Build a complete executive summary report."""
    now = datetime.now(timezone.utc)
    period = now - timedelta(days=days)
    prev_period = period - timedelta(days=days)

    def pct_change(current, previous):
        if previous == 0:
            return None
        return round((current - previous) / previous * 100, 1)

    # Current period stats
    total_events = mongo.db.events.count_documents({"timestamp": {"$gte": period}})
    total_incidents = mongo.db.incidents.count_documents({"created_at": {"$gte": period}})
    critical_incidents = mongo.db.incidents.count_documents(
        {"created_at": {"$gte": period}, "severity": "critical"})
    resolved = mongo.db.incidents.count_documents(
        {"created_at": {"$gte": period}, "status": {"$in": ["resolved", "closed", "false_positive"]}})
    auto_closed = mongo.db.incidents.count_documents(
        {"created_at": {"$gte": period}, "ai_triage.auto_closed": True})

    # Previous period for trend
    prev_incidents = mongo.db.incidents.count_documents(
        {"created_at": {"$gte": prev_period, "$lt": period}})
    prev_events = mongo.db.events.count_documents(
        {"timestamp": {"$gte": prev_period, "$lt": period}})

    # MTTR
    mttr_pipeline = [
        {"$match": {"status": {"$in": ["resolved", "closed"]},
                    "created_at": {"$gte": period},
                    "resolved_at": {"$exists": True}}},
        {"$project": {"resolution_time": {"$subtract": ["$resolved_at", "$created_at"]}}},
        {"$group": {"_id": None, "avg_ms": {"$avg": "$resolution_time"}}},
    ]
    mttr_result = list(mongo.db.incidents.aggregate(mttr_pipeline))
    mttr_hours = round(mttr_result[0]["avg_ms"] / 3_600_000, 1) if mttr_result else None

    # Top 5 MITRE techniques
    mitre_pipeline = [
        {"$match": {"created_at": {"$gte": period}}},
        {"$unwind": "$mitre_technique"},
        {"$group": {"_id": "$mitre_technique", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5},
    ]
    top_mitre = [{"technique": r["_id"], "count": r["count"]}
                 for r in mongo.db.incidents.aggregate(mitre_pipeline)]

    # Top 5 affected hosts
    host_pipeline = [
        {"$match": {"created_at": {"$gte": period}}},
        {"$group": {"_id": "$hostname", "count": {"$sum": 1},
                    "critical": {"$sum": {"$cond": [{"$eq": ["$severity", "critical"]}, 1, 0]}}}},
        {"$sort": {"count": -1}},
        {"$limit": 5},
    ]
    top_hosts = [{"hostname": r["_id"], "incidents": r["count"], "critical": r["critical"]}
                 for r in mongo.db.incidents.aggregate(host_pipeline)]

    # Active agents
    active_agents = mongo.db.agents.count_documents({"status": "active"})
    offline_agents = mongo.db.agents.count_documents({"status": "inactive"})

    # Compliance posture snapshot
    try:
        from watchtower.app.api.compliance import FRAMEWORKS, _score_control
        posture = {}
        for fw_id, fw in list(FRAMEWORKS.items())[:2]:  # SOC2 + NIST for exec report
            scored = [_score_control(c, period, mongo) for c in fw["controls"]]
            tw = sum(c.get("weight", 1) for c in fw["controls"])
            ws = sum(c["score"] * c.get("weight", 1) for c in scored) / max(tw, 1)
            posture[fw_id] = {"name": fw["name"], "score": round(ws, 1)}
    except Exception:
        posture = {}

    return {
        "period_days": days,
        "generated_at": now.isoformat(),
        "metrics": {
            "total_events": total_events,
            "total_incidents": total_incidents,
            "critical_incidents": critical_incidents,
            "resolved_incidents": resolved,
            "resolution_rate_pct": round(resolved / total_incidents * 100, 1) if total_incidents else 100,
            "auto_triaged_closed": auto_closed,
            "mttr_hours": mttr_hours,
            "active_agents": active_agents,
            "offline_agents": offline_agents,
        },
        "trends": {
            "incidents_change_pct": pct_change(total_incidents, prev_incidents),
            "events_change_pct": pct_change(total_events, prev_events),
        },
        "top_mitre_techniques": top_mitre,
        "top_affected_hosts": top_hosts,
        "compliance_posture": posture,
    }


# ── On-demand report generation ───────────────────────────────────────────────

@reports_bp.get("/executive-summary")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.ANALYST)
def executive_summary():
    from flask_jwt_extended import current_user
    days = int(request.args.get("days", 30))
    report = _build_executive_summary(days, mongo)
    report["org_name"] = current_app.config.get("ORG_NAME", "Organization")
    report["generated_by"] = current_user["username"]
    audit_log_action(current_user, "report_generated", "reports", "executive_summary",
                     {"days": days})
    return jsonify(report), 200


@reports_bp.get("/agent-health")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.ANALYST)
def agent_health_report():
    from flask_jwt_extended import current_user
    now = datetime.now(timezone.utc)
    agents = list(mongo.db.agents.find({}, {"api_key_hash": 0}).sort("hostname", 1))

    report_agents = []
    for a in agents:
        last_seen = a.get("last_seen")
        minutes_since = None
        if last_seen:
            minutes_since = round((now - last_seen).total_seconds() / 60, 1)

        # Events in last 24h from this agent
        events_24h = mongo.db.events.count_documents({
            "hostname": a["hostname"],
            "timestamp": {"$gte": now - timedelta(hours=24)},
        })

        # Open incidents
        open_incidents = mongo.db.incidents.count_documents({
            "hostname": a["hostname"],
            "status": {"$in": ["open", "investigating"]},
        })

        report_agents.append({
            "hostname": a["hostname"],
            "status": a.get("status"),
            "last_seen_minutes_ago": minutes_since,
            "agent_version": a.get("agent_version"),
            "os_version": a.get("os_version"),
            "events_24h": events_24h,
            "open_incidents": open_incidents,
            "sysmon_installed": a.get("sysmon_installed", False),
        })

    audit_log_action(current_user, "report_generated", "reports", "agent_health", {})
    return jsonify({
        "generated_at": now.isoformat(),
        "total_agents": len(agents),
        "active": sum(1 for a in report_agents if a["status"] == "active"),
        "inactive": sum(1 for a in report_agents if a["status"] == "inactive"),
        "agents": report_agents,
    }), 200


# ── Scheduled reports ─────────────────────────────────────────────────────────

@reports_bp.get("/schedules")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN)
def list_schedules():
    schedules = list(mongo.db.report_schedules.find().sort("created_at", -1))
    for s in schedules:
        s["_id"] = str(s["_id"])
        for f in ("created_at", "last_run", "next_run"):
            if isinstance(s.get(f), datetime):
                s[f] = s[f].isoformat()
    return jsonify({"data": schedules, "total": len(schedules)}), 200


@reports_bp.post("/schedules")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN)
def create_schedule():
    from flask_jwt_extended import current_user
    data = request.get_json(silent=True) or {}

    report_type = data.get("report_type", "executive_summary")
    if report_type not in ("executive_summary", "agent_health", "compliance"):
        return jsonify({"error": "invalid report_type"}), 422

    frequency = data.get("frequency", "weekly")
    if frequency not in ("daily", "weekly", "monthly"):
        return jsonify({"error": "frequency must be daily|weekly|monthly"}), 422

    recipients = data.get("recipients", [])
    if not recipients:
        return jsonify({"error": "at least one recipient email required"}), 422

    now = datetime.now(timezone.utc)
    next_run = _next_run(frequency, now)

    doc = {
        "name": data.get("name", f"{report_type} ({frequency})"),
        "report_type": report_type,
        "frequency": frequency,
        "recipients": recipients,
        "enabled": True,
        "days_lookback": int(data.get("days_lookback", 7 if frequency == "weekly" else 30)),
        "last_run": None,
        "next_run": next_run,
        "created_by": str(current_user["_id"]),
        "created_at": now,
    }
    result = mongo.db.report_schedules.insert_one(doc)
    audit_log_action(current_user, "report_schedule_created", "reports",
                     str(result.inserted_id), {"frequency": frequency, "type": report_type})
    return jsonify({"message": "Schedule created", "id": str(result.inserted_id),
                    "next_run": next_run.isoformat()}), 201


@reports_bp.delete("/schedules/<schedule_id>")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN)
def delete_schedule(schedule_id: str):
    from flask_jwt_extended import current_user
    try:
        oid = ObjectId(schedule_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400
    result = mongo.db.report_schedules.delete_one({"_id": oid})
    if result.deleted_count == 0:
        return jsonify({"error": "not_found"}), 404
    return jsonify({"message": "Schedule deleted"}), 200


def _next_run(frequency: str, from_dt: datetime) -> datetime:
    if frequency == "daily":
        return from_dt + timedelta(days=1)
    elif frequency == "weekly":
        return from_dt + timedelta(weeks=1)
    else:  # monthly
        return from_dt + timedelta(days=30)

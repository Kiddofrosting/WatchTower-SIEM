"""
WatchTower SIEM - Dashboard Summary API
"""
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify
from watchtower.app import mongo
from watchtower.app.security import require_auth
from watchtower.app.models import IncidentStatus

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.get("/summary")
@require_auth
def get_summary():
    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    # Core metrics
    total_events_24h = mongo.db.events.count_documents({"timestamp": {"$gte": last_24h}})
    open_incidents = mongo.db.incidents.count_documents({"status": IncidentStatus.OPEN})
    critical_incidents = mongo.db.incidents.count_documents(
        {"status": IncidentStatus.OPEN, "severity": "critical"})
    active_agents = mongo.db.agents.count_documents({"status": "active"})

    # Agents seen in last hour
    last_hour = now - timedelta(hours=1)
    online_agents = mongo.db.agents.count_documents({
        "status": "active",
        "last_seen": {"$gte": last_hour}
    })

    # Events by severity last 24h
    sev_pipeline = [
        {"$match": {"timestamp": {"$gte": last_24h}}},
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
    ]
    severity_dist = {r["_id"]: r["count"] for r in mongo.db.events.aggregate(sev_pipeline)}

    # Incident trend last 7 days
    inc_trend_pipeline = [
        {"$match": {"created_at": {"$gte": last_7d}}},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$created_at"}},
            "count": {"$sum": 1},
        }},
        {"$sort": {"_id": 1}},
    ]
    incident_trend = list(mongo.db.incidents.aggregate(inc_trend_pipeline))

    # Recent incidents
    recent_incidents = list(
        mongo.db.incidents.find(
            {"status": {"$in": [IncidentStatus.OPEN, IncidentStatus.INVESTIGATING]}},
            {"analyst_notes": 0, "timeline": 0, "ai_remediation": 0}
        ).sort("created_at", -1).limit(5)
    )
    for i in recent_incidents:
        i["_id"] = str(i["_id"])
        if isinstance(i.get("created_at"), datetime):
            i["created_at"] = i["created_at"].isoformat()

    # Unread notifications count
    unread_notifications = 0  # resolved per-user in notifications endpoint

    # Asset health summary
    asset_summary = {
        "total": mongo.db.assets.count_documents({}),
        "critical": mongo.db.assets.count_documents({"criticality": "critical"}),
        "internet_facing": mongo.db.assets.count_documents({"is_internet_facing": True}),
        "unowned": mongo.db.assets.count_documents({"owner": {"$in": ["", None]}}),
    }

    # AI triage stats (last 24h)
    triage_stats = {
        "auto_closed_24h": mongo.db.incidents.count_documents({
            "ai_triage.auto_closed": True,
            "updated_at": {"$gte": last_24h},
        }),
        "auto_escalated_24h": mongo.db.incidents.count_documents({
            "ai_triage.escalated": True,
            "updated_at": {"$gte": last_24h},
        }),
        "avg_triage_score": None,
    }
    score_pipeline = [
        {"$match": {"ai_triage.true_positive_score": {"$exists": True},
                    "created_at": {"$gte": last_24h}}},
        {"$group": {"_id": None, "avg": {"$avg": "$ai_triage.true_positive_score"}}},
    ]
    score_result = list(mongo.db.incidents.aggregate(score_pipeline))
    if score_result:
        triage_stats["avg_triage_score"] = round(score_result[0]["avg"], 1)

    return jsonify({
        "metrics": {
            "total_events_24h": total_events_24h,
            "open_incidents": open_incidents,
            "critical_incidents": critical_incidents,
            "active_agents": active_agents,
            "online_agents": online_agents,
        },
        "severity_distribution": severity_dist,
        "incident_trend": [{"date": r["_id"], "count": r["count"]} for r in incident_trend],
        "recent_incidents": recent_incidents,
        "asset_summary": asset_summary,
        "triage_stats": triage_stats,
    }), 200

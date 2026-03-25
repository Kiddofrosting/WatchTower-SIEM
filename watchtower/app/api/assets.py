"""
WatchTower SIEM - Asset Intelligence API
GET/PATCH asset profiles, asset summary for dashboard
"""

from datetime import datetime, timezone

from bson import ObjectId
from flask import Blueprint, jsonify, request

from watchtower.app import mongo
from watchtower.app.security import require_auth, require_roles, audit_log_action
from watchtower.app.models import UserRole

assets_bp = Blueprint("assets", __name__)


def _serialize(a: dict) -> dict:
    a["_id"] = str(a["_id"])
    for f in ("last_seen", "first_seen", "updated_at"):
        if isinstance(a.get(f), datetime):
            a[f] = a[f].isoformat()
    return a


@assets_bp.get("/")
@require_auth
def list_assets():
    query = {}
    if request.args.get("role"):
        query["role"] = request.args["role"]
    if request.args.get("criticality"):
        query["criticality"] = request.args["criticality"]
    if request.args.get("search"):
        term = request.args["search"]
        query["$or"] = [
            {"hostname": {"$regex": term, "$options": "i"}},
            {"owner": {"$regex": term, "$options": "i"}},
            {"department": {"$regex": term, "$options": "i"}},
            {"tags": {"$regex": term, "$options": "i"}},
        ]

    sort = request.args.get("sort", "criticality")
    sort_map = {
        "criticality": [("criticality_order", 1), ("hostname", 1)],
        "hostname": [("hostname", 1)],
        "last_seen": [("last_seen", -1)],
        "events": [("total_events_all_time", -1)],
    }

    # Add criticality sort order field via aggregation
    pipeline = [
        {"$match": query},
        {"$addFields": {
            "criticality_order": {
                "$switch": {
                    "branches": [
                        {"case": {"$eq": ["$criticality", "critical"]}, "then": 1},
                        {"case": {"$eq": ["$criticality", "high"]}, "then": 2},
                        {"case": {"$eq": ["$criticality", "medium"]}, "then": 3},
                        {"case": {"$eq": ["$criticality", "low"]}, "then": 4},
                    ],
                    "default": 5
                }
            }
        }},
        {"$sort": {"criticality_order": 1, "hostname": 1}},
    ]

    assets = list(mongo.db.assets.aggregate(pipeline))

    # Attach open incident count per host
    hostnames = [a["hostname"] for a in assets]
    open_counts = {}
    if hostnames:
        pipeline_counts = [
            {"$match": {"hostname": {"$in": hostnames}, "status": {"$in": ["open", "investigating"]}}},
            {"$group": {"_id": "$hostname", "count": {"$sum": 1}}},
        ]
        for r in mongo.db.incidents.aggregate(pipeline_counts):
            open_counts[r["_id"]] = r["count"]

    for a in assets:
        a["open_incidents"] = open_counts.get(a["hostname"], 0)
        a.pop("criticality_order", None)
        _serialize(a)

    return jsonify({"data": assets, "total": len(assets)}), 200


@assets_bp.get("/<hostname>")
@require_auth
def get_asset(hostname: str):
    asset = mongo.db.assets.find_one({"hostname": hostname})
    if not asset:
        return jsonify({"error": "not_found"}), 404

    # Recent incidents
    from datetime import timedelta
    recent_incidents = list(
        mongo.db.incidents.find(
            {"hostname": hostname},
            {"analyst_notes": 0, "timeline": 0, "ai_remediation": 0}
        ).sort("created_at", -1).limit(10)
    )
    for i in recent_incidents:
        i["_id"] = str(i["_id"])
        if isinstance(i.get("created_at"), datetime):
            i["created_at"] = i["created_at"].isoformat()

    # Event volume trend (last 7 days by day)
    now = datetime.now(timezone.utc)
    trend_pipeline = [
        {"$match": {"hostname": hostname, "timestamp": {"$gte": now - timedelta(days=7)}}},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}},
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}},
    ]
    event_trend = [{"date": r["_id"], "count": r["count"]}
                   for r in mongo.db.events.aggregate(trend_pipeline)]

    return jsonify({
        **_serialize(asset),
        "recent_incidents": recent_incidents,
        "event_trend_7d": event_trend,
    }), 200


@assets_bp.patch("/<hostname>")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.ANALYST)
def update_asset(hostname: str):
    """Manually set owner, role, criticality, tags, description."""
    from flask_jwt_extended import current_user

    asset = mongo.db.assets.find_one({"hostname": hostname})
    if not asset:
        return jsonify({"error": "not_found"}), 404

    data = request.get_json(silent=True) or {}
    allowed = {"owner", "owner_email", "department", "description", "tags"}
    updates = {k: v for k, v in data.items() if k in allowed}

    if "role" in data:
        updates["role"] = data["role"]
        updates["role_manually_set"] = True
    if "criticality" in data:
        updates["criticality"] = data["criticality"]
        updates["criticality_manually_set"] = True

    updates["updated_at"] = datetime.now(timezone.utc)

    mongo.db.assets.update_one({"hostname": hostname}, {"$set": updates})
    audit_log_action(current_user, "asset_updated", "asset", hostname,
                     {"fields": list(updates.keys())})
    return jsonify({"message": "Asset updated"}), 200


@assets_bp.get("/summary/overview")
@require_auth
def asset_overview():
    """Summary counts for the dashboard asset health widget."""
    by_criticality = list(mongo.db.assets.aggregate([
        {"$group": {"_id": "$criticality", "count": {"$sum": 1}}}
    ]))
    by_role = list(mongo.db.assets.aggregate([
        {"$group": {"_id": "$role", "count": {"$sum": 1}}}
    ]))
    total = mongo.db.assets.count_documents({})
    internet_facing = mongo.db.assets.count_documents({"is_internet_facing": True})
    unowned = mongo.db.assets.count_documents({"owner": {"$in": ["", None]}})

    return jsonify({
        "total_assets": total,
        "internet_facing": internet_facing,
        "unowned": unowned,
        "by_criticality": {r["_id"]: r["count"] for r in by_criticality},
        "by_role": {r["_id"]: r["count"] for r in by_role},
    }), 200

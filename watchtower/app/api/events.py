"""
WatchTower SIEM - Events API
Browse, search, and export security events.
"""

import csv
import io
from datetime import datetime, timezone

from bson import ObjectId
from flask import Blueprint, jsonify, request, stream_with_context, Response

from watchtower.app import mongo
from watchtower.app.models import EventFilterSchema
from watchtower.app.security import require_auth, require_roles, audit_log_action
from watchtower.app.models import UserRole

events_bp = Blueprint("events", __name__)
_filter_schema = EventFilterSchema()


def _build_query(filters: dict) -> dict:
    """Convert validated filter params into a MongoDB query."""
    query = {}

    if filters.get("hostname"):
        query["hostname"] = {"$regex": filters["hostname"], "$options": "i"}

    if filters.get("event_id") is not None:
        query["event_id"] = filters["event_id"]

    if filters.get("severity"):
        query["severity"] = filters["severity"]

    if filters.get("category"):
        query["category"] = filters["category"]

    if filters.get("start_time") or filters.get("end_time"):
        ts_filter = {}
        if filters.get("start_time"):
            ts_filter["$gte"] = filters["start_time"]
        if filters.get("end_time"):
            ts_filter["$lte"] = filters["end_time"]
        query["timestamp"] = ts_filter

    if filters.get("search"):
        term = filters["search"]
        query["$or"] = [
            {"message": {"$regex": term, "$options": "i"}},
            {"subject_username": {"$regex": term, "$options": "i"}},
            {"target_username": {"$regex": term, "$options": "i"}},
            {"process_name": {"$regex": term, "$options": "i"}},
            {"source_ip": {"$regex": term, "$options": "i"}},
            {"command_line": {"$regex": term, "$options": "i"}},
        ]

    return query


@events_bp.get("/")
@require_auth
def list_events():
    params = request.args.to_dict()
    errors = _filter_schema.validate(params)
    if errors:
        return jsonify({"error": "validation_error", "details": errors}), 422

    filters = _filter_schema.load(params)
    page = filters["page"]
    per_page = filters["per_page"]
    skip = (page - 1) * per_page

    sort_field = filters.get("sort_by", "timestamp")
    sort_dir = -1 if filters.get("sort_order", "desc") == "desc" else 1

    # Whitelist sort fields to prevent injection
    allowed_sort = {"timestamp", "hostname", "event_id", "severity", "category", "ingested_at"}
    if sort_field not in allowed_sort:
        sort_field = "timestamp"

    query = _build_query(filters)
    total = mongo.db.events.count_documents(query)
    cursor = (
        mongo.db.events.find(query, {"raw_event": 0})  # exclude raw to keep response lean
        .sort(sort_field, sort_dir)
        .skip(skip)
        .limit(per_page)
    )

    events = []
    for e in cursor:
        e["_id"] = str(e["_id"])
        e["agent_id"] = str(e.get("agent_id", ""))
        if isinstance(e.get("timestamp"), datetime):
            e["timestamp"] = e["timestamp"].isoformat()
        if isinstance(e.get("ingested_at"), datetime):
            e["ingested_at"] = e["ingested_at"].isoformat()
        events.append(e)

    return jsonify({
        "data": events,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": (total + per_page - 1) // per_page,
        }
    }), 200


@events_bp.get("/<event_id>")
@require_auth
def get_event(event_id: str):
    try:
        oid = ObjectId(event_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400

    event = mongo.db.events.find_one({"_id": oid})
    if not event:
        return jsonify({"error": "not_found"}), 404

    event["_id"] = str(event["_id"])
    event["agent_id"] = str(event.get("agent_id", ""))
    if isinstance(event.get("timestamp"), datetime):
        event["timestamp"] = event["timestamp"].isoformat()
    if isinstance(event.get("ingested_at"), datetime):
        event["ingested_at"] = event["ingested_at"].isoformat()

    return jsonify(event), 200


@events_bp.get("/export/csv")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.ANALYST)
def export_events_csv():
    """Stream a CSV export of filtered events (up to 50k)."""
    from flask_jwt_extended import current_user
    params = request.args.to_dict()
    filters = _filter_schema.load(_filter_schema.validate(params) or params)
    query = _build_query(filters)

    audit_log_action(current_user, "event_export", "events", "csv", {"query": str(query)[:500]})

    def generate():
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "timestamp", "hostname", "event_id", "category", "severity",
            "subject_username", "target_username", "process_name",
            "source_ip", "destination_ip", "message", "mitre_technique"
        ])
        yield output.getvalue()
        output.seek(0); output.truncate(0)

        cursor = mongo.db.events.find(query, {"raw_event": 0}).sort("timestamp", -1).limit(50000)
        for e in cursor:
            writer.writerow([
                e.get("timestamp", "").isoformat() if isinstance(e.get("timestamp"), datetime) else "",
                e.get("hostname", ""),
                e.get("event_id", ""),
                e.get("category", ""),
                e.get("severity", ""),
                e.get("subject_username", ""),
                e.get("target_username", ""),
                e.get("process_name", ""),
                e.get("source_ip", ""),
                e.get("destination_ip", ""),
                e.get("message", "")[:512],
                ",".join(e.get("mitre_technique", [])),
            ])
            yield output.getvalue()
            output.seek(0); output.truncate(0)

    return Response(
        stream_with_context(generate()),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=watchtower_events.csv"}
    )


@events_bp.get("/stats/summary")
@require_auth
def event_stats():
    """Aggregated event statistics for the dashboard."""
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    pipeline_severity = [
        {"$match": {"timestamp": {"$gte": last_24h}}},
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
    ]

    pipeline_category = [
        {"$match": {"timestamp": {"$gte": last_24h}}},
        {"$group": {"_id": "$category", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]

    pipeline_hourly = [
        {"$match": {"timestamp": {"$gte": last_24h}}},
        {"$group": {
            "_id": {
                "year": {"$year": "$timestamp"},
                "month": {"$month": "$timestamp"},
                "day": {"$dayOfMonth": "$timestamp"},
                "hour": {"$hour": "$timestamp"},
            },
            "count": {"$sum": 1},
        }},
        {"$sort": {"_id": 1}},
    ]

    pipeline_top_hosts = [
        {"$match": {"timestamp": {"$gte": last_24h}}},
        {"$group": {"_id": "$hostname", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]

    severity_counts = {r["_id"]: r["count"] for r in mongo.db.events.aggregate(pipeline_severity)}
    category_counts = list(mongo.db.events.aggregate(pipeline_category))
    hourly_trend = list(mongo.db.events.aggregate(pipeline_hourly))
    top_hosts = list(mongo.db.events.aggregate(pipeline_top_hosts))

    total_24h = mongo.db.events.count_documents({"timestamp": {"$gte": last_24h}})
    total_7d = mongo.db.events.count_documents({"timestamp": {"$gte": last_7d}})

    return jsonify({
        "total_24h": total_24h,
        "total_7d": total_7d,
        "by_severity": severity_counts,
        "by_category": [{"category": c["_id"], "count": c["count"]} for c in category_counts],
        "hourly_trend": [
            {
                "hour": f"{r['_id']['year']}-{r['_id']['month']:02d}-{r['_id']['day']:02d}T{r['_id']['hour']:02d}:00",
                "count": r["count"]
            } for r in hourly_trend
        ],
        "top_hosts": [{"hostname": h["_id"], "count": h["count"]} for h in top_hosts],
    }), 200

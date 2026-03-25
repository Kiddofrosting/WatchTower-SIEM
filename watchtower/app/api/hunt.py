"""
WatchTower SIEM - Threat Hunting API
=====================================
Saved hunt queries, ad-hoc search across events + incidents,
and investigation workbench helpers.

New endpoints:
  POST /api/v1/hunt/query          - Run an ad-hoc hunt query
  GET  /api/v1/hunt/saved          - List saved queries
  POST /api/v1/hunt/saved          - Save a query
  DELETE /api/v1/hunt/saved/:id    - Delete a saved query
  GET  /api/v1/hunt/investigate/:incident_id  - Full investigation workbench data
  GET  /api/v1/hunt/timeline/:hostname        - Host activity timeline
  GET  /api/v1/hunt/user-activity/:username   - All activity for a user across hosts
"""

from datetime import datetime, timedelta, timezone

from bson import ObjectId
from flask import Blueprint, jsonify, request

from watchtower.app import mongo
from watchtower.app.models import UserRole
from watchtower.app.security import require_auth, require_roles, audit_log_action

hunt_bp = Blueprint("hunt", __name__)


# ── Ad-hoc hunt query ────────────────────────────────────────────────────────

@hunt_bp.post("/query")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.ANALYST)
def run_hunt_query():
    """
    Run a structured hunt query against events.
    Body: {
      "hostname": "...",        # optional
      "username": "...",        # optional — searches subject/target username
      "process_name": "...",    # optional, supports partial match
      "command_line": "...",    # optional, supports partial match
      "source_ip": "...",       # optional
      "event_ids": [4625, ...], # optional
      "categories": ["authentication", ...],  # optional
      "mitre_technique": "T1110",  # optional
      "from": "ISO datetime",   # optional
      "to": "ISO datetime",     # optional
      "limit": 200
    }
    """
    from flask_jwt_extended import current_user
    data = request.get_json(silent=True) or {}
    limit = min(int(data.get("limit", 100)), 500)

    query = {}

    if data.get("hostname"):
        query["hostname"] = {"$regex": data["hostname"], "$options": "i"}
    if data.get("username"):
        term = data["username"]
        query["$or"] = [
            {"subject_username": {"$regex": term, "$options": "i"}},
            {"target_username": {"$regex": term, "$options": "i"}},
        ]
    if data.get("process_name"):
        query["process_name"] = {"$regex": data["process_name"], "$options": "i"}
    if data.get("command_line"):
        query["command_line"] = {"$regex": data["command_line"], "$options": "i"}
    if data.get("source_ip"):
        query["source_ip"] = data["source_ip"]
    if data.get("event_ids"):
        query["event_id"] = {"$in": data["event_ids"]}
    if data.get("categories"):
        query["category"] = {"$in": data["categories"]}
    if data.get("mitre_technique"):
        query["mitre_technique"] = data["mitre_technique"]

    ts_filter = {}
    if data.get("from"):
        try:
            ts_filter["$gte"] = datetime.fromisoformat(data["from"].replace("Z", "+00:00"))
        except Exception:
            pass
    if data.get("to"):
        try:
            ts_filter["$lte"] = datetime.fromisoformat(data["to"].replace("Z", "+00:00"))
        except Exception:
            pass
    if ts_filter:
        query["timestamp"] = ts_filter

    if not query:
        return jsonify({"error": "at least one filter is required"}), 422

    results = list(
        mongo.db.events.find(query, {"raw_event": 0})
        .sort("timestamp", -1)
        .limit(limit)
    )
    total = mongo.db.events.count_documents(query)

    for e in results:
        e["_id"] = str(e["_id"])
        if isinstance(e.get("timestamp"), datetime):
            e["timestamp"] = e["timestamp"].isoformat()
        if isinstance(e.get("ingested_at"), datetime):
            e["ingested_at"] = e["ingested_at"].isoformat()

    audit_log_action(current_user, "hunt_query", "events", "query",
                     {"query_keys": list(data.keys()), "results": len(results)})

    return jsonify({
        "results": results,
        "returned": len(results),
        "total_matching": total,
        "query": {k: v for k, v in data.items() if k != "limit"},
    }), 200


# ── Saved hunt queries ────────────────────────────────────────────────────────

@hunt_bp.get("/saved")
@require_auth
def list_saved_queries():
    from flask_jwt_extended import current_user
    # Return own + shared queries
    queries = list(mongo.db.saved_hunts.find({
        "$or": [
            {"owner_id": str(current_user["_id"])},
            {"shared": True},
        ]
    }).sort("created_at", -1))
    for q in queries:
        q["_id"] = str(q["_id"])
        if isinstance(q.get("created_at"), datetime):
            q["created_at"] = q["created_at"].isoformat()
    return jsonify({"data": queries, "total": len(queries)}), 200


@hunt_bp.post("/saved")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.ANALYST)
def save_query():
    from flask_jwt_extended import current_user
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    query_body = data.get("query")
    if not name or not query_body:
        return jsonify({"error": "name and query are required"}), 422

    doc = {
        "name": name[:128],
        "description": data.get("description", "")[:512],
        "query": query_body,
        "tags": data.get("tags", []),
        "shared": bool(data.get("shared", False)),
        "owner_id": str(current_user["_id"]),
        "owner_username": current_user["username"],
        "run_count": 0,
        "last_run": None,
        "created_at": datetime.now(timezone.utc),
    }
    result = mongo.db.saved_hunts.insert_one(doc)
    return jsonify({"message": "Query saved", "id": str(result.inserted_id)}), 201


@hunt_bp.delete("/saved/<query_id>")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.ANALYST)
def delete_saved_query(query_id: str):
    from flask_jwt_extended import current_user
    try:
        oid = ObjectId(query_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400

    q = mongo.db.saved_hunts.find_one({"_id": oid})
    if not q:
        return jsonify({"error": "not_found"}), 404

    # Only owner or admin can delete
    if q["owner_id"] != str(current_user["_id"]) and \
       current_user["role"] not in (UserRole.SUPER_ADMIN, UserRole.ADMIN):
        return jsonify({"error": "forbidden"}), 403

    mongo.db.saved_hunts.delete_one({"_id": oid})
    return jsonify({"message": "Query deleted"}), 200


# ── Investigation Workbench ────────────────────────────────────────────────────

@hunt_bp.get("/investigate/<incident_id>")
@require_auth
def investigation_workbench(incident_id: str):
    """
    Full investigation workbench for an incident.
    Returns everything an analyst needs in one call:
    - Incident detail with AI triage + remediation
    - All triggering events with full detail
    - All other incidents on the same host (last 72h)
    - All incidents involving the same usernames (last 72h)
    - Asset intelligence profile
    - Process tree (if Sysmon data available)
    - Correlation chain (if this is a chain incident)
    """
    try:
        oid = ObjectId(incident_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400

    inc = mongo.db.incidents.find_one({"_id": oid})
    if not inc:
        return jsonify({"error": "not_found"}), 404

    inc["_id"] = str(inc["_id"])
    for f in ("created_at", "updated_at", "resolved_at", "ai_remediation_generated_at"):
        if isinstance(inc.get(f), datetime):
            inc[f] = inc[f].isoformat()
    for tl in inc.get("timeline", []):
        if isinstance(tl.get("timestamp"), datetime):
            tl["timestamp"] = tl["timestamp"].isoformat()

    hostname = inc.get("hostname", "")
    now = datetime.now(timezone.utc)
    window_72h = now - timedelta(hours=72)

    # Triggering events
    triggering_events = []
    if inc.get("triggering_event_ids"):
        try:
            oids = [ObjectId(e) for e in inc["triggering_event_ids"][:50]]
            for ev in mongo.db.events.find({"_id": {"$in": oids}}):
                ev["_id"] = str(ev["_id"])
                if isinstance(ev.get("timestamp"), datetime):
                    ev["timestamp"] = ev["timestamp"].isoformat()
                triggering_events.append(ev)
        except Exception:
            pass

    # Collect usernames from triggering events
    usernames = set()
    for ev in triggering_events:
        if ev.get("subject_username") and not ev["subject_username"].endswith("$"):
            usernames.add(ev["subject_username"])
        if ev.get("target_username") and not ev["target_username"].endswith("$"):
            usernames.add(ev["target_username"])

    # Related incidents on same host
    host_incidents = list(
        mongo.db.incidents.find(
            {"hostname": hostname, "created_at": {"$gte": window_72h},
             "_id": {"$ne": oid}},
            {"analyst_notes": 0, "ai_remediation": 0}
        ).sort("created_at", -1).limit(20)
    )
    for i in host_incidents:
        i["_id"] = str(i["_id"])
        if isinstance(i.get("created_at"), datetime):
            i["created_at"] = i["created_at"].isoformat()

    # Related incidents by username across all hosts
    user_incidents = []
    if usernames:
        user_inc_raw = list(
            mongo.db.incidents.find(
                {"created_at": {"$gte": window_72h},
                 "_id": {"$ne": oid},
                 "$or": [
                     {"description": {"$regex": u, "$options": "i"}}
                     for u in list(usernames)[:5]
                 ]},
                {"analyst_notes": 0, "ai_remediation": 0}
            ).sort("created_at", -1).limit(10)
        )
        for i in user_inc_raw:
            i["_id"] = str(i["_id"])
            if isinstance(i.get("created_at"), datetime):
                i["created_at"] = i["created_at"].isoformat()
            user_incidents.append(i)

    # Asset profile
    asset = mongo.db.assets.find_one({"hostname": hostname}) or {}
    if asset.get("_id"):
        asset["_id"] = str(asset["_id"])
    for f in ("last_seen", "first_seen", "updated_at"):
        if isinstance(asset.get(f), datetime):
            asset[f] = asset[f].isoformat()

    # Process tree (events with parent_process on same host in ±1h window)
    process_tree = []
    if triggering_events:
        first_ts = triggering_events[0].get("timestamp")
        if first_ts:
            try:
                ts = datetime.fromisoformat(first_ts.replace("Z", "+00:00")) \
                    if isinstance(first_ts, str) else first_ts
                proc_events = list(
                    mongo.db.events.find(
                        {"hostname": hostname,
                         "category": "process_execution",
                         "timestamp": {"$gte": ts - timedelta(hours=1),
                                      "$lte": ts + timedelta(hours=1)}},
                        {"process_name": 1, "process_id": 1, "parent_process": 1,
                         "command_line": 1, "timestamp": 1, "subject_username": 1}
                    ).sort("timestamp", 1).limit(100)
                )
                for p in proc_events:
                    p["_id"] = str(p["_id"])
                    if isinstance(p.get("timestamp"), datetime):
                        p["timestamp"] = p["timestamp"].isoformat()
                    process_tree.append(p)
            except Exception:
                pass

    # Correlated chain incidents
    chain_members = []
    if inc.get("correlated_incident_ids"):
        for cid in inc["correlated_incident_ids"][:10]:
            try:
                ci = mongo.db.incidents.find_one(
                    {"_id": ObjectId(cid)},
                    {"title": 1, "severity": 1, "created_at": 1, "category": 1}
                )
                if ci:
                    ci["_id"] = str(ci["_id"])
                    if isinstance(ci.get("created_at"), datetime):
                        ci["created_at"] = ci["created_at"].isoformat()
                    chain_members.append(ci)
            except Exception:
                pass

    return jsonify({
        "incident": inc,
        "triggering_events": triggering_events,
        "host_incidents_72h": host_incidents,
        "user_incidents_72h": user_incidents,
        "involved_usernames": list(usernames),
        "asset_profile": asset,
        "process_tree": process_tree,
        "chain_members": chain_members,
    }), 200


# ── Host timeline ──────────────────────────────────────────────────────────────

@hunt_bp.get("/timeline/<hostname>")
@require_auth
def host_timeline(hostname: str):
    """
    Chronological activity timeline for a host — events + incidents interleaved.
    Useful for reconstructing exactly what happened on a machine.
    """
    hours = int(request.args.get("hours", 24))
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    events = list(
        mongo.db.events.find(
            {"hostname": hostname, "timestamp": {"$gte": since}},
            {"raw_event": 0}
        ).sort("timestamp", 1).limit(500)
    )
    for e in events:
        e["_id"] = str(e["_id"])
        e["_type"] = "event"
        if isinstance(e.get("timestamp"), datetime):
            e["timestamp"] = e["timestamp"].isoformat()

    incidents = list(
        mongo.db.incidents.find(
            {"hostname": hostname, "created_at": {"$gte": since}},
            {"analyst_notes": 0, "ai_remediation": 0, "triggering_event_ids": 0}
        ).sort("created_at", 1)
    )
    for i in incidents:
        i["_id"] = str(i["_id"])
        i["_type"] = "incident"
        i["timestamp"] = i["created_at"].isoformat() if isinstance(i.get("created_at"), datetime) else ""

    # Merge and sort by timestamp
    timeline = sorted(events + incidents, key=lambda x: x.get("timestamp", ""))

    return jsonify({
        "hostname": hostname,
        "hours": hours,
        "total_events": len(events),
        "total_incidents": len(incidents),
        "timeline": timeline,
    }), 200


# ── User activity pivot ────────────────────────────────────────────────────────

@hunt_bp.get("/user-activity/<username>")
@require_auth
def user_activity(username: str):
    """
    All activity for a username across all hosts — lateral movement pivot.
    """
    hours = int(request.args.get("hours", 72))
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    events = list(
        mongo.db.events.find(
            {"$or": [
                {"subject_username": {"$regex": f"^{username}$", "$options": "i"}},
                {"target_username": {"$regex": f"^{username}$", "$options": "i"}},
            ],
             "timestamp": {"$gte": since}},
            {"raw_event": 0}
        ).sort("timestamp", -1).limit(200)
    )
    for e in events:
        e["_id"] = str(e["_id"])
        if isinstance(e.get("timestamp"), datetime):
            e["timestamp"] = e["timestamp"].isoformat()

    # Hosts this user touched
    hosts_touched = list({e.get("hostname") for e in events if e.get("hostname")})

    # Events by host
    by_host = {}
    for e in events:
        h = e.get("hostname", "unknown")
        by_host.setdefault(h, 0)
        by_host[h] += 1

    return jsonify({
        "username": username,
        "hours": hours,
        "total_events": len(events),
        "hosts_touched": hosts_touched,
        "events_by_host": by_host,
        "events": events,
    }), 200

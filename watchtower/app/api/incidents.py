"""
WatchTower SIEM - Incidents API
Full incident lifecycle: CRUD, assignment, notes, AI remediation, bulk actions, SSE live updates.
"""

import json
from datetime import datetime, timezone

from bson import ObjectId
from flask import Blueprint, Response, jsonify, request, stream_with_context

from watchtower.app import mongo
from watchtower.app.models import IncidentUpdateSchema, IncidentStatus, UserRole
from watchtower.app.security import require_auth, require_roles, audit_log_action
from watchtower.app.services.ai_service import generate_remediation_async

incidents_bp = Blueprint("incidents", __name__)
_update_schema = IncidentUpdateSchema()


def _serialize_incident(inc: dict) -> dict:
    inc["_id"] = str(inc["_id"])
    for f in ("created_at", "updated_at", "resolved_at", "assigned_at", "ai_remediation_generated_at"):
        if isinstance(inc.get(f), datetime):
            inc[f] = inc[f].isoformat()
    inc["rule_id"] = str(inc.get("rule_id", ""))
    for tl in inc.get("timeline", []):
        if isinstance(tl.get("timestamp"), datetime):
            tl["timestamp"] = tl["timestamp"].isoformat()
    return inc


@incidents_bp.get("/")
@require_auth
def list_incidents():
    page = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 25)), 200)
    skip = (page - 1) * per_page

    query = {}
    if request.args.get("status"):
        query["status"] = request.args["status"]
    if request.args.get("severity"):
        query["severity"] = request.args["severity"]
    if request.args.get("hostname"):
        query["hostname"] = {"$regex": request.args["hostname"], "$options": "i"}
    if request.args.get("assigned_to"):
        query["assigned_to"] = request.args["assigned_to"]

    from flask_jwt_extended import current_user
    if current_user["role"] == UserRole.READ_ONLY:
        query["assigned_to"] = current_user["username"]

    total = mongo.db.incidents.count_documents(query)
    incidents = list(
        mongo.db.incidents.find(query)
        .sort("created_at", -1)
        .skip(skip)
        .limit(per_page)
    )

    return jsonify({
        "data": [_serialize_incident(i) for i in incidents],
        "pagination": {"page": page, "per_page": per_page, "total": total,
                       "pages": (total + per_page - 1) // per_page},
    }), 200


@incidents_bp.get("/<incident_id>")
@require_auth
def get_incident(incident_id: str):
    try:
        oid = ObjectId(incident_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400

    inc = mongo.db.incidents.find_one({"_id": oid})
    if not inc:
        return jsonify({"error": "not_found"}), 404
    return jsonify(_serialize_incident(inc)), 200


@incidents_bp.patch("/<incident_id>")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.ANALYST)
def update_incident(incident_id: str):
    from flask_jwt_extended import current_user
    try:
        oid = ObjectId(incident_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400

    inc = mongo.db.incidents.find_one({"_id": oid})
    if not inc:
        return jsonify({"error": "not_found"}), 404

    data = request.get_json(silent=True) or {}
    errors = _update_schema.validate(data)
    if errors:
        return jsonify({"error": "validation_error", "details": errors}), 422

    updates = {}
    timeline_entry = {
        "timestamp": datetime.now(timezone.utc),
        "actor": current_user["username"],
        "action": "updated",
        "detail": "",
    }

    if data.get("status"):
        old_status = inc["status"]
        updates["status"] = data["status"]
        timeline_entry["action"] = "status_changed"
        timeline_entry["detail"] = f"{old_status} → {data['status']}"
        if data["status"] in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED):
            updates["resolved_at"] = datetime.now(timezone.utc)
            if data.get("resolution_notes"):
                updates["resolution_notes"] = data["resolution_notes"]

    if data.get("assigned_to") is not None:
        updates["assigned_to"] = data["assigned_to"] or None
        updates["assigned_at"] = datetime.now(timezone.utc) if data["assigned_to"] else None
        timeline_entry["detail"] += f" assigned_to={data['assigned_to']}"

    if data.get("false_positive_reason"):
        updates["status"] = IncidentStatus.FALSE_POSITIVE
        updates["false_positive_reason"] = data["false_positive_reason"]
        # Auto-add suppression note to the triggering rule
        try:
            _record_fp_on_rule(inc.get("rule_id"), data["false_positive_reason"])
        except Exception:
            pass

    if updates:
        updates["updated_at"] = datetime.now(timezone.utc)
        mongo.db.incidents.update_one(
            {"_id": oid},
            {"$set": updates, "$push": {"timeline": timeline_entry}},
        )

    if data.get("note"):
        note = {
            "id": str(ObjectId()),
            "author": current_user["username"],
            "text": data["note"][:4096],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        mongo.db.incidents.update_one(
            {"_id": oid},
            {"$push": {"analyst_notes": note}, "$set": {"updated_at": datetime.now(timezone.utc)}}
        )

    audit_log_action(current_user, "incident_updated", "incident", incident_id,
                     {k: str(v) for k, v in updates.items() if k != "updated_at"})

    updated = mongo.db.incidents.find_one({"_id": oid})
    return jsonify(_serialize_incident(updated)), 200


def _record_fp_on_rule(rule_id: str, reason: str):
    """Append false-positive context to the triggering rule for analyst reference."""
    if not rule_id:
        return
    try:
        oid = ObjectId(rule_id)
        note = f"[FP {datetime.now(timezone.utc).date()}] {reason[:200]}"
        mongo.db.rules.update_one({"_id": oid}, {"$set": {"false_positive_notes": note}})
    except Exception:
        pass


# ── Bulk actions (NEW) ────────────────────────────────────────────────────────

@incidents_bp.post("/bulk")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.ANALYST)
def bulk_update_incidents():
    """
    Apply an action to multiple incidents at once.
    Body: { "ids": [...], "action": "close"|"assign"|"false_positive", "value": "..." }
    """
    from flask_jwt_extended import current_user
    data = request.get_json(silent=True) or {}
    ids = data.get("ids", [])
    action = data.get("action", "")
    value = data.get("value", "")

    if not ids or not action:
        return jsonify({"error": "ids and action are required"}), 422

    allowed_actions = {"close", "assign", "false_positive", "reopen"}
    if action not in allowed_actions:
        return jsonify({"error": f"action must be one of {sorted(allowed_actions)}"}), 422

    oids = []
    for raw_id in ids[:100]:  # cap at 100
        try:
            oids.append(ObjectId(raw_id))
        except Exception:
            pass

    if not oids:
        return jsonify({"error": "no valid ids provided"}), 422

    now = datetime.now(timezone.utc)
    updates = {"updated_at": now}
    timeline_entry = {"timestamp": now, "actor": current_user["username"], "action": f"bulk_{action}", "detail": value or ""}

    if action == "close":
        updates["status"] = IncidentStatus.CLOSED
        updates["resolved_at"] = now
    elif action == "assign":
        updates["assigned_to"] = value or None
        updates["assigned_at"] = now if value else None
    elif action == "false_positive":
        updates["status"] = IncidentStatus.FALSE_POSITIVE
        updates["false_positive_reason"] = value
    elif action == "reopen":
        updates["status"] = IncidentStatus.OPEN
        updates["resolved_at"] = None

    mongo.db.incidents.update_many(
        {"_id": {"$in": oids}},
        {"$set": updates, "$push": {"timeline": timeline_entry}},
    )

    audit_log_action(current_user, "incidents_bulk_updated", "incidents", "bulk",
                     {"action": action, "count": len(oids)})
    return jsonify({"updated": len(oids), "action": action}), 200


# ── AI Remediation (existing + SSE streaming) ────────────────────────────────

@incidents_bp.post("/<incident_id>/ai-remediation")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.ANALYST)
def request_ai_remediation(incident_id: str):
    from flask_jwt_extended import current_user
    try:
        oid = ObjectId(incident_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400

    inc = mongo.db.incidents.find_one({"_id": oid})
    if not inc:
        return jsonify({"error": "not_found"}), 404

    generate_remediation_async.delay(incident_id)
    audit_log_action(current_user, "ai_remediation_requested", "incident", incident_id, {})
    return jsonify({"message": "AI remediation generation queued"}), 202


@incidents_bp.get("/<incident_id>/ai-remediation/stream")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.ANALYST)
def stream_ai_remediation(incident_id: str):
    """
    NEW: Stream AI remediation tokens via Server-Sent Events.
    The client receives text chunks as they arrive from the LLM.
    """
    from flask import current_app
    try:
        oid = ObjectId(incident_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400

    inc = mongo.db.incidents.find_one({"_id": oid})
    if not inc:
        return jsonify({"error": "not_found"}), 404

    config = current_app.config

    def generate():
        provider = config.get("AI_PROVIDER", "anthropic")
        model = config.get("AI_MODEL", "claude-sonnet-4-6")

        from watchtower.app.services.ai_service import _build_incident_context, _build_prompt
        context = _build_incident_context(inc)
        prompt = _build_prompt(context)

        try:
            if provider == "anthropic":
                import anthropic
                api_key = config.get("ANTHROPIC_API_KEY", "")
                if not api_key:
                    yield "data: {\"error\": \"Anthropic API key not configured\"}\n\n"
                    return
                client = anthropic.Anthropic(api_key=api_key)
                with client.messages.stream(
                    model=model,
                    max_tokens=2048,
                    messages=[{"role": "user", "content": prompt}]
                ) as stream:
                    full_text = ""
                    for text in stream.text_stream:
                        full_text += text
                        yield f"data: {json.dumps({'delta': text})}\n\n"
                    # Persist to DB
                    mongo.db.incidents.update_one(
                        {"_id": oid},
                        {"$set": {
                            "ai_remediation": full_text,
                            "ai_remediation_generated_at": datetime.now(timezone.utc),
                            "updated_at": datetime.now(timezone.utc),
                        }}
                    )
                    yield "data: {\"done\": true}\n\n"
            else:
                # OpenAI streaming
                from openai import OpenAI
                api_key = config.get("OPENAI_API_KEY", "")
                if not api_key:
                    yield "data: {\"error\": \"OpenAI API key not configured\"}\n\n"
                    return
                client = OpenAI(api_key=api_key)
                stream = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=2048,
                    stream=True,
                )
                full_text = ""
                for chunk in stream:
                    delta = chunk.choices[0].delta.content or ""
                    full_text += delta
                    if delta:
                        yield f"data: {json.dumps({'delta': delta})}\n\n"
                mongo.db.incidents.update_one(
                    {"_id": oid},
                    {"$set": {
                        "ai_remediation": full_text,
                        "ai_remediation_generated_at": datetime.now(timezone.utc),
                        "updated_at": datetime.now(timezone.utc),
                    }}
                )
                yield "data: {\"done\": true}\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)[:200]})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )


# ── Stats, delete, export (unchanged) ────────────────────────────────────────

@incidents_bp.get("/stats/summary")
@require_auth
def incident_stats():
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    open_count = mongo.db.incidents.count_documents({"status": IncidentStatus.OPEN})
    investigating_count = mongo.db.incidents.count_documents({"status": IncidentStatus.INVESTIGATING})
    critical_open = mongo.db.incidents.count_documents({"status": IncidentStatus.OPEN, "severity": "critical"})
    new_24h = mongo.db.incidents.count_documents({"created_at": {"$gte": last_24h}})
    new_7d = mongo.db.incidents.count_documents({"created_at": {"$gte": last_7d}})

    by_severity = list(mongo.db.incidents.aggregate([
        {"$match": {"status": {"$in": [IncidentStatus.OPEN, IncidentStatus.INVESTIGATING]}}},
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
    ]))
    by_mitre = list(mongo.db.incidents.aggregate([
        {"$match": {"created_at": {"$gte": last_7d}}},
        {"$unwind": "$mitre_technique"},
        {"$group": {"_id": "$mitre_technique", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]))
    mttr = list(mongo.db.incidents.aggregate([
        {"$match": {"status": "resolved", "resolved_at": {"$gte": last_7d}}},
        {"$project": {"resolution_time": {"$subtract": ["$resolved_at", "$created_at"]}}},
        {"$group": {"_id": None, "avg_ms": {"$avg": "$resolution_time"}}},
    ]))
    avg_resolution_hours = round(mttr[0]["avg_ms"] / 3_600_000, 2) if mttr else None

    return jsonify({
        "open": open_count,
        "investigating": investigating_count,
        "critical_open": critical_open,
        "new_24h": new_24h,
        "new_7d": new_7d,
        "avg_resolution_hours": avg_resolution_hours,
        "by_severity": {r["_id"]: r["count"] for r in by_severity},
        "mitre_breakdown": [{"technique": r["_id"], "count": r["count"]} for r in by_mitre],
    }), 200


@incidents_bp.delete("/<incident_id>")
@require_roles(UserRole.SUPER_ADMIN)
def delete_incident(incident_id: str):
    from flask_jwt_extended import current_user
    try:
        oid = ObjectId(incident_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400

    inc = mongo.db.incidents.find_one({"_id": oid})
    if not inc:
        return jsonify({"error": "not_found"}), 404

    mongo.db.incidents.delete_one({"_id": oid})
    audit_log_action(current_user, "incident_deleted", "incident", incident_id, {})
    return jsonify({"message": "Incident deleted"}), 200


@incidents_bp.get("/<incident_id>/export")
@require_auth
def export_incident_pdf(incident_id: str):
    from flask import current_app, send_file
    from flask_jwt_extended import current_user
    try:
        oid = ObjectId(incident_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400

    inc = mongo.db.incidents.find_one({"_id": oid})
    if not inc:
        return jsonify({"error": "not_found"}), 404

    events = []
    if inc.get("triggering_event_ids"):
        event_oids = []
        for eid in inc["triggering_event_ids"][:50]:
            try:
                event_oids.append(ObjectId(eid))
            except Exception:
                pass
        if event_oids:
            raw_events = list(mongo.db.events.find({"_id": {"$in": event_oids}}))
            for e in raw_events:
                e["_id"] = str(e["_id"])
                if isinstance(e.get("timestamp"), datetime):
                    e["timestamp"] = e["timestamp"].isoformat()
                events.append(e)

    inc_serialized = _serialize_incident(inc)
    from watchtower.app.services.pdf_service import generate_incident_pdf
    org_name = current_app.config.get("ORG_NAME", "WatchTower SIEM")

    try:
        pdf_bytes = generate_incident_pdf(inc_serialized, events, org_name=org_name)
    except Exception as e:
        current_app.logger.error(f"PDF generation failed for incident {incident_id}: {e}")
        return jsonify({"error": "pdf_generation_failed", "message": str(e)}), 500

    safe_title = "".join(c if c.isalnum() or c in " -_" else "_"
                         for c in inc_serialized.get("title", "incident")[:40]).strip()
    filename = f"WatchTower_Incident_{incident_id[:8]}_{safe_title}.pdf"

    audit_log_action(current_user, "incident_exported", "incident", incident_id, {"format": "pdf"})

    import io
    return send_file(io.BytesIO(pdf_bytes), mimetype="application/pdf",
                     as_attachment=True, download_name=filename)

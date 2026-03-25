"""
WatchTower SIEM - Phase 1 API
Natural Language Hunt + Analyst Copilot + Time-Travel Investigation

Endpoints:
  POST /api/v1/copilot/nl-hunt              - Natural language event query
  POST /api/v1/copilot/explain/:incident_id - Explain incident in plain English
  GET  /api/v1/copilot/weekly-summary       - Executive prose summary
  GET  /api/v1/copilot/priority-queue       - What should I investigate next?
  POST /api/v1/copilot/is-normal            - Is this event normal for this host?
  POST /api/v1/copilot/draft-playbook/:id   - Generate containment playbook
  GET  /api/v1/copilot/compliance-impact/:id - Compliance control impact
  POST /api/v1/copilot/chat                 - Free-form conversational assistant

  GET  /api/v1/copilot/time-travel/snapshot       - Point-in-time host snapshot
  GET  /api/v1/copilot/time-travel/window         - Event window around a time
  GET  /api/v1/copilot/time-travel/diff/:id       - Before/after incident diff
  GET  /api/v1/copilot/time-travel/replay         - Step-by-step event replay
  GET  /api/v1/copilot/time-travel/blast-radius/:id - Blast radius analysis
"""

from datetime import datetime, timedelta, timezone

from bson import ObjectId
from flask import Blueprint, Response, current_app, jsonify, request, stream_with_context

from watchtower.app import mongo
from watchtower.app.models import UserRole
from watchtower.app.security import audit_log_action, require_auth, require_roles

copilot_bp = Blueprint("copilot", __name__)


def _cfg():
    return current_app.config


def _require_ai():
    """Return error response if AI is not configured."""
    if not (_cfg().get("ANTHROPIC_API_KEY") or _cfg().get("OPENAI_API_KEY")):
        return jsonify({
            "error": "ai_not_configured",
            "message": "Set ANTHROPIC_API_KEY or OPENAI_API_KEY in your .env to use AI features."
        }), 503
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Natural Language Hunt
# ─────────────────────────────────────────────────────────────────────────────

@copilot_bp.post("/nl-hunt")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.ANALYST)
def nl_hunt():
    """
    Translate a plain English question into a MongoDB query and execute it.
    Body: { "question": "Show me failed logins from external IPs today" }
    """
    from flask_jwt_extended import current_user
    err = _require_ai()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    question = (data.get("question") or "").strip()
    if not question:
        return jsonify({"error": "question is required"}), 422
    if len(question) > 500:
        return jsonify({"error": "question too long (max 500 chars)"}), 422

    from watchtower.app.services.nl_hunt import execute_nl_query
    result = execute_nl_query(question, _cfg(), mongo)

    audit_log_action(current_user, "nl_hunt", "events", "query",
                     {"question": question[:100], "results": result.get("result_count", 0)})

    return jsonify(result), 200 if not result.get("error") else 400


@copilot_bp.post("/nl-hunt/translate-only")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.ANALYST)
def nl_translate_only():
    """
    Translate a question to a query spec WITHOUT executing it.
    Useful for previewing what the query will do.
    """
    err = _require_ai()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    question = (data.get("question") or "").strip()
    if not question:
        return jsonify({"error": "question is required"}), 422

    from watchtower.app.services.nl_hunt import translate_nl_to_query
    spec = translate_nl_to_query(question, _cfg())
    return jsonify(spec), 200 if not spec.get("error") else 400


# ─────────────────────────────────────────────────────────────────────────────
# Analyst Copilot
# ─────────────────────────────────────────────────────────────────────────────

@copilot_bp.get("/explain/<incident_id>")
@require_auth
def explain_incident(incident_id: str):
    """Explain an incident in plain English for a junior analyst."""
    err = _require_ai()
    if err:
        return err

    try:
        oid = ObjectId(incident_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400

    inc = mongo.db.incidents.find_one({"_id": oid})
    if not inc:
        return jsonify({"error": "not_found"}), 404

    asset = mongo.db.assets.find_one({"hostname": inc.get("hostname", "")}) or {}

    from watchtower.app.services.analyst_copilot import explain_incident as _explain
    explanation = _explain(inc, asset, _cfg())

    return jsonify({
        "incident_id": incident_id,
        "explanation": explanation,
        "incident_title": inc.get("title"),
        "severity": inc.get("severity"),
    }), 200


@copilot_bp.get("/weekly-summary")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.ANALYST)
def weekly_summary():
    """Generate an executive prose summary of the week's security posture."""
    from flask_jwt_extended import current_user
    err = _require_ai()
    if err:
        return err

    days = int(request.args.get("days", 7))
    now = datetime.now(timezone.utc)
    period = now - timedelta(days=days)
    prev = period - timedelta(days=days)

    total_events = mongo.db.events.count_documents({"timestamp": {"$gte": period}})
    total_incidents = mongo.db.incidents.count_documents({"created_at": {"$gte": period}})
    critical = mongo.db.incidents.count_documents({"created_at": {"$gte": period}, "severity": "critical"})
    resolved = mongo.db.incidents.count_documents({
        "created_at": {"$gte": period},
        "status": {"$in": ["resolved", "closed", "false_positive"]}
    })
    auto_closed = mongo.db.incidents.count_documents({
        "created_at": {"$gte": period}, "ai_triage.auto_closed": True
    })
    prev_incidents = mongo.db.incidents.count_documents({"created_at": {"$gte": prev, "$lt": period}})
    prev_events = mongo.db.events.count_documents({"timestamp": {"$gte": prev, "$lt": period}})

    mttr_r = list(mongo.db.incidents.aggregate([
        {"$match": {"status": {"$in": ["resolved", "closed"]}, "created_at": {"$gte": period},
                    "resolved_at": {"$exists": True}}},
        {"$project": {"rt": {"$subtract": ["$resolved_at", "$created_at"]}}},
        {"$group": {"_id": None, "avg": {"$avg": "$rt"}}},
    ]))
    mttr = round(mttr_r[0]["avg"] / 3_600_000, 1) if mttr_r else None

    top_mitre = list(mongo.db.incidents.aggregate([
        {"$match": {"created_at": {"$gte": period}}},
        {"$unwind": "$mitre_technique"},
        {"$group": {"_id": "$mitre_technique", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}, {"$limit": 5},
    ]))
    top_hosts = list(mongo.db.incidents.aggregate([
        {"$match": {"created_at": {"$gte": period}}},
        {"$group": {"_id": "$hostname", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}, {"$limit": 5},
    ]))

    def pct(a, b):
        return round((a - b) / b * 100, 1) if b else None

    stats = {
        "total_events": total_events,
        "total_incidents": total_incidents,
        "critical_incidents": critical,
        "resolved_incidents": resolved,
        "auto_closed": auto_closed,
        "mttr_hours": mttr,
        "active_agents": mongo.db.agents.count_documents({"status": "active"}),
        "top_mitre": [{"technique": r["_id"], "count": r["count"]} for r in top_mitre],
        "top_hosts": [{"hostname": r["_id"], "count": r["count"]} for r in top_hosts],
        "incident_change_pct": pct(total_incidents, prev_incidents),
        "event_change_pct": pct(total_events, prev_events),
        "org_name": _cfg().get("ORG_NAME", "Organization"),
    }

    from watchtower.app.services.analyst_copilot import generate_weekly_summary
    summary = generate_weekly_summary(stats, _cfg())

    audit_log_action(current_user, "weekly_summary_generated", "copilot", "summary", {"days": days})
    return jsonify({"summary": summary, "stats": stats, "period_days": days}), 200


@copilot_bp.get("/priority-queue")
@require_auth
def priority_queue():
    """Recommend which open incidents to investigate first."""
    err = _require_ai()
    if err:
        return err

    open_incidents = list(mongo.db.incidents.find(
        {"status": {"$in": ["open", "investigating"]}},
        {"analyst_notes": 0, "ai_remediation": 0, "triggering_event_ids": 0}
    ).sort("created_at", -1).limit(20))

    if not open_incidents:
        return jsonify({"recommendation": "No open incidents.", "queue": []}), 200

    # Build asset lookup
    hostnames = list({i.get("hostname", "") for i in open_incidents})
    asset_map = {}
    for a in mongo.db.assets.find({"hostname": {"$in": hostnames}}):
        asset_map[a["hostname"]] = a

    from watchtower.app.services.analyst_copilot import get_priority_queue
    result = get_priority_queue(open_incidents, asset_map, _cfg())

    # Attach incident details to queue items
    inc_map = {str(i["_id"]): i for i in open_incidents}
    for item in result.get("queue", []):
        inc = inc_map.get(item.get("id"), {})
        if inc:
            item["title"] = inc.get("title", "")
            item["severity"] = inc.get("severity", "")
            item["hostname"] = inc.get("hostname", "")
            if isinstance(inc.get("created_at"), datetime):
                item["created_at"] = inc["created_at"].isoformat()

    return jsonify(result), 200


@copilot_bp.post("/is-normal")
@require_auth
def is_normal():
    """Check if a specific event is normal for its host."""
    err = _require_ai()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    event_id = data.get("event_id")
    if not event_id:
        return jsonify({"error": "event_id required"}), 422

    try:
        ev = mongo.db.events.find_one({"_id": ObjectId(event_id)}, {"raw_event": 0})
    except Exception:
        return jsonify({"error": "invalid_id"}), 400

    if not ev:
        return jsonify({"error": "event not found"}), 404

    hostname = ev.get("hostname", "")
    asset = mongo.db.assets.find_one({"hostname": hostname}) or {}
    baseline = mongo.db.baselines.find_one({"hostname": hostname}) or {}

    from watchtower.app.services.analyst_copilot import is_this_normal
    assessment = is_this_normal(ev, asset, baseline, _cfg())

    return jsonify({
        "event_id": event_id,
        "hostname": hostname,
        "assessment": assessment,
        "asset_known": bool(asset),
        "baseline_available": bool(baseline),
    }), 200


@copilot_bp.post("/draft-playbook/<incident_id>")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.ANALYST)
def draft_playbook(incident_id: str):
    """Generate a step-by-step containment playbook for an incident."""
    from flask_jwt_extended import current_user
    err = _require_ai()
    if err:
        return err

    try:
        oid = ObjectId(incident_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400

    inc = mongo.db.incidents.find_one({"_id": oid})
    if not inc:
        return jsonify({"error": "not_found"}), 404

    from watchtower.app.services.analyst_copilot import draft_playbook as _draft
    playbook = _draft(inc, _cfg())

    audit_log_action(current_user, "playbook_generated", "copilot", incident_id, {})
    return jsonify({
        "incident_id": incident_id,
        "incident_title": inc.get("title"),
        "playbook": playbook,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }), 200


@copilot_bp.get("/compliance-impact/<incident_id>")
@require_auth
def compliance_impact(incident_id: str):
    """Analyse which compliance controls this incident affects."""
    err = _require_ai()
    if err:
        return err

    try:
        oid = ObjectId(incident_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400

    inc = mongo.db.incidents.find_one({"_id": oid})
    if not inc:
        return jsonify({"error": "not_found"}), 404

    from watchtower.app.services.analyst_copilot import compliance_impact as _impact
    result = _impact(inc, _cfg())

    return jsonify({
        "incident_id": incident_id,
        "incident_title": inc.get("title"),
        **result,
    }), 200


@copilot_bp.post("/chat")
@require_auth
def copilot_chat():
    """Free-form conversational assistant with SIEM context."""
    err = _require_ai()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    history = data.get("history", [])  # [{role, content}]
    if not message:
        return jsonify({"error": "message is required"}), 422

    # Build SIEM context
    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)
    context = {
        "open_incidents": mongo.db.incidents.count_documents({"status": "open"}),
        "critical_incidents": mongo.db.incidents.count_documents(
            {"status": "open", "severity": "critical"}),
        "events_24h": mongo.db.events.count_documents({"timestamp": {"$gte": last_24h}}),
        "active_agents": mongo.db.agents.count_documents({"status": "active"}),
    }

    # Top category
    top_cat = list(mongo.db.events.aggregate([
        {"$match": {"timestamp": {"$gte": last_24h}}},
        {"$group": {"_id": "$category", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}, {"$limit": 1},
    ]))
    context["top_category"] = top_cat[0]["_id"] if top_cat else "none"

    # Highest triage score today
    max_score = list(mongo.db.incidents.aggregate([
        {"$match": {"created_at": {"$gte": last_24h},
                    "ai_triage.true_positive_score": {"$exists": True}}},
        {"$group": {"_id": None, "max": {"$max": "$ai_triage.true_positive_score"}}},
    ]))
    context["max_triage_score"] = max_score[0]["max"] if max_score else None

    from watchtower.app.services.analyst_copilot import copilot_chat as _chat
    response = _chat(message, context, history, _cfg())

    return jsonify({
        "response": response,
        "context_used": context,
    }), 200


@copilot_bp.get("/chat/stream")
@require_auth
def copilot_chat_stream():
    """Streaming version of the chat endpoint via SSE."""
    import json as _json
    err = _require_ai()
    if err:
        return err

    message = request.args.get("message", "").strip()
    if not message:
        return jsonify({"error": "message param required"}), 422

    config = _cfg()
    provider = config.get("AI_PROVIDER", "anthropic")
    model = config.get("AI_MODEL", "claude-sonnet-4-6")

    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)
    context = {
        "open_incidents": mongo.db.incidents.count_documents({"status": "open"}),
        "events_24h": mongo.db.events.count_documents({"timestamp": {"$gte": last_24h}}),
        "active_agents": mongo.db.agents.count_documents({"status": "active"}),
        "top_category": "unknown",
    }

    system = f"""You are WatchTower Copilot, an expert security analyst assistant.
Current open incidents: {context['open_incidents']}. Events today: {context['events_24h']:,}.
Active agents: {context['active_agents']}. Be concise, accurate, and security-focused."""

    def generate():
        try:
            if provider == "anthropic":
                import anthropic
                client = anthropic.Anthropic(api_key=config.get("ANTHROPIC_API_KEY", ""))
                with client.messages.stream(
                    model=model, max_tokens=800,
                    system=system,
                    messages=[{"role": "user", "content": message}]
                ) as stream:
                    for text in stream.text_stream:
                        yield f"data: {_json.dumps({'delta': text})}\n\n"
                    yield "data: {\"done\": true}\n\n"
            else:
                from openai import OpenAI
                client = OpenAI(api_key=config.get("OPENAI_API_KEY", ""))
                stream = client.chat.completions.create(
                    model=model, max_tokens=800, stream=True,
                    messages=[{"role": "system", "content": system},
                               {"role": "user", "content": message}]
                )
                for chunk in stream:
                    delta = chunk.choices[0].delta.content or ""
                    if delta:
                        yield f"data: {_json.dumps({'delta': delta})}\n\n"
                yield "data: {\"done\": true}\n\n"
        except Exception as e:
            yield f"data: {_json.dumps({'error': str(e)[:100]})}\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ─────────────────────────────────────────────────────────────────────────────
# Time-Travel Investigation
# ─────────────────────────────────────────────────────────────────────────────

@copilot_bp.get("/time-travel/snapshot")
@require_auth
def time_travel_snapshot():
    """
    Point-in-time host state snapshot.
    Params: hostname, at (ISO datetime)
    """
    hostname = request.args.get("hostname", "")
    at_str = request.args.get("at", "")
    if not hostname or not at_str:
        return jsonify({"error": "hostname and at params required"}), 422

    try:
        at_time = datetime.fromisoformat(at_str.replace("Z", "+00:00"))
    except Exception:
        return jsonify({"error": "invalid datetime format, use ISO 8601"}), 422

    from watchtower.app.services.time_travel import point_in_time_snapshot
    result = point_in_time_snapshot(hostname, at_time, mongo)
    return jsonify(result), 200


@copilot_bp.get("/time-travel/window")
@require_auth
def time_travel_window():
    """
    All events in a window around a point in time.
    Params: hostname, center (ISO datetime), before (minutes), after (minutes)
    """
    hostname = request.args.get("hostname", "")
    center_str = request.args.get("center", "")
    before = int(request.args.get("before", 60))
    after = int(request.args.get("after", 30))

    if not hostname or not center_str:
        return jsonify({"error": "hostname and center params required"}), 422
    if before > 1440 or after > 1440:
        return jsonify({"error": "window cannot exceed 24 hours (1440 minutes)"}), 422

    try:
        center = datetime.fromisoformat(center_str.replace("Z", "+00:00"))
    except Exception:
        return jsonify({"error": "invalid datetime format"}), 422

    from watchtower.app.services.time_travel import get_event_window
    return jsonify(get_event_window(hostname, center, before, after, mongo)), 200


@copilot_bp.get("/time-travel/diff/<incident_id>")
@require_auth
def time_travel_diff(incident_id: str):
    """Before/after state comparison for an incident."""
    try:
        oid = ObjectId(incident_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400

    inc = mongo.db.incidents.find_one({"_id": oid}, {"hostname": 1, "created_at": 1})
    if not inc:
        return jsonify({"error": "not_found"}), 404

    hostname = inc.get("hostname", "")
    inc_time = inc.get("created_at")
    if not isinstance(inc_time, datetime):
        return jsonify({"error": "incident has no created_at timestamp"}), 400

    from watchtower.app.services.time_travel import before_after_diff
    return jsonify(before_after_diff(hostname, inc_time, mongo)), 200


@copilot_bp.get("/time-travel/replay")
@require_auth
def time_travel_replay():
    """
    Step-by-step event replay for a host in a time window.
    Params: hostname, start (ISO datetime), end (ISO datetime)
    """
    hostname = request.args.get("hostname", "")
    start_str = request.args.get("start", "")
    end_str = request.args.get("end", "")
    if not all([hostname, start_str, end_str]):
        return jsonify({"error": "hostname, start, and end params required"}), 422

    try:
        start = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
        end = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
    except Exception:
        return jsonify({"error": "invalid datetime format"}), 422

    if (end - start).total_seconds() > 86400:
        return jsonify({"error": "replay window cannot exceed 24 hours"}), 422

    from watchtower.app.services.time_travel import get_event_replay
    return jsonify(get_event_replay(hostname, start, end, mongo)), 200


@copilot_bp.get("/time-travel/blast-radius/<incident_id>")
@require_auth
def blast_radius(incident_id: str):
    """Analyse what other hosts may have been affected by an incident."""
    try:
        oid = ObjectId(incident_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400

    inc = mongo.db.incidents.find_one({"_id": oid}, {"hostname": 1, "created_at": 1, "title": 1})
    if not inc:
        return jsonify({"error": "not_found"}), 404

    hostname = inc.get("hostname", "")
    inc_time = inc.get("created_at")
    if not isinstance(inc_time, datetime):
        return jsonify({"error": "incident has no timestamp"}), 400

    from watchtower.app.services.time_travel import get_blast_radius
    result = get_blast_radius(hostname, inc_time, mongo)
    result["incident_title"] = inc.get("title", "")
    return jsonify(result), 200

"""
WatchTower SIEM - Agents API
Agent registration, management, and health monitoring.
"""

from datetime import datetime, timezone

from bson import ObjectId
from flask import Blueprint, jsonify, request

from watchtower.app import mongo
from watchtower.app.models import AgentRegisterSchema, AgentStatus, UserRole, new_agent
from watchtower.app.security import (
    audit_log_action, generate_api_key, require_auth, require_roles
)

agents_bp = Blueprint("agents", __name__)
_reg_schema = AgentRegisterSchema()


@agents_bp.post("/register")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN)
def register_agent():
    from flask_jwt_extended import current_user
    data = request.get_json(silent=True) or {}
    errors = _reg_schema.validate(data)
    if errors:
        return jsonify({"error": "validation_error", "details": errors}), 422

    existing = mongo.db.agents.find_one({"hostname": data["hostname"], "status": "active"})
    if existing:
        return jsonify({"error": "hostname_already_registered",
                        "agent_id": str(existing["_id"])}), 409

    raw_key, key_hash, key_prefix = generate_api_key()
    agent_doc = new_agent(
        hostname=data["hostname"],
        ip_address=data["ip_address"],
        os_version=data["os_version"],
        api_key_hash=key_hash,
        api_key_prefix=key_prefix,
        registered_by=str(current_user["_id"]),
    )
    agent_doc["sysmon_installed"] = data.get("sysmon_installed", False)
    agent_doc["agent_version"] = data.get("agent_version", "1.0.0")

    result = mongo.db.agents.insert_one(agent_doc)
    audit_log_action(current_user, "agent_registered", "agent",
                     str(result.inserted_id), {"hostname": data["hostname"]})

    return jsonify({
        "agent_id": str(result.inserted_id),
        "hostname": data["hostname"],
        "api_key": raw_key,
        "message": "Store this API key securely. It will not be shown again.",
    }), 201


@agents_bp.get("/")
@require_auth
def list_agents():
    query = {}
    if request.args.get("status"):
        query["status"] = request.args["status"]

    agents = list(mongo.db.agents.find(query, {"api_key_hash": 0}).sort("hostname", 1))
    for a in agents:
        a["_id"] = str(a["_id"])
        for f in ("registered_at", "updated_at", "last_seen"):
            if isinstance(a.get(f), datetime):
                a[f] = a[f].isoformat()
    return jsonify({"data": agents, "total": len(agents)}), 200


@agents_bp.get("/<agent_id>")
@require_auth
def get_agent(agent_id: str):
    try:
        oid = ObjectId(agent_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400
    agent = mongo.db.agents.find_one({"_id": oid}, {"api_key_hash": 0})
    if not agent:
        return jsonify({"error": "not_found"}), 404
    agent["_id"] = str(agent["_id"])
    for f in ("registered_at", "updated_at", "last_seen"):
        if isinstance(agent.get(f), datetime):
            agent[f] = agent[f].isoformat()
    return jsonify(agent), 200


@agents_bp.patch("/<agent_id>")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN)
def update_agent(agent_id: str):
    from flask_jwt_extended import current_user
    try:
        oid = ObjectId(agent_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400

    data = request.get_json(silent=True) or {}
    allowed = {"description", "tags", "status", "config"}
    updates = {k: v for k, v in data.items() if k in allowed}
    if not updates:
        return jsonify({"error": "no_valid_fields"}), 422

    updates["updated_at"] = datetime.now(timezone.utc)
    mongo.db.agents.update_one({"_id": oid}, {"$set": updates})
    audit_log_action(current_user, "agent_updated", "agent", agent_id,
                     {"fields": list(updates.keys())})
    return jsonify({"message": "Agent updated"}), 200


@agents_bp.post("/<agent_id>/rotate-key")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN)
def rotate_agent_key(agent_id: str):
    from flask_jwt_extended import current_user
    try:
        oid = ObjectId(agent_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400

    if not mongo.db.agents.find_one({"_id": oid}):
        return jsonify({"error": "not_found"}), 404

    raw_key, key_hash, key_prefix = generate_api_key()
    mongo.db.agents.update_one(
        {"_id": oid},
        {"$set": {
            "api_key_hash": key_hash,
            "api_key_prefix": key_prefix,
            "updated_at": datetime.now(timezone.utc),
        }}
    )
    audit_log_action(current_user, "agent_key_rotated", "agent", agent_id, {})
    return jsonify({
        "api_key": raw_key,
        "message": "New API key generated. Store it securely.",
    }), 200


@agents_bp.delete("/<agent_id>")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN)
def decommission_agent(agent_id: str):
    from flask_jwt_extended import current_user
    try:
        oid = ObjectId(agent_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400

    result = mongo.db.agents.update_one(
        {"_id": oid},
        {"$set": {"status": AgentStatus.DECOMMISSIONED, "updated_at": datetime.now(timezone.utc)}}
    )
    if result.matched_count == 0:
        return jsonify({"error": "not_found"}), 404

    audit_log_action(current_user, "agent_decommissioned", "agent", agent_id, {})
    return jsonify({"message": "Agent decommissioned"}), 200

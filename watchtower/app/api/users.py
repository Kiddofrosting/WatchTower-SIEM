"""WatchTower SIEM - Users API"""
from datetime import datetime, timezone
from bson import ObjectId
from flask import Blueprint, jsonify, request
from watchtower.app import mongo
from watchtower.app.models import UserRole
from watchtower.app.security import require_roles, audit_log_action, require_auth

users_bp = Blueprint("users", __name__)


def _serialize_user(u):
    u["_id"] = str(u["_id"])
    u.pop("password_hash", None)
    u.pop("mfa_secret", None)
    u.pop("mfa_backup_codes", None)
    u.pop("mfa_secret_pending", None)
    for f in ("created_at", "updated_at", "last_login", "password_changed_at", "locked_until"):
        if isinstance(u.get(f), datetime):
            u[f] = u[f].isoformat()
    return u


@users_bp.get("/")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN)
def list_users():
    users = list(mongo.db.users.find({}, {"password_hash": 0, "mfa_secret": 0}))
    return jsonify({"data": [_serialize_user(u) for u in users]}), 200


@users_bp.get("/<user_id>")
@require_auth
def get_user(user_id: str):
    from flask_jwt_extended import current_user
    try:
        oid = ObjectId(user_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400
    if str(current_user["_id"]) != user_id and current_user["role"] not in (UserRole.SUPER_ADMIN, UserRole.ADMIN):
        return jsonify({"error": "forbidden"}), 403
    user = mongo.db.users.find_one({"_id": oid}, {"password_hash": 0, "mfa_secret": 0})
    if not user:
        return jsonify({"error": "not_found"}), 404
    return jsonify(_serialize_user(user)), 200


@users_bp.patch("/<user_id>")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN)
def update_user(user_id: str):
    from flask_jwt_extended import current_user
    try:
        oid = ObjectId(user_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400
    data = request.get_json(silent=True) or {}
    allowed = {"full_name", "is_active", "role", "preferences"}
    if "role" in data and data["role"] == UserRole.SUPER_ADMIN and current_user["role"] != UserRole.SUPER_ADMIN:
        return jsonify({"error": "forbidden"}), 403
    updates = {k: v for k, v in data.items() if k in allowed}
    updates["updated_at"] = datetime.now(timezone.utc)
    mongo.db.users.update_one({"_id": oid}, {"$set": updates})
    audit_log_action(current_user, "user_updated", "user", user_id, {"fields": list(updates.keys())})
    return jsonify({"message": "User updated"}), 200


@users_bp.delete("/<user_id>")
@require_roles(UserRole.SUPER_ADMIN)
def delete_user(user_id: str):
    from flask_jwt_extended import current_user
    try:
        oid = ObjectId(user_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400
    if str(current_user["_id"]) == user_id:
        return jsonify({"error": "cannot_delete_self"}), 400
    mongo.db.users.update_one({"_id": oid}, {"$set": {"is_active": False, "updated_at": datetime.now(timezone.utc)}})
    audit_log_action(current_user, "user_deactivated", "user", user_id, {})
    return jsonify({"message": "User deactivated"}), 200


@users_bp.get("/audit-log")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN)
def get_audit_log():
    page = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 50)), 500)
    skip = (page - 1) * per_page
    query = {}
    if request.args.get("user_id"):
        query["user_id"] = request.args["user_id"]
    if request.args.get("action"):
        query["action"] = request.args["action"]
    total = mongo.db.audit_log.count_documents(query)
    logs = list(mongo.db.audit_log.find(query).sort("timestamp", -1).skip(skip).limit(per_page))
    for log in logs:
        log["_id"] = str(log["_id"])
        if isinstance(log.get("timestamp"), datetime):
            log["timestamp"] = log["timestamp"].isoformat()
    return jsonify({"data": logs, "pagination": {"page": page, "per_page": per_page, "total": total}}), 200

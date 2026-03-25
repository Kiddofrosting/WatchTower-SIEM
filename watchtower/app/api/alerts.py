"""WatchTower SIEM - Alerts/Notifications API"""
from datetime import datetime, timezone
from bson import ObjectId
from flask import Blueprint, jsonify, request
from watchtower.app import mongo
from watchtower.app.security import require_auth

alerts_bp = Blueprint("alerts", __name__)


@alerts_bp.get("/notifications")
@require_auth
def get_notifications():
    from flask_jwt_extended import current_user
    user_id = str(current_user["_id"])
    unread_only = request.args.get("unread_only", "false").lower() == "true"
    query = {"user_id": user_id}
    if unread_only:
        query["read"] = False
    notifications = list(mongo.db.notifications.find(query).sort("created_at", -1).limit(50))
    for n in notifications:
        n["_id"] = str(n["_id"])
        if isinstance(n.get("created_at"), datetime):
            n["created_at"] = n["created_at"].isoformat()
    unread_count = mongo.db.notifications.count_documents({"user_id": user_id, "read": False})
    return jsonify({"data": notifications, "unread_count": unread_count}), 200


@alerts_bp.post("/notifications/<notif_id>/read")
@require_auth
def mark_read(notif_id: str):
    from flask_jwt_extended import current_user
    try:
        oid = ObjectId(notif_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400
    mongo.db.notifications.update_one(
        {"_id": oid, "user_id": str(current_user["_id"])},
        {"$set": {"read": True}}
    )
    return jsonify({"message": "Marked as read"}), 200


@alerts_bp.post("/notifications/read-all")
@require_auth
def mark_all_read():
    from flask_jwt_extended import current_user
    mongo.db.notifications.update_many(
        {"user_id": str(current_user["_id"]), "read": False},
        {"$set": {"read": True}}
    )
    return jsonify({"message": "All notifications marked as read"}), 200

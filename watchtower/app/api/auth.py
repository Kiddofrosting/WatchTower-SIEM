"""
WatchTower SIEM - Authentication API
JWT-based login, logout, refresh, MFA, password management, password reset.
"""

import secrets
from datetime import datetime, timedelta, timezone

from bson import ObjectId
from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
)

from watchtower.app import limiter, mongo
from watchtower.app.models import LoginSchema, RegisterUserSchema, ChangePasswordSchema, UserRole, new_user
from watchtower.app.security import (
    audit_log_action,
    check_password,
    generate_backup_codes,
    generate_mfa_secret,
    get_mfa_uri,
    hash_password,
    require_auth,
    require_roles,
    sanitize_input,
    validate_password_policy,
    verify_mfa_code,
)

auth_bp = Blueprint("auth", __name__)

login_schema = LoginSchema()
register_schema = RegisterUserSchema()
change_pw_schema = ChangePasswordSchema()


@auth_bp.post("/login")
@limiter.limit("10 per minute")
def login():
    data = request.get_json(silent=True) or {}
    errors = login_schema.validate(data)
    if errors:
        return jsonify({"error": "validation_error", "details": errors}), 422

    username = data["username"].lower().strip()
    password = data["password"]
    mfa_code = data.get("mfa_code")

    user = mongo.db.users.find_one({
        "$or": [{"username": username}, {"email": username}],
        "is_active": True,
    })

    if not user:
        return jsonify({"error": "invalid_credentials"}), 401

    if user.get("locked_until") and user["locked_until"] > datetime.now(timezone.utc):
        remaining = int((user["locked_until"] - datetime.now(timezone.utc)).total_seconds() / 60)
        return jsonify({"error": "account_locked", "message": f"Account locked. Try again in {remaining} minutes."}), 423

    if not check_password(password, user["password_hash"]):
        attempts = user.get("failed_login_attempts", 0) + 1
        max_attempts = current_app.config["MAX_LOGIN_ATTEMPTS"]
        update = {"$set": {"failed_login_attempts": attempts, "updated_at": datetime.now(timezone.utc)}}

        if attempts >= max_attempts:
            lockout_until = datetime.now(timezone.utc) + timedelta(minutes=current_app.config["LOCKOUT_DURATION_MINUTES"])
            update["$set"]["locked_until"] = lockout_until

        mongo.db.users.update_one({"_id": user["_id"]}, update)
        return jsonify({"error": "invalid_credentials"}), 401

    if user.get("mfa_enabled"):
        if not mfa_code:
            return jsonify({"error": "mfa_required", "message": "MFA code required"}), 401

        backup_used = False
        if mfa_code in user.get("mfa_backup_codes", []):
            mongo.db.users.update_one({"_id": user["_id"]}, {"$pull": {"mfa_backup_codes": mfa_code}})
            backup_used = True
        elif not verify_mfa_code(user["mfa_secret"], mfa_code):
            return jsonify({"error": "invalid_mfa_code"}), 401

    client_ip = request.remote_addr
    mongo.db.users.update_one(
        {"_id": user["_id"]},
        {"$set": {
            "failed_login_attempts": 0,
            "locked_until": None,
            "last_login": datetime.now(timezone.utc),
            "last_login_ip": client_ip,
            "updated_at": datetime.now(timezone.utc),
        }}
    )

    access_token = create_access_token(identity=user)
    refresh_token = create_refresh_token(identity=user)
    audit_log_action(user, "login", "user", str(user["_id"]), {"ip": client_ip})

    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {
            "id": str(user["_id"]),
            "username": user["username"],
            "email": user["email"],
            "full_name": user.get("full_name", ""),
            "role": user["role"],
            "mfa_enabled": user.get("mfa_enabled", False),
            "must_change_password": user.get("must_change_password", False),
            "preferences": user.get("preferences", {}),
        }
    }), 200


@auth_bp.post("/refresh")
@jwt_required(refresh=True)
def refresh():
    from flask_jwt_extended import current_user
    if not current_user:
        return jsonify({"error": "unauthorized"}), 401
    access_token = create_access_token(identity=current_user)
    return jsonify({"access_token": access_token}), 200


@auth_bp.post("/logout")
@require_auth
def logout():
    jti = get_jwt()["jti"]
    exp = get_jwt()["exp"]
    mongo.db.token_blocklist.insert_one({
        "jti": jti,
        "expires_at": datetime.fromtimestamp(exp, tz=timezone.utc),
    })
    from flask_jwt_extended import current_user
    audit_log_action(current_user, "logout", "user", str(current_user["_id"]), {})
    return jsonify({"message": "Logged out successfully"}), 200


@auth_bp.post("/register")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN)
def register_user():
    from flask_jwt_extended import current_user
    data = request.get_json(silent=True) or {}
    errors = register_schema.validate(data)
    if errors:
        return jsonify({"error": "validation_error", "details": errors}), 422

    if mongo.db.users.find_one({"username": data["username"].lower()}):
        return jsonify({"error": "username_taken"}), 409
    if mongo.db.users.find_one({"email": data["email"].lower()}):
        return jsonify({"error": "email_taken"}), 409

    valid, msg = validate_password_policy(data["password"])
    if not valid:
        return jsonify({"error": "weak_password", "message": msg}), 422

    if data.get("role") == UserRole.SUPER_ADMIN and current_user["role"] != UserRole.SUPER_ADMIN:
        return jsonify({"error": "forbidden", "message": "Cannot assign super_admin role"}), 403

    user_doc = new_user(
        username=data["username"],
        email=data["email"],
        password_hash=hash_password(data["password"]),
        role=data.get("role", UserRole.ANALYST),
        full_name=data.get("full_name", ""),
        created_by=str(current_user["_id"]),
    )
    result = mongo.db.users.insert_one(user_doc)
    audit_log_action(current_user, "user_created", "user", str(result.inserted_id),
                     {"new_username": data["username"], "role": data.get("role")})
    return jsonify({"message": "User created", "user_id": str(result.inserted_id)}), 201


@auth_bp.post("/change-password")
@require_auth
def change_password():
    from flask_jwt_extended import current_user
    data = request.get_json(silent=True) or {}
    errors = change_pw_schema.validate(data)
    if errors:
        return jsonify({"error": "validation_error", "details": errors}), 422

    if not check_password(data["current_password"], current_user["password_hash"]):
        return jsonify({"error": "invalid_current_password"}), 401

    valid, msg = validate_password_policy(data["new_password"])
    if not valid:
        return jsonify({"error": "weak_password", "message": msg}), 422

    mongo.db.users.update_one(
        {"_id": current_user["_id"]},
        {"$set": {
            "password_hash": hash_password(data["new_password"]),
            "password_changed_at": datetime.now(timezone.utc),
            "must_change_password": False,
            "updated_at": datetime.now(timezone.utc),
        }}
    )
    audit_log_action(current_user, "password_changed", "user", str(current_user["_id"]), {})
    return jsonify({"message": "Password changed successfully"}), 200


# ── Password Reset Flow (NEW) ─────────────────────────────────────────────────

@auth_bp.post("/forgot-password")
@limiter.limit("5 per hour")
def forgot_password():
    """
    Generate a password reset token and email it to the user.
    Always returns 200 to avoid user enumeration.
    """
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").lower().strip()
    if not email:
        return jsonify({"message": "If that email exists, a reset link has been sent."}), 200

    user = mongo.db.users.find_one({"email": email, "is_active": True})
    if user:
        token = secrets.token_urlsafe(48)
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        mongo.db.password_reset_tokens.update_one(
            {"user_id": str(user["_id"])},
            {"$set": {
                "user_id": str(user["_id"]),
                "token": token,
                "expires_at": expires,
                "used": False,
            }},
            upsert=True,
        )
        # Send reset email
        try:
            from flask_mail import Message
            from watchtower.app import mail
            base_url = current_app.config.get("BASE_URL", "http://localhost:5000")
            reset_link = f"{base_url}/dashboard/reset-password?token={token}"
            msg = Message(
                subject="WatchTower SIEM — Password Reset Request",
                recipients=[user["email"]],
                html=f"""
<p>Hello {user.get('username', '')},</p>
<p>A password reset was requested for your WatchTower SIEM account.
Click below to reset your password. This link expires in 1 hour.</p>
<p><a href="{reset_link}">Reset Password</a></p>
<p>If you did not request this, you can safely ignore this email.</p>
<p><small>WatchTower SIEM &mdash; {current_app.config.get('ORG_NAME','')}</small></p>
""",
            )
            mail.send(msg)
        except Exception as e:
            current_app.logger.error(f"Password reset email failed: {e}")

    return jsonify({"message": "If that email exists, a reset link has been sent."}), 200


@auth_bp.post("/reset-password")
@limiter.limit("10 per hour")
def reset_password():
    """Consume a reset token and set a new password."""
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    new_password = data.get("new_password", "")

    if not token or not new_password:
        return jsonify({"error": "token and new_password are required"}), 422

    record = mongo.db.password_reset_tokens.find_one({
        "token": token,
        "used": False,
        "expires_at": {"$gt": datetime.now(timezone.utc)},
    })
    if not record:
        return jsonify({"error": "invalid_or_expired_token"}), 400

    valid, msg = validate_password_policy(new_password)
    if not valid:
        return jsonify({"error": "weak_password", "message": msg}), 422

    from bson import ObjectId as OID
    mongo.db.users.update_one(
        {"_id": OID(record["user_id"])},
        {"$set": {
            "password_hash": hash_password(new_password),
            "password_changed_at": datetime.now(timezone.utc),
            "must_change_password": False,
            "failed_login_attempts": 0,
            "locked_until": None,
            "updated_at": datetime.now(timezone.utc),
        }}
    )
    mongo.db.password_reset_tokens.update_one({"_id": record["_id"]}, {"$set": {"used": True}})
    return jsonify({"message": "Password reset successfully. Please log in."}), 200


# ── MFA endpoints (unchanged) ─────────────────────────────────────────────────

@auth_bp.post("/mfa/setup")
@require_auth
def setup_mfa():
    from flask_jwt_extended import current_user
    secret = generate_mfa_secret()
    uri = get_mfa_uri(current_user["username"], secret)
    mongo.db.users.update_one(
        {"_id": current_user["_id"]},
        {"$set": {"mfa_secret_pending": secret, "updated_at": datetime.now(timezone.utc)}}
    )
    return jsonify({"secret": secret, "otpauth_uri": uri}), 200


@auth_bp.post("/mfa/verify-setup")
@require_auth
def verify_mfa_setup():
    from flask_jwt_extended import current_user
    data = request.get_json(silent=True) or {}
    code = sanitize_input(data.get("code", ""), 10)
    user = mongo.db.users.find_one({"_id": current_user["_id"]})
    pending_secret = user.get("mfa_secret_pending")
    if not pending_secret:
        return jsonify({"error": "no_pending_mfa_setup"}), 400
    if not verify_mfa_code(pending_secret, code):
        return jsonify({"error": "invalid_code"}), 400
    backup_codes = generate_backup_codes()
    mongo.db.users.update_one(
        {"_id": current_user["_id"]},
        {"$set": {
            "mfa_enabled": True,
            "mfa_secret": pending_secret,
            "mfa_backup_codes": backup_codes,
            "updated_at": datetime.now(timezone.utc),
        }, "$unset": {"mfa_secret_pending": ""}}
    )
    audit_log_action(current_user, "mfa_enabled", "user", str(current_user["_id"]), {})
    return jsonify({
        "message": "MFA enabled successfully",
        "backup_codes": backup_codes,
        "warning": "Save these backup codes securely. They will not be shown again.",
    }), 200


@auth_bp.post("/mfa/disable")
@require_auth
def disable_mfa():
    from flask_jwt_extended import current_user
    data = request.get_json(silent=True) or {}
    code = sanitize_input(data.get("code", ""), 10)
    password = data.get("password", "")
    user = mongo.db.users.find_one({"_id": current_user["_id"]})
    if not check_password(password, user["password_hash"]):
        return jsonify({"error": "invalid_password"}), 401
    if not verify_mfa_code(user.get("mfa_secret", ""), code):
        return jsonify({"error": "invalid_mfa_code"}), 400
    mongo.db.users.update_one(
        {"_id": current_user["_id"]},
        {"$set": {"mfa_enabled": False, "mfa_secret": None, "mfa_backup_codes": [], "updated_at": datetime.now(timezone.utc)}}
    )
    audit_log_action(current_user, "mfa_disabled", "user", str(current_user["_id"]), {})
    return jsonify({"message": "MFA disabled"}), 200


@auth_bp.get("/me")
@require_auth
def get_me():
    from flask_jwt_extended import current_user
    u = current_user
    return jsonify({
        "id": str(u["_id"]),
        "username": u["username"],
        "email": u["email"],
        "full_name": u.get("full_name", ""),
        "role": u["role"],
        "mfa_enabled": u.get("mfa_enabled", False),
        "last_login": u.get("last_login").isoformat() if u.get("last_login") else None,
        "preferences": u.get("preferences", {}),
    }), 200

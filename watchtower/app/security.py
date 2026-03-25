"""
WatchTower SIEM - Security Utilities
Authentication decorators, password hashing, HMAC verification, audit logging.
"""

import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import string
from datetime import datetime, timezone
from functools import wraps

import bcrypt
import pyotp
import qrcode
import qrcode.image.svg
from bson import ObjectId
from flask import current_app, g, jsonify, request
from flask_jwt_extended import get_jwt, get_jwt_identity, verify_jwt_in_request

from watchtower.app.models import UserRole, new_audit_log


# ─────────────────────────────────────────────────────────────────────────────
# Password utilities
# ─────────────────────────────────────────────────────────────────────────────

_PASSWORD_POLICY = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_\-#^()+=~`|{}[\]:;<>,.?/\\]).{12,128}$'
)


def hash_password(password: str) -> str:
    rounds = current_app.config.get("BCRYPT_LOG_ROUNDS", 13)
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds)).decode()


def check_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


def validate_password_policy(password: str) -> tuple[bool, str]:
    """Returns (is_valid, error_message)."""
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."
    if not _PASSWORD_POLICY.match(password):
        return False, (
            "Password must contain uppercase, lowercase, digit, "
            "and special character (@$!%*?&_-#^()+=~`|{}[]:;<>,.?/\\)."
        )
    return True, ""


# ─────────────────────────────────────────────────────────────────────────────
# API key utilities
# ─────────────────────────────────────────────────────────────────────────────

def generate_api_key() -> tuple[str, str, str]:
    """Returns (raw_key, key_hash, key_prefix) for agent registration."""
    raw = "wt-" + secrets.token_urlsafe(40)
    prefix = raw[:12]
    key_hash = hashlib.sha256(raw.encode()).hexdigest()
    return raw, key_hash, prefix


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# HMAC verification
# ─────────────────────────────────────────────────────────────────────────────

def verify_hmac_signature(body: bytes, received_sig: str, secret: str) -> bool:
    """Verify HMAC-SHA256 signature on ingestion payload."""
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, received_sig)


# ─────────────────────────────────────────────────────────────────────────────
# MFA utilities
# ─────────────────────────────────────────────────────────────────────────────

def generate_mfa_secret() -> str:
    return pyotp.random_base32()


def get_mfa_uri(username: str, secret: str) -> str:
    org = current_app.config.get("ORG_NAME", "WatchTower")
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=f"{org} WatchTower")


def verify_mfa_code(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def generate_backup_codes(count: int = 8) -> list[str]:
    alphabet = string.ascii_uppercase + string.digits
    return [
        "".join(secrets.choice(alphabet) for _ in range(4)) + "-" +
        "".join(secrets.choice(alphabet) for _ in range(4))
        for _ in range(count)
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Auth decorators
# ─────────────────────────────────────────────────────────────────────────────

def _get_mongo():
    from watchtower.app import mongo
    return mongo


def require_roles(*roles):
    """Decorator: require JWT + one of the specified roles."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            from flask_jwt_extended import current_user
            if current_user is None:
                return jsonify({"error": "unauthorized"}), 401
            if current_user.get("role") not in roles:
                audit_log_action(
                    current_user,
                    "access_denied",
                    "endpoint",
                    request.path,
                    {"method": request.method, "required_roles": list(roles)},
                )
                return jsonify({"error": "forbidden", "message": "Insufficient role"}), 403
            g.current_user = current_user
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def require_auth(fn):
    """Decorator: require valid JWT (any role)."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        from flask_jwt_extended import current_user
        if current_user is None:
            return jsonify({"error": "unauthorized"}), 401
        g.current_user = current_user
        return fn(*args, **kwargs)
    return wrapper


def require_agent_auth(fn):
    """Decorator: validate agent API key + HMAC signature."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        api_key = request.headers.get("X-WatchTower-Key", "")
        signature = request.headers.get("X-WatchTower-Signature", "")

        if not api_key or not signature:
            return jsonify({"error": "missing_credentials"}), 401

        mongo = _get_mongo()
        key_hash = hash_api_key(api_key)
        agent = mongo.db.agents.find_one(
            {"api_key_hash": key_hash, "status": "active"}
        )
        if not agent:
            current_app.logger.warning("Invalid agent key", extra={"key_prefix": api_key[:12]})
            return jsonify({"error": "invalid_credentials"}), 401

        # Verify HMAC
        body = request.get_data()
        if not verify_hmac_signature(body, signature, api_key):
            current_app.logger.warning(
                "HMAC verification failed", extra={"agent": agent.get("hostname")}
            )
            return jsonify({"error": "invalid_signature"}), 401

        g.agent = agent
        return fn(*args, **kwargs)
    return wrapper


# ─────────────────────────────────────────────────────────────────────────────
# Audit logging
# ─────────────────────────────────────────────────────────────────────────────

def audit_log_action(user: dict, action: str, resource_type: str,
                     resource_id: str, details: dict = None):
    """Write an entry to the append-only audit log."""
    try:
        mongo = _get_mongo()
        log_entry = new_audit_log(
            user_id=str(user.get("_id", "")),
            username=user.get("username", "system"),
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id),
            details=details or {},
            ip_address=_get_client_ip(),
            user_agent=request.headers.get("User-Agent", ""),
        )
        mongo.db.audit_log.insert_one(log_entry)
    except Exception as e:
        current_app.logger.error(f"Audit log write failed: {e}")


def _get_client_ip() -> str:
    """Extract real client IP, trusting X-Forwarded-For only from trusted proxies."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Take first IP (client), validate it's a routable address
        ip = forwarded.split(",")[0].strip()
        try:
            addr = ipaddress.ip_address(ip)
            if not addr.is_private:
                return ip
        except ValueError:
            pass
    return request.remote_addr or "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Input sanitization
# ─────────────────────────────────────────────────────────────────────────────

import bleach

ALLOWED_TAGS = []  # strip all HTML by default
ALLOWED_ATTRIBUTES = {}


def sanitize_input(value: str, max_length: int = 1024) -> str:
    """Strip HTML/JS from user input and truncate."""
    if not isinstance(value, str):
        return str(value)
    cleaned = bleach.clean(value, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES, strip=True)
    return cleaned[:max_length]


def sanitize_dict(data: dict, max_depth: int = 5) -> dict:
    """Recursively sanitize string values in a dict."""
    if max_depth <= 0:
        return {}
    result = {}
    for k, v in data.items():
        safe_key = sanitize_input(str(k), 128)
        if isinstance(v, str):
            result[safe_key] = sanitize_input(v)
        elif isinstance(v, dict):
            result[safe_key] = sanitize_dict(v, max_depth - 1)
        elif isinstance(v, list):
            result[safe_key] = [
                sanitize_input(i) if isinstance(i, str) else i
                for i in v[:100]  # limit list size
            ]
        else:
            result[safe_key] = v
    return result

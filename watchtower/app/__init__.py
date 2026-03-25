"""
WatchTower SIEM - Application Factory
Production-grade Flask application with full security hardening.
"""

import os
import logging
from datetime import timedelta

import structlog
from flask import Flask, jsonify, request, g
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect
from flask_compress import Compress
from flask_cors import CORS
from prometheus_flask_exporter import PrometheusMetrics

# ── Extension instances (uninitialised) ──────────────────────────────────────
mongo = PyMongo()
jwt = JWTManager()
limiter = Limiter(key_func=get_remote_address)
mail = Mail()
csrf = CSRFProtect()
compress = Compress()
cors = CORS()


def create_app(config_name: str = None) -> Flask:
    """Application factory."""
    app = Flask(__name__, template_folder="templates", static_folder="static")

    # ── Load configuration ────────────────────────────────────────────────────
    _load_config(app, config_name)

    # ── Initialise extensions ─────────────────────────────────────────────────
    mongo.init_app(app)
    jwt.init_app(app)
    limiter.init_app(app)
    mail.init_app(app)
    csrf.init_app(app)
    compress.init_app(app)

    # ── CORS — allow the test tool and any configured origins ─────────────────
    _init_cors(app)

    # Prometheus metrics (only in prod)
    if not app.config.get("TESTING"):
        metrics = PrometheusMetrics(app, path="/metrics")  # noqa: F841

    # ── Sentry error tracking ─────────────────────────────────────────────────
    _init_sentry(app)

    # ── Structured logging ────────────────────────────────────────────────────
    _configure_logging(app)

    # ── Security headers ──────────────────────────────────────────────────────
    _register_security_headers(app)

    # ── JWT callbacks ─────────────────────────────────────────────────────────
    _register_jwt_callbacks(app, mongo)

    # ── Blueprints ────────────────────────────────────────────────────────────
    _register_blueprints(app)

    # ── Error handlers ────────────────────────────────────────────────────────
    _register_error_handlers(app)

    # ── MongoDB indexes ───────────────────────────────────────────────────────
    with app.app_context():
        _ensure_indexes(mongo)

    app.logger.info("WatchTower SIEM started", extra={"env": app.config["ENV"]})
    return app


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_config(app: Flask, config_name: str):
    from dotenv import load_dotenv
    load_dotenv()

    app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]

    # FIX: Refuse to start with default placeholder secrets for critical keys only
    # (Optional service keys like ANTHROPIC_API_KEY, MAIL_PASSWORD are allowed to remain unset)
    _PLACEHOLDER_PREFIXES = ("CHANGE_ME", "REPLACE_ME", "YOUR_")
    _CRITICAL_SECRETS = ("SECRET_KEY", "JWT_SECRET_KEY")
    for env_var in _CRITICAL_SECRETS:
        val = os.environ.get(env_var, "")
        if not val or any(val.startswith(p) for p in _PLACEHOLDER_PREFIXES):
            raise RuntimeError(
                f"SECURITY: {env_var} is still set to a placeholder value. "
                "Generate a real secret and set it in your .env file before starting."
            )
    app.config["ENV"] = os.getenv("FLASK_ENV", "production")
    app.config["DEBUG"] = app.config["ENV"] == "development"
    app.config["TESTING"] = config_name == "testing"

    # MongoDB
    app.config["MONGO_URI"] = os.environ["MONGO_URI"]

    # JWT
    app.config["JWT_SECRET_KEY"] = os.environ["JWT_SECRET_KEY"]
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(
        seconds=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES", 3600))
    )
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(
        seconds=int(os.getenv("JWT_REFRESH_TOKEN_EXPIRES", 604800))
    )
    app.config["JWT_TOKEN_LOCATION"] = ["headers", "cookies"]
    app.config["JWT_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "true") == "true"
    app.config["JWT_COOKIE_SAMESITE"] = "Strict"
    app.config["JWT_COOKIE_CSRF_PROTECT"] = True

    # Redis / Celery
    app.config["REDIS_URL"] = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    app.config["CELERY_BROKER_URL"] = os.getenv("CELERY_BROKER_URL", app.config["REDIS_URL"])
    app.config["CELERY_RESULT_BACKEND"] = os.getenv("CELERY_RESULT_BACKEND", app.config["REDIS_URL"])

    # Mail
    app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER", "localhost")
    app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", 587))
    app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS", "true") == "true"
    app.config["MAIL_USE_SSL"] = os.getenv("MAIL_USE_SSL", "false") == "true"
    app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
    app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
    app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_DEFAULT_SENDER", "WatchTower <noreply@localhost>")

    # Security
    app.config["BCRYPT_LOG_ROUNDS"] = int(os.getenv("BCRYPT_LOG_ROUNDS", 13))
    app.config["MAX_LOGIN_ATTEMPTS"] = int(os.getenv("MAX_LOGIN_ATTEMPTS", 5))
    app.config["LOCKOUT_DURATION_MINUTES"] = int(os.getenv("LOCKOUT_DURATION_MINUTES", 30))
    app.config["WTF_CSRF_TIME_LIMIT"] = int(os.getenv("WTF_CSRF_TIME_LIMIT", 3600))
    app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "true") == "true"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
    app.config["WTF_CSRF_SSL_STRICT"] = False

    # Rate limiting
    app.config["RATELIMIT_STORAGE_URL"] = app.config["REDIS_URL"]
    app.config["RATELIMIT_DEFAULT"] = os.getenv("RATELIMIT_DEFAULT", "200 per hour")
    app.config["RATELIMIT_HEADERS_ENABLED"] = True

    # App-level
    app.config["BASE_URL"] = os.getenv("BASE_URL", "https://localhost")
    app.config["ORG_NAME"] = os.getenv("ORG_NAME", "Your Organization")
    app.config["GEOIP_DB_PATH"] = os.getenv("GEOIP_DB_PATH", "")

    # Retention
    app.config["RETENTION_RAW_EVENTS"] = int(os.getenv("RETENTION_RAW_EVENTS", 90))
    app.config["RETENTION_INCIDENTS"] = int(os.getenv("RETENTION_INCIDENTS", 365))
    app.config["RETENTION_AUDIT_LOG"] = int(os.getenv("RETENTION_AUDIT_LOG", 730))
    app.config["RETENTION_NORMALIZED_EVENTS"] = int(os.getenv("RETENTION_NORMALIZED_EVENTS", 180))

    # AI
    app.config["AI_PROVIDER"] = os.getenv("AI_PROVIDER", "anthropic")
    app.config["AI_MODEL"] = os.getenv("AI_MODEL", "claude-sonnet-4-6")
    app.config["ANTHROPIC_API_KEY"] = os.getenv("ANTHROPIC_API_KEY", "")
    app.config["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY", "")


def _init_cors(app: Flask):
    """
    Configure CORS for the API.
    - In development / testing: allow any origin (needed for the file:// test tool
      and local development without a reverse proxy).
    - In production: restrict to the origins listed in CORS_ORIGINS env var,
      which defaults to BASE_URL only.

    Only /api/v1/* routes get CORS headers — the dashboard SPA itself is served
    from the same origin and needs no CORS.
    """
    env = app.config.get("ENV", "production")

    if env in ("development", "testing"):
        # Dev/test: allow everything so the standalone HTML test tool works
        origins = "*"
    else:
        # Production: read a comma-separated list from env, defaulting to BASE_URL
        raw = os.getenv("CORS_ORIGINS", app.config.get("BASE_URL", ""))
        origins = [o.strip() for o in raw.split(",") if o.strip()] or "*"

    cors.init_app(
        app,
        resources={r"/api/*": {"origins": origins}},
        supports_credentials=True,
        allow_headers=["Content-Type", "Authorization",
                        "X-WatchTower-Key", "X-WatchTower-Signature",
                        "X-CSRFToken"],
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        max_age=600,
    )


def _init_sentry(app: Flask):
    dsn = os.getenv("SENTRY_DSN")
    if dsn:
        import sentry_sdk
        from sentry_sdk.integrations.flask import FlaskIntegration
        sentry_sdk.init(
            dsn=dsn,
            integrations=[FlaskIntegration()],
            traces_sample_rate=0.1,
            environment=app.config["ENV"],
        )


def _configure_logging(app: Flask):
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
    )
    if not app.config.get("TESTING"):
        logging.basicConfig(
            format="%(message)s",
            level=logging.INFO,
        )


def _register_security_headers(app: Flask):
    @app.after_request
    def add_security_headers(response):
        csp = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com 'unsafe-inline'; "
            "style-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://cdnjs.cloudflare.com; "
            "connect-src 'self' https://cdn.jsdelivr.net; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        response.headers["Content-Security-Policy"] = csp
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=()"
        )
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )
        response.headers.pop("Server", None)
        response.headers.pop("X-Powered-By", None)
        return response

    @app.before_request
    def set_request_id():
        import uuid
        g.request_id = str(uuid.uuid4())
        structlog.contextvars.bind_contextvars(request_id=g.request_id)


def _register_jwt_callbacks(app: Flask, mongo: PyMongo):
    @jwt.user_identity_loader
    def user_identity_lookup(user):
        return str(user["_id"])

    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        from bson import ObjectId
        identity = jwt_data["sub"]
        try:
            return mongo.db.users.find_one({"_id": ObjectId(identity), "is_active": True})
        except Exception:
            return None

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({"error": "token_expired", "message": "Token has expired"}), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({"error": "invalid_token", "message": "Signature verification failed"}), 401

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({"error": "authorization_required", "message": "Request does not contain an access token"}), 401

    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return jsonify({"error": "token_revoked", "message": "Token has been revoked"}), 401

    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        jti = jwt_payload["jti"]
        token = mongo.db.token_blocklist.find_one({"jti": jti})
        return token is not None


def _register_blueprints(app: Flask):
    from watchtower.app.api.auth import auth_bp
    from watchtower.app.api.ingest import ingest_bp
    from watchtower.app.api.events import events_bp
    from watchtower.app.api.incidents import incidents_bp
    from watchtower.app.api.rules import rules_bp
    from watchtower.app.api.agents import agents_bp
    from watchtower.app.api.alerts import alerts_bp
    from watchtower.app.api.users import users_bp
    from watchtower.app.api.compliance import compliance_bp
    from watchtower.app.api.settings import settings_bp
    from watchtower.app.api.dashboard import dashboard_bp
    from watchtower.app.api.health import health_bp
    from watchtower.app.api.assets import assets_bp
    from watchtower.app.api.copilot import copilot_bp
    from watchtower.app.api.hunt import hunt_bp
    from watchtower.app.api.canary import canary_bp
    from watchtower.app.api.reports import reports_bp
    from watchtower.app.views import views_bp

    app.register_blueprint(health_bp)
    app.register_blueprint(auth_bp, url_prefix="/api/v1/auth")
    app.register_blueprint(ingest_bp, url_prefix="/api/v1")
    app.register_blueprint(events_bp, url_prefix="/api/v1/events")
    app.register_blueprint(incidents_bp, url_prefix="/api/v1/incidents")
    app.register_blueprint(rules_bp, url_prefix="/api/v1/rules")
    app.register_blueprint(agents_bp, url_prefix="/api/v1/agents")
    app.register_blueprint(alerts_bp, url_prefix="/api/v1/alerts")
    app.register_blueprint(users_bp, url_prefix="/api/v1/users")
    app.register_blueprint(compliance_bp, url_prefix="/api/v1/compliance")
    app.register_blueprint(settings_bp, url_prefix="/api/v1/settings")
    app.register_blueprint(dashboard_bp, url_prefix="/api/v1/dashboard")
    app.register_blueprint(assets_bp, url_prefix="/api/v1/assets")
    app.register_blueprint(copilot_bp, url_prefix="/api/v1/copilot")
    app.register_blueprint(hunt_bp, url_prefix="/api/v1/hunt")
    app.register_blueprint(canary_bp, url_prefix="/api/v1/canary")
    app.register_blueprint(reports_bp, url_prefix="/api/v1/reports")
    app.register_blueprint(views_bp)

    # Exempt all API blueprints from CSRF — they authenticate via JWT Bearer
    # tokens in the Authorization header, not cookie/session-based forms.
    # CSRF protection only applies to browser session (cookie) auth flows.
    for bp in (auth_bp, ingest_bp, events_bp, incidents_bp, rules_bp,
               agents_bp, alerts_bp, users_bp, compliance_bp, settings_bp,
               dashboard_bp, health_bp, assets_bp, copilot_bp, hunt_bp, canary_bp, reports_bp):
        csrf.exempt(bp)


def _register_error_handlers(app: Flask):
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"error": "bad_request", "message": str(e)}), 400

    @app.errorhandler(401)
    def unauthorized(e):
        return jsonify({"error": "unauthorized", "message": "Authentication required"}), 401

    @app.errorhandler(403)
    def forbidden(e):
        return jsonify({"error": "forbidden", "message": "Insufficient permissions"}), 403

    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "not_found", "message": "Resource not found"}), 404
        from flask import render_template
        return render_template("dashboard/404.html"), 404

    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        return jsonify({"error": "rate_limit_exceeded", "message": "Too many requests"}), 429

    @app.errorhandler(500)
    def internal_error(e):
        app.logger.exception("Internal server error")
        return jsonify({"error": "internal_error", "message": "An internal error occurred"}), 500


def _ensure_indexes(mongo: PyMongo):
    """Create all required MongoDB indexes for performance and uniqueness."""
    db = mongo.db

    # Users
    db.users.create_index("email", unique=True)
    db.users.create_index("username", unique=True)

    # Agents
    db.agents.create_index("api_key_hash", unique=True)
    db.agents.create_index("hostname")
    db.agents.create_index("last_seen")

    # Events
    db.events.create_index([("timestamp", -1)])
    db.events.create_index([("event_id", 1), ("hostname", 1)])
    db.events.create_index("hostname")
    db.events.create_index("severity")
    db.events.create_index("category")
    db.events.create_index([("timestamp", -1), ("hostname", 1)])
    db.events.create_index("mitre_technique")
    db.events.create_index([("timestamp", 1)], expireAfterSeconds=7776000,
                           name="events_ttl")  # 90 days default; updated by retention service

    # Incidents
    db.incidents.create_index([("created_at", -1)])
    db.incidents.create_index("status")
    db.incidents.create_index("severity")
    db.incidents.create_index("assigned_to")
    db.incidents.create_index([("created_at", 1)], expireAfterSeconds=31536000,
                               name="incidents_ttl")

    # Rules
    db.rules.create_index("name", unique=True)
    db.rules.create_index("enabled")
    db.rules.create_index("category")

    # Audit log
    db.audit_log.create_index([("timestamp", -1)])
    db.audit_log.create_index("user_id")
    db.audit_log.create_index("action")

    # Token blocklist
    db.token_blocklist.create_index("jti", unique=True)
    db.token_blocklist.create_index("expires_at", expireAfterSeconds=0)

    # Assets (NEW: asset intelligence profiles)
    db.assets.create_index("hostname", unique=True)
    db.assets.create_index("criticality")
    db.assets.create_index("role")
    db.assets.create_index("owner")
    db.assets.create_index([("last_seen", -1)])

    # Correlation rules
    db.correlation_rules.create_index("name", unique=True)
    db.correlation_rules.create_index("enabled")

    # Baselines
    db.baselines.create_index("hostname", unique=True)

    # Saved hunt queries
    db.saved_hunts.create_index([("owner_id", 1), ("created_at", -1)])
    db.saved_hunts.create_index("shared")

    # Canary tokens
    db.canaries.create_index("value", unique=True)
    db.canaries.create_index("type")
    db.canaries.create_index("enabled")

    # Copilot chat history
    db.copilot_chat_history.create_index([("user_id", 1), ("created_at", -1)])

    # Report schedules
    db.report_schedules.create_index("next_run")
    db.report_schedules.create_index("enabled")

    # Password reset tokens (NEW: supports forgot-password flow)
    db.password_reset_tokens.create_index("user_id", unique=True)
    db.password_reset_tokens.create_index("token", unique=True)
    db.password_reset_tokens.create_index("expires_at", expireAfterSeconds=0)

    # Notifications
    db.notifications.create_index([("created_at", -1)])
    db.notifications.create_index([("user_id", 1), ("read", 1)])

    # Threat intel
    db.threat_intel.create_index("ioc_value", unique=True)
    db.threat_intel.create_index("ioc_type")
    db.threat_intel.create_index([("expires_at", 1)], expireAfterSeconds=0)

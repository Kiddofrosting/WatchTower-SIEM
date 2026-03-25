# WatchTower SIEM — Patch & Improvement Changelog

## Bug Fixes

### Docker / Infrastructure
- **`requirements.txt`** — Upgraded `gevent` from `24.2.1` → `24.11.1`. The old version failed to build on Python 3.13+ due to a Cython `long` type error.
- **`requirements.txt`** — Added `flower==2.0.1` explicitly (was missing from deps despite being used in compose).
- **`requirements.txt`** — Added `pyyaml==6.0.2` for Sigma rule import.
- **`docker-compose.yml`** — Removed hardcoded `SESSION_COOKIE_SECURE=false` from `x-common-env`. This was silently overriding the `.env` value and forcing cookies to be sent over plain HTTP in all Docker deployments.
- **`docker-compose.yml`** — Removed public `ports:` bindings from `mongodb` and `redis` services. Both were bound to `0.0.0.0`, exposing them outside the Docker network.
- **`docker-compose.yml`** — Added `condition: service_started` on `celery-beat` → `celery-worker` dependency so Beat doesn't queue tasks before a worker is ready.
- **`docker-compose.yml`** — Added Flower healthcheck (`curl /healthcheck`), persistent DB (`--db=/app/logs/flower.db --persistent=True`), and `depends_on: celery-worker`.
- **`Dockerfile` + `Dockerfile.celery`** — Converted to multi-stage builds. Build deps stay in the builder stage; the runtime image is lean.
- **`.dockerignore`** — Added (was missing). Prevents `.git/`, `.idea/`, `*.docx`, test files, and `__pycache__` from being sent to the Docker build context.
- **`.gitignore`** — Added `.env`, `cookies.txt`, `*.db` to prevent secrets being committed.

### Celery
- **`celery_app.py`** — Fixed `task_routes` keys: were `"celery_workers.tasks.*"` (missing `watchtower.` prefix) causing all task routing to silently fall through to the default queue.
- **`celery_app.py`** — Fixed `beat_schedule` task names with the same missing prefix. Scheduled jobs (daily retention cleanup, 5-min heartbeat check) were firing but Celery could not find the tasks — they silently failed on every trigger.
- **`celery_app.py`** — Changed `worker_prefetch_multiplier` from `4` → `1`. With `acks_late=True`, a prefetch of 4 causes each worker to reserve 4 tasks before finishing one, starving the `ai` queue (120-second tasks).
- **`celery_app.py`** — Added `worker_init` signal to create the Flask app **once per worker process** and cache it on a module-level variable (`get_flask_app()`). Previously `create_app()` was called on every single task invocation, re-running index creation, Sentry init, extension setup, and CORS configuration each time.
- **`tasks.py`** — Updated all tasks to use `get_flask_app()` singleton instead of `_get_flask_app()` which called `create_app()` each time.
- **`tasks.py`** — Replaced `logging` with `structlog` for consistent structured JSON log output across the whole application.

### Security
- **`app/__init__.py`** — Added startup secret validation. The app now raises `RuntimeError` at boot if `SECRET_KEY` or `JWT_SECRET_KEY` still starts with `CHANGE_ME` or other known placeholder strings. Prevents accidentally running production with default secrets.
- **`app/__init__.py`** — Fixed AI model string from stale `claude-sonnet-4-20250514` → `claude-sonnet-4-6`.
- **`app/api/ingest.py`** — Fixed rate limiter key function. Was keying on the first 16 characters of the API key header (collision-prone if two agents share a key prefix). Now keys on the authenticated `agent._id` which is guaranteed unique.
- **`.env` / `.env.example`** — Updated `AI_MODEL` to `claude-sonnet-4-6`.

### Health Endpoint
- **`app/api/health.py`** — Extended `/api/v1/health` to return per-component status: MongoDB ping latency (ms), Redis connectivity, and Celery worker count. Enables smarter load balancer health checks and monitoring dashboards.

### Alerting
- **`app/services/alerting.py`** — Fixed email recipient list. Previously only `SUPER_ADMIN_EMAIL` (a single hardcoded address) received alert emails. Now queries all active users with `notifications_email != false` and sends to all of them.
- **`app/celery_workers/tasks.py`** — Fixed `check_agent_heartbeats`: agent-offline events now trigger email + Slack alerts via `send_agent_offline_alerts()`. Previously only in-app notifications were created.

### MongoDB Indexes
- **`app/__init__.py`** — Added indexes for the new `password_reset_tokens` collection (`user_id` unique, `token` unique, `expires_at` TTL).

---

## New Features

### Authentication
- **`app/api/auth.py`** — Added complete **password reset flow**:
  - `POST /api/v1/auth/forgot-password` — generates a time-limited token (1 hour) and emails a reset link. Always returns 200 to prevent user enumeration.
  - `POST /api/v1/auth/reset-password` — consumes the token, validates password policy, updates the hash, and marks the token as used.

### Detection Rules
- **`app/api/rules.py`** — Added `POST /api/v1/rules/:id/test` — test a rule against a sample event payload without touching the database. Returns `{matched, reason, condition}`.
- **`app/api/rules.py`** — Added `POST /api/v1/rules/import-sigma` — accepts a Sigma YAML rule and transpiles it into a WatchTower condition DSL rule (extracts event IDs, field filters, MITRE mapping, severity, references).
- **`app/api/rules.py`** — Added `GET /api/v1/rules/:id/stats` — returns total hit count, last triggered timestamp, and a 30-day daily trend of incidents triggered by the rule.

### Incidents
- **`app/api/incidents.py`** — Added `POST /api/v1/incidents/bulk` — apply an action (`close`, `assign`, `false_positive`, `reopen`) to up to 100 incidents in a single request.
- **`app/api/incidents.py`** — Added `GET /api/v1/incidents/:id/ai-remediation/stream` — streams AI remediation tokens via **Server-Sent Events** as they arrive from the LLM. The UI can render markdown progressively instead of waiting 10–15 seconds for a complete response.
- **`app/api/incidents.py`** — When an incident is marked as `false_positive`, the reason is now written back to the triggering rule's `false_positive_notes` field so analysts building future rules have context.

### Alerting
- **`app/services/alerting.py`** — Added **outbound webhook** channel. Admin can configure a `webhook_url` + `webhook_secret` in settings. WatchTower POSTs a signed (`HMAC-SHA256`) JSON payload for each new incident, enabling integration with any SOAR, Jira, ServiceNow, or custom automation.
- **`app/services/alerting.py`** — Added **maintenance window** support. If a window is active, all alert dispatch (email, Slack, webhook) is suppressed. In-app notifications are still created.
- **`app/services/alerting.py`** — Added `send_agent_offline_alerts()` for email + Slack notification when an agent goes offline.

### Settings
- **`app/api/settings.py`** — Added `POST /api/v1/settings/maintenance-window` and `GET /api/v1/settings/maintenance-window` for managing alert suppression windows during planned maintenance.
- **`app/api/settings.py`** — Added `GET /api/v1/settings/audit-log` — paginated audit log browser.
- **`app/api/settings.py`** — Added `GET /api/v1/settings/audit-log/export` — streams the full audit log as a CSV file for compliance evidence packages (SOC 2, ISO 27001). Supports `?from=` and `?to=` date filters.
- **`app/api/settings.py`** — Added webhook and Teams webhook settings keys to the allowed settings update list.

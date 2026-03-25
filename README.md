# 🔭 WatchTower SIEM

**Enterprise-grade Security Information and Event Management (SIEM) platform for Windows environments.**

WatchTower collects, normalizes, and analyzes Windows Event Logs in real time, correlates them against 30+ built-in MITRE ATT&CK detection rules, raises incidents, and generates AI-powered remediation guidance — all wrapped in a slick dark-themed dashboard.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Features](#features)
3. [Prerequisites](#prerequisites)
4. [Quick Start — Docker Compose (Recommended)](#quick-start--docker-compose-recommended)
5. [Quick Start — Local Development (No Docker)](#quick-start--local-development-no-docker)
6. [Configuration Reference](#configuration-reference)
7. [First Login & Seeding](#first-login--seeding)
8. [Deploying Windows Agents](#deploying-windows-agents)
9. [Detection Rules](#detection-rules)
10. [AI Remediation](#ai-remediation)
11. [API Reference](#api-reference)
12. [Monitoring & Operations](#monitoring--operations)
13. [Security Hardening](#security-hardening)
14. [Troubleshooting](#troubleshooting)
15. [Project Structure](#project-structure)

---

## Architecture Overview

```
                          ┌─────────────────────────────┐
  Windows Endpoints       │        WatchTower SIEM       │
  ┌──────────────┐        │                              │
  │ WatchTower   │─HTTPS──►  Flask API (Gunicorn)        │
  │ Agent (PS1)  │  HMAC  │       │                      │
  └──────────────┘        │       ▼                      │
                          │  MongoDB (Events/Incidents)  │
  Browser / SOC           │       │                      │
  ┌──────────────┐        │       ▼                      │
  │  Dashboard   │◄──────►│  Celery Workers              │
  │  (SPA)       │        │  ├── Detection Engine        │
  └──────────────┘        │  ├── AI Remediation (LLM)    │
                          │  ├── Retention Cleanup       │
  Alerting                │  └── Agent Heartbeat         │
  ├── Email (SMTP)        │       │                      │
  ├── Slack Webhook       │  Redis (Queue/Cache)         │
  └── In-App              │                              │
                          └─────────────────────────────┘
```

### Components

| Service | Role |
|---|---|
| **Flask API** | REST API, dashboard SPA, JWT auth, rate limiting |
| **MongoDB** | Primary store for events, incidents, rules, users, audit log |
| **Redis** | Celery broker + result backend, rate limit storage |
| **Celery Worker** | Async detection engine, AI calls, enrichment |
| **Celery Beat** | Scheduled tasks (retention cleanup, heartbeat checks) |
| **Flower** | Celery task monitoring UI |

---

## Features

### Core SIEM
- **High-throughput event ingestion** — up to 1,000 events/minute per agent via HMAC-authenticated REST endpoint
- **30+ built-in detection rules** mapped to MITRE ATT&CK techniques (brute force, lateral movement, credential dumping, persistence, defense evasion, and more)
- **Threshold-based alerting** — count-in-window rules (e.g., "10 failed logons in 5 minutes")
- **Incident lifecycle management** — Open → Investigating → Contained → Resolved/False Positive → Closed
- **Real-time dashboard** — live metrics, incident trend, severity distribution, agent health

### Detection Coverage
- Authentication events (4624, 4625, 4648, 4672, 4768, 4769, 4771, 4776, 4740)
- Account management (4720, 4722–4726, 4728, 4732, 4740, 4756)
- Process execution (4688, 4689, Sysmon 1)
- Scheduled tasks (4698–4702), Services (7045, 7040)
- PowerShell script block logging (4103, 4104)
- Sysmon events (1, 3, 7, 8, 10, 11, 12, 13, 22, 25)
- Audit policy tampering (4719), domain policy changes (4739)
- RDP lateral movement (4778, 4779)

### AI-Powered Response
- Automatic remediation guidance via Anthropic Claude or OpenAI GPT
- Structured incident context sent to LLM (no raw PII)
- Covers: threat assessment, containment steps, investigation checklist, remediation, prevention, MITRE context

### Security
- JWT access + refresh tokens with revocation (MongoDB blocklist)
- TOTP multi-factor authentication with backup codes
- Bcrypt password hashing (configurable rounds)
- HMAC-SHA256 signed agent payloads
- Account lockout after configurable failed attempts
- Rate limiting on all endpoints (Redis-backed)
- Full audit log for all actions
- HSTS, CSP, X-Frame-Options, and other security headers

### Compliance Reporting
- SOC 2 Type II (CC6.x, CC7.x)
- NIST SP 800-53 Rev 5 (AC-2, AC-7, AU-2, AU-3, AU-12, IA-5, SI-4, IR-4)
- CIS Controls v8 (CIS-8, 13, 16, 17)

---

## Prerequisites

### Docker Compose (recommended)
- Docker Engine 24+
- Docker Compose v2.20+
- 4 GB RAM minimum (8 GB recommended)
- 20 GB disk

### Local Development
- Python 3.11 or 3.12
- MongoDB 7.0 (local or Atlas)
- Redis 7.x
- Git

---

## Quick Start — Docker Compose (Recommended)

### Step 1: Clone and configure

```bash
git clone https://github.com/yourorg/watchtower-siem.git
cd watchtower-siem

# Copy environment template
cp .env .env
```

### Step 2: Edit `.env` — minimum required values

Open `.env` in your editor and set at minimum:

```bash
# Generate strong secrets (run these in your terminal):
python3 -c "import secrets; print(secrets.token_hex(32))"  # for SECRET_KEY
python3 -c "import secrets; print(secrets.token_hex(32))"  # for JWT_SECRET_KEY

SECRET_KEY=<paste_first_output>
JWT_SECRET_KEY=<paste_second_output>

# Set your admin email
SUPER_ADMIN_EMAIL=admin@yourdomain.com
SUPER_ADMIN_PASSWORD=MyStr0ng@Pass!   # must be 12+ chars, upper+lower+digit+special

# Optional but recommended - enables AI incident analysis
ANTHROPIC_API_KEY=sk-ant-...
```

> **Note:** For local testing, the defaults in `.env.example` will work without modification. For production, change all `CHANGE_ME` values.

### Step 3: Start all services

```bash
# Build and start (first time takes 2-3 minutes)
docker compose up -d --build

# Watch logs
docker compose logs -f api
```

### Step 4: Seed the database

```bash
# Create admin user + seed built-in detection rules
docker compose --profile seed run --rm seeder
```

You should see:
```
[+] Created super_admin user: admin (admin@yourdomain.com)
[+] Seeded 30 built-in detection rules
[✓] Database seeding complete!
```

### Step 5: Access the dashboard

Open **http://localhost:5000** in your browser.

Login with:
- **Username:** `admin`
- **Password:** `Admin@WatchTower1!` (or what you set in `SUPER_ADMIN_PASSWORD`)

### Service URLs

| Service | URL | Notes |
|---|---|---|
| Dashboard | http://localhost:5000 | Main SIEM interface |
| API | http://localhost:5000/api/v1/ | REST API |
| Health check | http://localhost:5000/api/v1/health | Load balancer probe |
| Flower (Celery) | http://localhost:5555 | Task monitoring |
| Metrics (Prometheus) | http://localhost:5000/metrics | Prometheus scrape endpoint |

### Stopping and restarting

```bash
# Stop all services (data preserved)
docker compose down

# Stop and remove all data (reset to clean state)
docker compose down -v

# Restart a single service
docker compose restart api
docker compose restart celery-worker
```

---

## Quick Start — Local Development (No Docker)

### Step 1: Install system dependencies

```bash
# macOS
brew install mongodb-community@7.0 redis python@3.12

# Ubuntu/Debian
sudo apt-get install -y python3.12 python3.12-venv mongodb redis-server
```

### Step 2: Set up Python environment

```bash
cd watchtower-siem

python3.12 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Start MongoDB and Redis

```bash
# macOS (Homebrew)
brew services start mongodb-community@7.0
brew services start redis

# Linux
sudo systemctl start mongod
sudo systemctl start redis-server

# Verify they're running
mongosh --eval "db.adminCommand('ping')"
redis-cli ping   # should return PONG
```

### Step 4: Configure environment

```bash
cp .env .env
```

Edit `.env` for local development — update these to use localhost:

```bash
FLASK_ENV=development
SECRET_KEY=dev-local-secret-not-for-production
JWT_SECRET_KEY=dev-jwt-secret-not-for-production
MONGO_URI=mongodb://localhost:27017/watchtower_dev
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/1
SESSION_COOKIE_SECURE=false     # Required for HTTP in dev
```

### Step 5: Seed the database

```bash
python seed_admin.py \
  --username admin \
  --email admin@localhost \
  --password Admin@WatchTower1!
```

### Step 6: Start the application

**Terminal 1 — Flask API:**
```bash
source .venv/bin/activate
python run.py
# API available at http://localhost:5000
```

**Terminal 2 — Celery Worker (optional, for async detection):**
```bash
source .venv/bin/activate
celery -A watchtower.celery_workers.celery_app worker \
  --loglevel=info \
  --queues=detection,ai,maintenance \
  --concurrency=2
```

**Terminal 3 — Celery Beat (optional, for scheduled tasks):**
```bash
source .venv/bin/activate
celery -A watchtower.celery_workers.celery_app beat --loglevel=info
```

### Step 7: Open the dashboard

Navigate to **http://localhost:5000**

---

## Configuration Reference

All configuration is via environment variables (`.env` file).

### Core

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | *(required)* | Flask session signing key — use 64 random chars |
| `JWT_SECRET_KEY` | *(required)* | JWT signing key — use 64 random chars |
| `FLASK_ENV` | `production` | Set to `development` for debug mode |
| `APP_PORT` | `5000` | Port to bind |
| `BASE_URL` | `http://localhost:5000` | Public URL (used in email links) |

### Database

| Variable | Default | Description |
|---|---|---|
| `MONGO_URI` | *(required)* | Full MongoDB connection string |

### Security

| Variable | Default | Description |
|---|---|---|
| `BCRYPT_LOG_ROUNDS` | `13` | bcrypt work factor (higher = slower hashing) |
| `MAX_LOGIN_ATTEMPTS` | `5` | Failed attempts before account lockout |
| `LOCKOUT_DURATION_MINUTES` | `30` | Lockout duration |
| `SESSION_COOKIE_SECURE` | `true` | Set `false` for local HTTP dev only |

### AI / LLM

| Variable | Default | Description |
|---|---|---|
| `AI_PROVIDER` | `anthropic` | `anthropic` or `openai` |
| `AI_MODEL` | `claude-sonnet-4-20250514` | Model name for your chosen provider |
| `ANTHROPIC_API_KEY` | *(empty)* | Required if using Anthropic |
| `OPENAI_API_KEY` | *(empty)* | Required if using OpenAI |

### Retention (days)

| Variable | Default |
|---|---|
| `RETENTION_RAW_EVENTS` | `90` |
| `RETENTION_INCIDENTS` | `365` |
| `RETENTION_AUDIT_LOG` | `730` |

---

## First Login & Seeding

After seeding, log in at `/login`.

**Immediately after first login:**
1. Go to **Settings → Your Profile**
2. Change the default password
3. Enable MFA (Settings → Security → Enable TOTP)

### Creating additional users

Use the Users API (admin/super_admin role required):

```bash
curl -X POST http://localhost:5000/api/v1/auth/register \
  -H "Authorization: Bearer <your_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "analyst1",
    "email": "analyst1@company.com",
    "password": "Analyst@Pass1!",
    "full_name": "Security Analyst",
    "role": "analyst"
  }'
```

Available roles: `super_admin`, `admin`, `analyst`, `read_only`

---

## Deploying Windows Agents

### Step 1: Register the agent in WatchTower

```bash
curl -X POST http://localhost:5000/api/v1/agents/register \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "WIN-WORKSTATION-01",
    "ip_address": "192.168.1.50",
    "os_version": "Windows 11 23H2",
    "sysmon_installed": true
  }'
```

Save the returned `api_key` — it will **not be shown again**.

### Step 2: Create the agent configuration

On the Windows host, create `C:\WatchTower\config.json`:

```json
{
  "server_url": "http://your-watchtower-server:5000",
  "api_key": "wt-xxxxxxxxxxxxxxxxxx",
  "batch_size": 100,
  "flush_interval_seconds": 30,
  "log_channels": [
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-PowerShell/Operational"
  ]
}
```

### Step 3: Send events (PowerShell example)

The agent collects Windows events and POSTs them to the ingest endpoint, signed with HMAC-SHA256:

```powershell
$apiKey = "wt-your-api-key-here"
$serverUrl = "http://your-watchtower-server:5000"

# Build event batch from Windows Event Log
$events = Get-WinEvent -LogName Security -MaxEvents 50 | ForEach-Object {
    $xml = [xml]$_.ToXml()
    @{
        event_id  = [int]$_.Id
        channel   = $_.LogName
        timestamp = $_.TimeCreated.ToString("o")
        computer  = $_.MachineName
        provider  = $_.ProviderName
        message   = $_.Message
        data      = @{}   # Parse EventData fields as needed
    }
}

$body = $events | ConvertTo-Json -Compress

# Sign with HMAC-SHA256
$hmac = [System.Security.Cryptography.HMACSHA256]::new([System.Text.Encoding]::UTF8.GetBytes($apiKey))
$sig  = [System.BitConverter]::ToString($hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($body))).Replace("-","").ToLower()

Invoke-RestMethod -Uri "$serverUrl/api/v1/ingest" `
  -Method POST `
  -Headers @{
    "X-WatchTower-Key"       = $apiKey
    "X-WatchTower-Signature" = $sig
    "Content-Type"           = "application/json"
  } `
  -Body $body
```

### Recommended: Install Sysmon

Sysmon dramatically improves detection fidelity. Install it before deploying agents:

```powershell
# Download Sysmon from Sysinternals
# https://learn.microsoft.com/sysinternals/downloads/sysmon

Sysmon64.exe -accepteula -i sysmonconfig.xml
```

Use the [SwiftOnSecurity Sysmon config](https://github.com/SwiftOnSecurity/sysmon-config) as a baseline.

---

## Detection Rules

### Viewing rules

Navigate to **Dashboard → Detection Rules** or:

```bash
curl http://localhost:5000/api/v1/rules/ \
  -H "Authorization: Bearer <token>"
```

### Creating a custom rule

```bash
curl -X POST http://localhost:5000/api/v1/rules/ \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Suspicious PowerShell Encoded Command",
    "description": "Detects PowerShell launched with -EncodedCommand flag, common in malware.",
    "category": "powershell",
    "severity": "high",
    "mitre_technique": ["T1059.001"],
    "mitre_tactic": ["Execution"],
    "condition": {
      "event_ids": [4688],
      "fields": {
        "command_line": {"contains": "-encodedcommand"}
      }
    }
  }'
```

### Rule condition DSL

```json
{
  "event_ids": [4625, 4771],          // Match any of these Windows Event IDs
  "severity": ["high", "critical"],   // Match any of these severities
  "category": "authentication",       // Match this category
  "threshold": 10,                    // Trigger after N matches in window
  "window_seconds": 300,              // Time window for threshold
  "exclude_machine_accounts": true,   // Skip computer$ accounts
  "fields": {
    "process_name": {"contains": "mimikatz"},
    "logon_type": {"equals": "3"},
    "command_line": {"regex": "-[Ee]ncode[dD]"}
  }
}
```

---

## AI Remediation

When an incident is created, WatchTower can automatically generate remediation guidance.

### Enable AI

Set `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` in your `.env`.

### Trigger AI analysis

```bash
curl -X POST http://localhost:5000/api/v1/incidents/<incident_id>/ai-remediation \
  -H "Authorization: Bearer <token>"
```

Or click **"Generate AI Remediation"** in the incident detail view.

The AI response includes:
- Threat assessment
- Immediate containment steps (30-minute window)
- Investigation checklist
- Technical remediation steps
- Prevention recommendations
- MITRE ATT&CK context

---

## API Reference

All endpoints are prefixed with `/api/v1/`. Authentication uses Bearer JWT tokens.

### Authentication

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/auth/login` | Login, returns access + refresh tokens |
| `POST` | `/auth/logout` | Revoke current token |
| `POST` | `/auth/refresh` | Refresh access token |
| `POST` | `/auth/register` | Create new user (admin only) |
| `POST` | `/auth/change-password` | Change own password |
| `POST` | `/auth/mfa/setup` | Get MFA TOTP URI |
| `POST` | `/auth/mfa/verify-setup` | Confirm and enable MFA |
| `POST` | `/auth/mfa/disable` | Disable MFA |
| `GET` | `/auth/me` | Get current user info |

### Events

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/events/` | List/search events (paginated) |
| `GET` | `/events/<id>` | Get single event with raw data |
| `GET` | `/events/export` | Export events as CSV |
| `GET` | `/events/stats` | Event statistics |

Query params for `GET /events/`: `hostname`, `event_id`, `severity`, `category`, `start_time`, `end_time`, `search`, `page`, `per_page`, `sort_by`, `sort_order`

### Incidents

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/incidents/` | List incidents (paginated, filterable) |
| `GET` | `/incidents/<id>` | Get incident details |
| `PATCH` | `/incidents/<id>` | Update status, assign, add note |
| `POST` | `/incidents/<id>/ai-remediation` | Trigger AI analysis |

### Ingest (Agent → SIEM)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/ingest` | HMAC Key | Submit event batch (up to 1000 events) |

Headers required: `X-WatchTower-Key`, `X-WatchTower-Signature`

### Other Endpoints

| Prefix | Description |
|---|---|
| `/agents/` | Agent registration and management |
| `/rules/` | Detection rule CRUD |
| `/alerts/notifications` | In-app notifications |
| `/compliance/` | Compliance framework reports |
| `/dashboard/summary` | Dashboard metrics |
| `/users/` | User management |
| `/settings/` | Global settings |
| `/api/v1/health` | Health check |

---

## Monitoring & Operations

### Health check

```bash
curl http://localhost:5000/api/v1/health
# {"status": "ok", "checks": {"mongodb": "ok"}, "service": "WatchTower SIEM"}
```

### Prometheus metrics

WatchTower exports Prometheus metrics at `/metrics`:

```
# Request counts, latencies, error rates per endpoint
flask_http_request_total{...}
flask_http_request_duration_seconds{...}
```

### Celery task monitoring

Access **Flower** at http://localhost:5555 to see:
- Active, queued, and completed tasks
- Task retry counts and failures
- Worker health

### Logs

```bash
# API logs
docker compose logs -f api

# Celery worker logs
docker compose logs -f celery-worker

# All services
docker compose logs -f
```

### Backup

```bash
# Backup MongoDB
docker exec watchtower_mongodb mongodump \
  --username watchtower_user \
  --password watchtowerpass \
  --authenticationDatabase watchtower \
  --db watchtower \
  --out /tmp/backup

docker cp watchtower_mongodb:/tmp/backup ./backup-$(date +%Y%m%d)
```

---

## Security Hardening

For production deployments:

### 1. Use strong secrets

```bash
# Generate proper secrets
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### 2. Enable TLS

Place WatchTower behind nginx or a load balancer with TLS termination:

```nginx
server {
    listen 443 ssl;
    server_name watchtower.yourdomain.com;
    ssl_certificate     /etc/ssl/certs/watchtower.crt;
    ssl_certificate_key /etc/ssl/private/watchtower.key;
    
    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $host;
    }
}
```

Set `SESSION_COOKIE_SECURE=true` and `BASE_URL=https://watchtower.yourdomain.com`.

### 3. Restrict MongoDB access

In production, use MongoDB Atlas or restrict bind IP in `mongod.conf`:

```yaml
net:
  bindIp: 127.0.0.1   # or your app server IP only
  tls:
    mode: requireTLS
    certificateKeyFile: /etc/ssl/mongodb.pem
```

### 4. Enable MFA

All admin accounts should have TOTP MFA enabled.

### 5. Change Flower credentials

Set strong values for `FLOWER_USER` and `FLOWER_PASSWORD` in `.env`.

### 6. Firewall rules

Expose only port 443 (or 5000 in dev) to the internet. MongoDB (27017), Redis (6379), and Flower (5555) should be internal only.

---

## Troubleshooting

### `ModuleNotFoundError: No module named 'watchtower'`

Make sure you're running from the project root:
```bash
cd /path/to/watchtower-siem
python run.py       # not: cd watchtower && python run.py
```

Or install as editable package:
```bash
pip install -e .
```

### `Cannot connect to MongoDB`

Check MongoDB is running and the URI is correct:
```bash
mongosh "mongodb://localhost:27017/watchtower_dev" --eval "db.stats()"
```

For Docker: verify the `mongodb` service is healthy:
```bash
docker compose ps
docker compose logs mongodb
```

### `Cannot connect to Redis`

```bash
redis-cli -a <password> ping
# Should return PONG
```

### Login returns `invalid_credentials` even with correct password

The admin user may not have been seeded. Run the seeder again:
```bash
# Docker
docker compose --profile seed run --rm seeder

# Local
python seed_admin.py
```

### Celery tasks not running

Verify workers are up:
```bash
# Docker
docker compose ps celery-worker

# Local — check worker is connected
celery -A watchtower.celery_workers.celery_app inspect active
```

### `jwt.exceptions.InvalidSignatureError`

Your `JWT_SECRET_KEY` in `.env` doesn't match. All tokens issued with the old key are invalid. Either:
- Keep the same key, or
- Restart the app and have all users log in again.

### Port 5000 already in use

```bash
# macOS: AirPlay uses 5000 by default. Disable it in System Settings > General > AirDrop & Handoff
# Or change APP_PORT in .env
APP_PORT=5001
```

### Detection engine not creating incidents

1. Check Celery worker is running and processing `detection` queue
2. Verify at least one detection rule is `enabled: true`
3. Check the event has the correct `event_id` matching a rule condition
4. Look at Celery logs: `docker compose logs celery-worker`

---

## Project Structure

```
watchtower-siem/
│
├── run.py                          # Development server entry point
├── wsgi.py                         # Production WSGI entry point (Gunicorn)
├── seed_admin.py                   # Database seeder (admin user + detection rules)
├── requirements.txt                # Python dependencies
├── Dockerfile                      # Flask API container
├── Dockerfile.celery               # Celery worker container
├── docker-compose.yml              # Full stack orchestration
├── .env.example                    # Environment variable template
│
├── docker/
│   └── mongo-init.js               # MongoDB user initialization script
│
└── watchtower/
    ├── app/
    │   ├── __init__.py             # Flask application factory, extensions, config
    │   ├── models.py               # MongoDB document schemas, Marshmallow validators
    │   ├── security.py             # Auth decorators, password/HMAC/MFA utilities
    │   ├── views.py                # SPA route (serves dashboard HTML)
    │   │
    │   ├── api/                    # REST API blueprints
    │   │   ├── auth.py             # Login, logout, MFA, password management
    │   │   ├── ingest.py           # Agent event ingestion (HMAC-authenticated)
    │   │   ├── events.py           # Event browse, search, export
    │   │   ├── incidents.py        # Incident CRUD, assignment, AI remediation
    │   │   ├── rules.py            # Detection rule CRUD + seeding
    │   │   ├── agents.py           # Agent registration and management
    │   │   ├── alerts.py           # In-app notifications
    │   │   ├── users.py            # User management
    │   │   ├── compliance.py       # SOC2/NIST/CIS compliance reports
    │   │   ├── dashboard.py        # Dashboard summary metrics
    │   │   ├── settings.py         # Global settings
    │   │   └── health.py           # Health check endpoint
    │   │
    │   ├── detection/
    │   │   ├── engine.py           # Rule evaluation, threshold logic, incident creation
    │   │   └── builtin_rules.py    # 30+ MITRE ATT&CK mapped detection rules
    │   │
    │   ├── services/
    │   │   ├── ai_service.py       # Anthropic/OpenAI LLM integration
    │   │   ├── alerting.py         # Email, Slack, in-app notification dispatch
    │   │   ├── normalizer.py       # Raw Windows event → normalized schema
    │   │   └── queue_service.py    # Celery task dispatch helpers
    │   │
    │   ├── templates/dashboard/
    │   │   ├── login.html          # Login page
    │   │   ├── app.html            # Dashboard SPA shell
    │   │   └── 404.html            # 404 error page
    │   │
    │   └── static/
    │       ├── css/dashboard.css   # Dashboard styles
    │       ├── js/api.js           # JWT-aware fetch wrapper
    │       ├── js/dashboard.js     # Dashboard SPA logic
    │       ├── js/utils.js         # Shared utilities
    │       └── img/logo.svg        # WatchTower logo
    │
    └── celery_workers/
        ├── celery_app.py           # Celery app + beat schedule configuration
        └── tasks.py                # Async tasks: detection, AI, retention, heartbeat
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

*WatchTower SIEM — Built for defenders. Powered by open standards.*

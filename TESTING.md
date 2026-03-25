# WatchTower SIEM — Phase 1 Testing Guide

## Overview

Phase 1 introduces three major AI-powered features:
1. **Natural Language Hunt** — plain English → MongoDB query translation
2. **Analyst Copilot** — 7 AI-assisted workflows (explain, summarise, prioritise, etc.)
3. **Time-Travel Investigation** — reconstruct host state at any point in time

All three have comprehensive unit, integration, and manual tests.

---

## Quick start

```bash
# Install test dependencies (inside the container or venv)
pip install -r tests/requirements-test.txt

# Run all Phase 1 tests
pytest tests/ -v

# Run just one feature
pytest tests/test_nl_hunt.py -v
pytest tests/test_analyst_copilot.py -v
pytest tests/test_time_travel.py -v
pytest tests/test_integration_phase1.py -v

# Run with coverage report
pytest tests/ --cov=watchtower/app/services --cov=watchtower/app/api/copilot \
  --cov-report=term-missing
```

---

## Test structure

```
tests/
├── conftest.py                    # Shared fixtures (mock DB, auth, sample data)
├── requirements-test.txt          # Test dependencies
├── test_nl_hunt.py                # Natural Language Hunt — 18 tests
├── test_analyst_copilot.py        # Analyst Copilot — 24 tests
├── test_time_travel.py            # Time-Travel Investigation — 22 tests
└── test_integration_phase1.py     # End-to-end integration — 8 tests
```

**Total: 72 automated tests.** All run with mongomock (no real MongoDB needed).
All AI calls are mocked — tests run without any API keys.

---

## Manual testing guide

### Prerequisites

Stack must be running with an Anthropic or OpenAI API key configured:

```bash
docker compose up -d
docker compose --profile seed run --rm seeder
```

Get a JWT token:

```powershell
$body = '{"username":"admin@watchtower.local","password":"Admin@KX8b0b47Yegf_jVS1!"}'
$token = (Invoke-RestMethod http://localhost:5000/api/v1/auth/login `
  -Method POST -ContentType application/json -Body $body).access_token
$h = @{Authorization="Bearer $token"; "Content-Type"="application/json"}
```

---

### Feature 1: Natural Language Hunt

#### Test A — Simple event query

```powershell
Invoke-RestMethod http://localhost:5000/api/v1/copilot/nl-hunt `
  -Method POST -Headers $h `
  -Body '{"question": "Show me failed login attempts in the last hour"}'
```

**Expected:** `result_count >= 0`, `collection = "events"`, `explanation` in plain English,
`suggested_visualisation = "timeline"`.

#### Test B — Aggregation query

```powershell
Invoke-RestMethod http://localhost:5000/api/v1/copilot/nl-hunt `
  -Method POST -Headers $h `
  -Body '{"question": "Which hosts had the most events today?"}'
```

**Expected:** Results grouped by hostname, `suggested_visualisation = "bar_chart"`.

#### Test C — Preview without executing

```powershell
Invoke-RestMethod http://localhost:5000/api/v1/copilot/nl-hunt/translate-only `
  -Method POST -Headers $h `
  -Body '{"question": "users who logged in outside business hours"}'
```

**Expected:** Returns `collection`, `pipeline`, `explanation` — no `results` field.

#### Test D — Security: blocked operator

```powershell
# This tests that even if the LLM were to produce a malicious query,
# the validation layer blocks it. The endpoint should return HTTP 400.
Invoke-RestMethod http://localhost:5000/api/v1/copilot/nl-hunt `
  -Method POST -Headers $h `
  -Body '{"question": "find everything using JavaScript"}'
```

**Expected:** Either a valid safe query OR HTTP 400 with `error: unsafe_query`.
(The LLM should produce a safe query for this; if it were somehow coerced into
producing $where, the validation catches it.)

---

### Feature 2: Analyst Copilot

First, get an incident ID from the open incidents list:

```powershell
$incidents = Invoke-RestMethod http://localhost:5000/api/v1/incidents/ -Headers $h
$incId = $incidents.data[0]._id
```

#### Test E — Explain incident

```powershell
Invoke-RestMethod "http://localhost:5000/api/v1/copilot/explain/$incId" -Headers $h
```

**Expected:** `explanation` field with plain English text, 3 paragraphs (What happened / Why it matters / What to do first).

#### Test F — Priority queue

```powershell
Invoke-RestMethod http://localhost:5000/api/v1/copilot/priority-queue -Headers $h
```

**Expected:** `recommendation` (1-2 sentences), `queue` array with `priority`, `reason`, `title` per incident.
Verify critical incidents appear before low severity ones.

#### Test G — Weekly summary

```powershell
Invoke-RestMethod "http://localhost:5000/api/v1/copilot/weekly-summary?days=7" -Headers $h
```

**Expected:** `summary` field with 3 paragraphs of executive prose, `stats` object with numeric metrics.

#### Test H — Draft playbook

```powershell
Invoke-RestMethod "http://localhost:5000/api/v1/copilot/draft-playbook/$incId" `
  -Method POST -Headers $h
```

**Expected:** `playbook` with 5 phases (Containment, Evidence Collection, Investigation, Eradication, Post-Incident).
Verify Windows-specific commands are present (PowerShell, Event Viewer paths).

#### Test I — Compliance impact

```powershell
Invoke-RestMethod "http://localhost:5000/api/v1/copilot/compliance-impact/$incId" -Headers $h
```

**Expected:** `affected_frameworks` list with at least 1 framework, `immediate_notification_required` bool.

#### Test J — Is this normal?

```powershell
$events = Invoke-RestMethod "http://localhost:5000/api/v1/events/?per_page=1" -Headers $h
$eventId = $events.data[0]._id

Invoke-RestMethod http://localhost:5000/api/v1/copilot/is-normal `
  -Method POST -Headers $h `
  -Body "{`"event_id`": `"$eventId`"}"
```

**Expected:** `assessment` with plain English opinion (normal / suspicious / abnormal),
`asset_known` bool, `baseline_available` bool.

#### Test K — Conversational chat

```powershell
Invoke-RestMethod http://localhost:5000/api/v1/copilot/chat `
  -Method POST -Headers $h `
  -Body '{"message": "What is T1110 and how do I detect it?", "history": []}'
```

**Expected:** `response` with an explanation of MITRE T1110, detection strategies,
`context_used` showing current SIEM stats.

Multi-turn conversation:

```powershell
$history = @(@{role="user"; content="What is T1110?"}, @{role="assistant"; content="T1110 is Brute Force."})
Invoke-RestMethod http://localhost:5000/api/v1/copilot/chat `
  -Method POST -Headers $h `
  -Body (ConvertTo-Json @{message="What are the sub-techniques?"; history=$history})
```

**Expected:** Response references the prior context (T1110 sub-techniques).

---

### Feature 3: Time-Travel Investigation

#### Test L — Point-in-time snapshot

```powershell
$at = (Get-Date).ToUniversalTime().ToString("o")
Invoke-RestMethod "http://localhost:5000/api/v1/copilot/time-travel/snapshot?hostname=TEST-HOST-01&at=$at" `
  -Headers $h
```

**Expected:** `state` with `active_processes`, `logged_in_users`, `external_network_connections`,
`events_in_window` count.

#### Test M — Event window

```powershell
$center = (Get-Date).ToUniversalTime().ToString("o")
Invoke-RestMethod "http://localhost:5000/api/v1/copilot/time-travel/window?hostname=TEST-HOST-01&center=$center&before=60&after=30" `
  -Headers $h
```

**Expected:** `timeline` array with mixed `_type: event` and `_type: incident` entries, sorted chronologically.
`category_breakdown` showing event distribution.

#### Test N — Before/after diff

```powershell
Invoke-RestMethod "http://localhost:5000/api/v1/copilot/time-travel/diff/$incId" -Headers $h
```

**Expected:** `diff` object with `new_processes`, `new_users`, `new_external_connections`,
`privilege_events_after`. `changes_detected` bool.

#### Test O — Event replay

```powershell
$start = (Get-Date).AddHours(-2).ToUniversalTime().ToString("o")
$end = (Get-Date).ToUniversalTime().ToString("o")
Invoke-RestMethod "http://localhost:5000/api/v1/copilot/time-travel/replay?hostname=TEST-HOST-01&start=$start&end=$end" `
  -Headers $h
```

**Expected:** `replay` array of scenes, each with `events`, `start`, `end`, `categories`.
Multiple events in same time cluster = one scene.

#### Test P — Blast radius

```powershell
Invoke-RestMethod "http://localhost:5000/api/v1/copilot/time-travel/blast-radius/$incId" -Headers $h
```

**Expected:** `related_hosts` list, `lateral_movement_indicators`, `risk_summary` with
`high_criticality_hosts_involved` and `potential_lateral_moves` counts.

---

## Validation checklist

Run these checks after every deployment:

- [ ] `GET /api/v1/health` returns `status: ok` with all components healthy
- [ ] NL Hunt rejects queries with blocked operators (`$where`, `$function`)
- [ ] NL Hunt caps results at 500 even if LLM specifies higher
- [ ] All copilot endpoints return 503 when no AI key is configured
- [ ] All copilot endpoints return 401 without JWT
- [ ] Time-travel replay rejects windows > 24 hours
- [ ] Time-travel diff returns `changes_detected: false` when no changes found
- [ ] Chat streaming endpoint (`GET /api/v1/copilot/chat/stream?message=test`) sends SSE

---

## Load / stress testing (optional)

```powershell
# Hammer the NL hunt endpoint with 20 concurrent requests
1..20 | ForEach-Object -Parallel {
  $h = @{Authorization="Bearer $using:token"; "Content-Type"="application/json"}
  Invoke-RestMethod http://localhost:5000/api/v1/copilot/nl-hunt `
    -Method POST -Headers $h `
    -Body '{"question": "failed logins today"}'
} -ThrottleLimit 5
```

**Expected:** All requests succeed (200), no 500 errors. The NL hunt makes 2 AI calls
per request — with 20 concurrent you'll use ~40 API calls. Ensure your API key has
sufficient rate limits.

---

## Known limitations in testing

1. **AI responses are non-deterministic** — manual tests verify structure and
   presence of expected fields, not exact content. The LLM may phrase things
   differently on each call.

2. **mongomock limitations** — some complex MongoDB aggregation operators behave
   slightly differently in mongomock vs real MongoDB. If tests pass but production
   queries fail, run with a real test MongoDB instance.

3. **Time-based tests** — tests that depend on "events in the last hour" may be
   sensitive to system clock. If CI runs slowly, increase window sizes in conftest
   fixtures.

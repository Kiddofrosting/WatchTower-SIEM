"""
Tests for Analyst Copilot Service
===================================
Tests cover all 7 copilot capabilities + API endpoints.
"""

import json
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone


def _mock_anthropic(text: str):
    """Helper: mock Anthropic client that returns given text."""
    mock = MagicMock()
    mock.messages.create.return_value = MagicMock(
        content=[MagicMock(text=text)]
    )
    return mock


# ── 1. Incident Explainer ─────────────────────────────────────────────────────

class TestIncidentExplainer:

    def test_explain_returns_string(self):
        from watchtower.app.services.analyst_copilot import explain_incident
        incident = {
            "title": "Brute Force on SERVER-01",
            "severity": "high",
            "category": "authentication",
            "rule_name": "Brute Force - Multiple Failed Logons",
            "description": "10 failed logons in 5 minutes.",
            "mitre_technique": ["T1110"],
            "mitre_tactic": ["Credential Access"],
            "event_count": 10,
            "ai_triage": {"true_positive_score": 82, "analyst_brief": "Likely real brute force."},
        }
        asset = {"hostname": "SERVER-01", "role": "domain_controller", "criticality": "critical",
                 "owner": "IT Team", "is_internet_facing": False}
        config = {"AI_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "test"}

        with patch("anthropic.Anthropic") as mock_cls:
            mock_cls.return_value = _mock_anthropic("**What happened** The attacker tried many passwords.")
            result = explain_incident(incident, asset, config)

        assert isinstance(result, str)
        assert len(result) > 10

    def test_explain_api_endpoint(self, client, auth_headers, sample_incident, mock_mongo):
        with patch("anthropic.Anthropic") as mock_cls:
            mock_cls.return_value = _mock_anthropic("Plain English explanation here.")
            resp = client.get(
                f"/api/v1/copilot/explain/{sample_incident['_id']}",
                headers=auth_headers
            )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "explanation" in data
        assert "incident_id" in data

    def test_explain_invalid_id(self, client, auth_headers):
        resp = client.get("/api/v1/copilot/explain/not-an-id", headers=auth_headers)
        assert resp.status_code == 400

    def test_explain_not_found(self, client, auth_headers):
        from bson import ObjectId
        fake_id = str(ObjectId())
        resp = client.get(f"/api/v1/copilot/explain/{fake_id}", headers=auth_headers)
        assert resp.status_code == 404


# ── 2. Weekly Summary ─────────────────────────────────────────────────────────

class TestWeeklySummary:

    def test_summary_returns_prose(self):
        from watchtower.app.services.analyst_copilot import generate_weekly_summary
        stats = {
            "total_events": 15000,
            "total_incidents": 23,
            "critical_incidents": 2,
            "resolved_incidents": 18,
            "auto_closed": 8,
            "mttr_hours": 4.2,
            "active_agents": 42,
            "top_mitre": [{"technique": "T1110", "count": 5}],
            "top_hosts": [{"hostname": "DC-01", "count": 8}],
            "incident_change_pct": -12.5,
            "event_change_pct": 3.2,
            "org_name": "TestCorp",
        }
        config = {"AI_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "test"}

        with patch("anthropic.Anthropic") as mock_cls:
            mock_cls.return_value = _mock_anthropic(
                "This week TestCorp maintained a strong security posture. "
                "Incident volume decreased 12.5% compared to last week. "
                "Two critical incidents were investigated and resolved within SLA."
            )
            result = generate_weekly_summary(stats, config)

        assert isinstance(result, str)
        assert len(result) > 20

    def test_weekly_summary_api(self, client, auth_headers):
        with patch("anthropic.Anthropic") as mock_cls:
            mock_cls.return_value = _mock_anthropic("Weekly security summary prose.")
            resp = client.get("/api/v1/copilot/weekly-summary", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert "summary" in data
        assert "stats" in data
        assert "period_days" in data

    def test_weekly_summary_custom_days(self, client, auth_headers):
        with patch("anthropic.Anthropic") as mock_cls:
            mock_cls.return_value = _mock_anthropic("30-day summary.")
            resp = client.get("/api/v1/copilot/weekly-summary?days=30", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()["period_days"] == 30


# ── 3. Priority Queue ────────────────────────────────────────────────────────

class TestPriorityQueue:

    def test_empty_queue(self):
        from watchtower.app.services.analyst_copilot import get_priority_queue
        result = get_priority_queue([], {}, {"AI_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "test"})
        assert result["queue"] == []
        assert "No open incidents" in result["recommendation"]

    def test_priority_queue_returns_ordered_list(self):
        from watchtower.app.services.analyst_copilot import get_priority_queue
        from bson import ObjectId
        incidents = [
            {"_id": ObjectId(), "title": "Brute Force", "severity": "high",
             "hostname": "WS-01", "category": "authentication",
             "ai_triage": {"true_positive_score": 85},
             "created_at": datetime.now(timezone.utc), "mitre_technique": []},
            {"_id": ObjectId(), "title": "Low noise", "severity": "low",
             "hostname": "WS-02", "category": "network",
             "ai_triage": {"true_positive_score": 12},
             "created_at": datetime.now(timezone.utc), "mitre_technique": []},
        ]
        expected = json.dumps({
            "recommendation": "Start with the brute force incident.",
            "queue": [
                {"id": str(incidents[0]["_id"]), "priority": 1, "reason": "High triage score."},
                {"id": str(incidents[1]["_id"]), "priority": 2, "reason": "Low priority."},
            ]
        })
        config = {"AI_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "test"}

        with patch("anthropic.Anthropic") as mock_cls:
            mock_cls.return_value = _mock_anthropic(expected)
            result = get_priority_queue(incidents, {}, config)

        assert len(result["queue"]) == 2
        assert result["queue"][0]["priority"] == 1

    def test_priority_queue_api(self, client, auth_headers, sample_incident):
        queue_json = json.dumps({
            "recommendation": "Review the brute force incident first.",
            "queue": [{"id": str(sample_incident["_id"]), "priority": 1, "reason": "High severity."}]
        })
        with patch("anthropic.Anthropic") as mock_cls:
            mock_cls.return_value = _mock_anthropic(queue_json)
            resp = client.get("/api/v1/copilot/priority-queue", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert "recommendation" in data
        assert "queue" in data


# ── 4. Is This Normal ────────────────────────────────────────────────────────

class TestIsNormal:

    def test_is_normal_returns_assessment(self):
        from watchtower.app.services.analyst_copilot import is_this_normal
        event = {
            "hostname": "WS-01",
            "category": "process_execution",
            "event_id": 4688,
            "process_name": "mimikatz.exe",
            "subject_username": "jdoe",
            "message": "A new process was created.",
            "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
            "source_ip": "",
        }
        asset = {
            "role": "workstation",
            "criticality": "medium",
            "known_processes": ["chrome.exe", "outlook.exe", "explorer.exe"],
            "known_users": ["jdoe", "service_account"],
        }
        config = {"AI_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "test"}

        with patch("anthropic.Anthropic") as mock_cls:
            mock_cls.return_value = _mock_anthropic(
                "This is definitely abnormal. mimikatz.exe is a credential dumping tool "
                "and is not in the known process list for this host. Isolate immediately."
            )
            result = is_this_normal(event, asset, {}, config)

        assert isinstance(result, str)
        assert len(result) > 10

    def test_is_normal_api(self, client, auth_headers, sample_event):
        with patch("anthropic.Anthropic") as mock_cls:
            mock_cls.return_value = _mock_anthropic("This looks suspicious for this host.")
            resp = client.post(
                "/api/v1/copilot/is-normal",
                json={"event_id": str(sample_event["_id"])},
                headers=auth_headers
            )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "assessment" in data
        assert "hostname" in data

    def test_is_normal_missing_event_id(self, client, auth_headers):
        resp = client.post("/api/v1/copilot/is-normal", json={}, headers=auth_headers)
        assert resp.status_code == 422


# ── 5. Playbook Generator ────────────────────────────────────────────────────

class TestPlaybookGenerator:

    def test_draft_playbook_returns_markdown(self):
        from watchtower.app.services.analyst_copilot import draft_playbook
        incident = {
            "title": "Mimikatz on DC-01",
            "severity": "critical",
            "category": "credential_access",
            "rule_name": "Credential Dumping",
            "hostname": "DC-01",
            "description": "Mimikatz.exe detected running as SYSTEM.",
            "mitre_technique": ["T1003.001"],
            "mitre_tactic": ["Credential Access"],
        }
        config = {"AI_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "test"}

        playbook_text = """## Phase 1: Immediate Containment
1. Isolate DC-01 from the network.
2. Reset KRBTGT password twice.
## Phase 2: Evidence Collection
1. Take memory dump with WinPmem."""

        with patch("anthropic.Anthropic") as mock_cls:
            mock_cls.return_value = _mock_anthropic(playbook_text)
            result = draft_playbook(incident, config)

        assert "Phase 1" in result or "Containment" in result or len(result) > 20

    def test_playbook_api_endpoint(self, client, auth_headers, sample_incident):
        with patch("anthropic.Anthropic") as mock_cls:
            mock_cls.return_value = _mock_anthropic("## Phase 1\n1. Isolate the host.")
            resp = client.post(
                f"/api/v1/copilot/draft-playbook/{sample_incident['_id']}",
                headers=auth_headers
            )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "playbook" in data
        assert "incident_id" in data


# ── 6. Compliance Impact ──────────────────────────────────────────────────────

class TestComplianceImpact:

    def test_compliance_impact_returns_frameworks(self):
        from watchtower.app.services.analyst_copilot import compliance_impact
        incident = {
            "category": "credential_access",
            "severity": "critical",
            "description": "Credentials were dumped from LSASS.",
            "mitre_technique": ["T1003.001"],
        }
        config = {"AI_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "test"}
        expected_json = json.dumps({
            "affected_frameworks": [
                {
                    "framework": "SOC 2 Type II",
                    "affected_controls": ["CC6.1: Logical Access Controls"],
                    "reportable": True,
                    "reporting_deadline": "72 hours",
                    "required_actions": ["Document the incident"],
                    "risk_level": "critical",
                }
            ],
            "immediate_notification_required": True,
            "summary": "This incident affects SOC 2 CC6.1 and requires immediate notification.",
        })

        with patch("anthropic.Anthropic") as mock_cls:
            mock_cls.return_value = _mock_anthropic(expected_json)
            result = compliance_impact(incident, config)

        assert "affected_frameworks" in result
        assert len(result["affected_frameworks"]) >= 1

    def test_compliance_impact_api(self, client, auth_headers, sample_incident):
        expected_json = json.dumps({
            "affected_frameworks": [],
            "immediate_notification_required": False,
            "summary": "Low compliance impact.",
        })
        with patch("anthropic.Anthropic") as mock_cls:
            mock_cls.return_value = _mock_anthropic(expected_json)
            resp = client.get(
                f"/api/v1/copilot/compliance-impact/{sample_incident['_id']}",
                headers=auth_headers
            )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "incident_id" in data


# ── 7. Chat ───────────────────────────────────────────────────────────────────

class TestCopilotChat:

    def test_chat_returns_response(self):
        from watchtower.app.services.analyst_copilot import copilot_chat
        config = {"AI_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "test"}

        with patch("anthropic.Anthropic") as mock_cls:
            mock_cls.return_value = _mock_anthropic(
                "T1110 is the Brute Force technique in MITRE ATT&CK. "
                "It covers password guessing, spraying, and credential stuffing."
            )
            result = copilot_chat("What is T1110?", {}, [], config)

        assert isinstance(result, str)
        assert len(result) > 10

    def test_chat_with_history(self):
        from watchtower.app.services.analyst_copilot import copilot_chat
        config = {"AI_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "test"}
        history = [
            {"role": "user", "content": "What is LSASS?"},
            {"role": "assistant", "content": "LSASS is the Local Security Authority Subsystem Service."},
        ]

        with patch("anthropic.Anthropic") as mock_cls:
            mock_cls.return_value = _mock_anthropic("Mimikatz targets LSASS to extract credentials.")
            result = copilot_chat("How does Mimikatz relate to it?", {}, history, config)

        assert isinstance(result, str)

    def test_chat_api_endpoint(self, client, auth_headers):
        with patch("anthropic.Anthropic") as mock_cls:
            mock_cls.return_value = _mock_anthropic("Here is my answer about T1110.")
            resp = client.post(
                "/api/v1/copilot/chat",
                json={"message": "Explain T1110", "history": []},
                headers=auth_headers
            )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "response" in data
        assert "context_used" in data

    def test_chat_missing_message(self, client, auth_headers):
        resp = client.post("/api/v1/copilot/chat", json={}, headers=auth_headers)
        assert resp.status_code == 422

    def test_chat_no_ai_configured(self, client, auth_headers, app):
        original = app.config.get("ANTHROPIC_API_KEY")
        app.config["ANTHROPIC_API_KEY"] = ""
        app.config["OPENAI_API_KEY"] = ""
        try:
            resp = client.post("/api/v1/copilot/chat",
                               json={"message": "test"}, headers=auth_headers)
            assert resp.status_code == 503
        finally:
            app.config["ANTHROPIC_API_KEY"] = original

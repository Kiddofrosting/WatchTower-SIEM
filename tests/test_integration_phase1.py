"""
Phase 1 Integration Tests
==========================
End-to-end tests that exercise the full request lifecycle
for all three Phase 1 features together.
"""

import json
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta, timezone


class TestNLHuntIntegration:
    """Full request → translate → validate → execute → respond cycle."""

    def test_full_auth_events_query(self, client, auth_headers, sample_event):
        spec_json = json.dumps({
            "collection": "events",
            "pipeline": [
                {"$match": {"category": "authentication"}},
                {"$sort": {"timestamp": -1}},
                {"$limit": 50},
            ],
            "explanation": "Authentication events sorted newest first.",
            "suggested_visualisation": "timeline",
        })
        with patch("anthropic.Anthropic") as mock_cls:
            mock_cls.return_value.messages.create.side_effect = [
                MagicMock(content=[MagicMock(text=spec_json)]),
                MagicMock(content=[MagicMock(text="Found 1 authentication event in the last 24 hours.")]),
            ]
            resp = client.post(
                "/api/v1/copilot/nl-hunt",
                json={"question": "Show me authentication events"},
                headers=auth_headers,
            )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["result_count"] >= 1
        assert data["suggested_visualisation"] == "timeline"
        assert "summary" in data
        assert not data.get("error")

    def test_nl_hunt_with_aggregation(self, client, auth_headers, sample_event):
        """Test group-by aggregation pipeline."""
        spec_json = json.dumps({
            "collection": "events",
            "pipeline": [
                {"$match": {"category": "authentication"}},
                {"$group": {"_id": "$hostname", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 10},
            ],
            "explanation": "Event counts grouped by hostname.",
            "suggested_visualisation": "bar_chart",
        })
        with patch("anthropic.Anthropic") as mock_cls:
            mock_cls.return_value.messages.create.side_effect = [
                MagicMock(content=[MagicMock(text=spec_json)]),
                MagicMock(content=[MagicMock(text="TEST-HOST-01 had 1 authentication event.")]),
            ]
            resp = client.post(
                "/api/v1/copilot/nl-hunt",
                json={"question": "Which hosts have the most authentication events?"},
                headers=auth_headers,
            )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["suggested_visualisation"] == "bar_chart"

    def test_injection_attempt_blocked(self, client, auth_headers):
        """Simulate LLM being tricked into returning a malicious pipeline."""
        evil_spec = json.dumps({
            "collection": "events",
            "pipeline": [
                {"$match": {"$where": "function() { return db.users.drop(); }"}},
                {"$limit": 10},
            ],
            "explanation": "Totally safe query.",
        })
        with patch("anthropic.Anthropic") as mock_cls:
            mock_cls.return_value.messages.create.return_value = \
                MagicMock(content=[MagicMock(text=evil_spec)])
            resp = client.post(
                "/api/v1/copilot/nl-hunt",
                json={"question": "drop the database"},
                headers=auth_headers,
            )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data.get("error") == "unsafe_query"


class TestCopilotIntegration:
    """Full copilot workflow tests."""

    def test_explain_incident_full_workflow(self, client, auth_headers, sample_incident, mock_mongo):
        """Register asset, then get incident explanation with asset context."""
        mock_mongo.assets.insert_one({
            "hostname": "TEST-HOST-01",
            "role": "workstation",
            "criticality": "medium",
            "owner": "IT Team",
            "is_internet_facing": False,
            "known_processes": ["chrome.exe"],
            "known_users": ["jdoe"],
        })
        with patch("anthropic.Anthropic") as mock_cls:
            mock_cls.return_value.messages.create.return_value = \
                MagicMock(content=[MagicMock(text="**What happened** Brute force attack detected.")])
            resp = client.get(
                f"/api/v1/copilot/explain/{sample_incident['_id']}",
                headers=auth_headers,
            )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "explanation" in data
        assert len(data["explanation"]) > 0

    def test_priority_queue_no_incidents(self, client, auth_headers, mock_mongo):
        """Empty incident list returns immediately without AI call."""
        mock_mongo.incidents.delete_many({})
        resp = client.get("/api/v1/copilot/priority-queue", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert "No open incidents" in data["recommendation"]

    def test_chat_conversation_flow(self, client, auth_headers):
        """Multi-turn conversation maintains context."""
        history = [
            {"role": "user", "content": "What is LSASS?"},
            {"role": "assistant", "content": "LSASS is the Local Security Authority Subsystem Service."},
        ]
        with patch("anthropic.Anthropic") as mock_cls:
            mock_cls.return_value.messages.create.return_value = \
                MagicMock(content=[MagicMock(text="Mimikatz targets LSASS to dump credentials from memory.")])
            resp = client.post(
                "/api/v1/copilot/chat",
                json={"message": "How does Mimikatz target it?", "history": history},
                headers=auth_headers,
            )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "response" in data
        assert len(data["response"]) > 5


class TestTimeTravelIntegration:
    """Full time-travel investigation workflow tests."""

    def test_full_investigation_workflow(self, client, auth_headers, sample_incident, mock_mongo):
        """Complete investigation: diff → blast radius → replay."""
        now = datetime.now(timezone.utc)
        hostname = "TEST-HOST-01"

        # Seed some events around the incident time
        for i in range(5):
            mock_mongo.events.insert_one({
                "hostname": hostname,
                "event_id": 4688,
                "category": "process_execution",
                "timestamp": now - timedelta(minutes=i * 10),
                "process_name": f"process{i}.exe",
                "subject_username": "jdoe",
                "severity": "info",
                "message": f"Process {i} created",
                "mitre_technique": [],
            })

        # Step 1: Before/after diff
        diff_resp = client.get(
            f"/api/v1/copilot/time-travel/diff/{sample_incident['_id']}",
            headers=auth_headers,
        )
        assert diff_resp.status_code == 200
        diff_data = diff_resp.get_json()
        assert "diff" in diff_data

        # Step 2: Blast radius
        blast_resp = client.get(
            f"/api/v1/copilot/time-travel/blast-radius/{sample_incident['_id']}",
            headers=auth_headers,
        )
        assert blast_resp.status_code == 200
        blast_data = blast_resp.get_json()
        assert "related_hosts" in blast_data

        # Step 3: Event replay
        start = (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        end = now.isoformat().replace("+00:00", "Z")
        replay_resp = client.get(
            f"/api/v1/copilot/time-travel/replay?hostname={hostname}&start={start}&end={end}",
            headers=auth_headers,
        )
        assert replay_resp.status_code == 200
        replay_data = replay_resp.get_json()
        assert "replay" in replay_data
        assert replay_data["total_events"] >= 1

"""
Tests for Natural Language Hunt Service
========================================
Tests cover:
  - Query translation (mock AI responses)
  - Security validation (blocked operators, field whitelist)
  - Query execution against in-memory DB
  - Edge cases (empty results, bad questions, very long queries)
"""

import json
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone


# ── Unit tests: query validation ──────────────────────────────────────────────

class TestQueryValidation:

    def test_blocked_operator_where(self):
        from watchtower.app.services.nl_hunt import _parse_and_validate_query_spec
        raw = json.dumps({
            "collection": "events",
            "pipeline": [{"$match": {"$where": "this.hostname == 'evil'"}}],
            "explanation": "test",
        })
        result = _parse_and_validate_query_spec(raw, "test question")
        assert result.get("error") == "unsafe_query"
        assert "$where" in result.get("detail", "")

    def test_blocked_operator_function(self):
        from watchtower.app.services.nl_hunt import _parse_and_validate_query_spec
        raw = json.dumps({
            "collection": "events",
            "pipeline": [{"$match": {"x": {"$function": {"body": "return 1"}}}}],
            "explanation": "test",
        })
        result = _parse_and_validate_query_spec(raw, "test")
        assert result.get("error") == "unsafe_query"

    def test_blocked_operator_nested(self):
        """Blocked operators nested deep in pipeline should be caught."""
        from watchtower.app.services.nl_hunt import _parse_and_validate_query_spec
        raw = json.dumps({
            "collection": "events",
            "pipeline": [
                {"$match": {"hostname": "test"}},
                {"$group": {"_id": "$hostname", "x": {"$accumulator": {"init": "function(){}"}}}},
            ],
            "explanation": "test",
        })
        result = _parse_and_validate_query_spec(raw, "test")
        assert result.get("error") == "unsafe_query"

    def test_invalid_collection(self):
        from watchtower.app.services.nl_hunt import _parse_and_validate_query_spec
        raw = json.dumps({
            "collection": "users",  # not in COLLECTION_MAP
            "pipeline": [{"$match": {}}],
            "explanation": "test",
        })
        result = _parse_and_validate_query_spec(raw, "test")
        assert result.get("error") == "invalid_collection"

    def test_limit_enforced(self):
        """If LLM omits $limit, one is added."""
        from watchtower.app.services.nl_hunt import _parse_and_validate_query_spec
        raw = json.dumps({
            "collection": "events",
            "pipeline": [{"$match": {"hostname": "test"}}],
            "explanation": "test",
        })
        result = _parse_and_validate_query_spec(raw, "test")
        assert not result.get("error")
        assert any("$limit" in stage for stage in result["pipeline"])

    def test_limit_capped_at_500(self):
        """LLM-specified limit of 9999 is capped at 500."""
        from watchtower.app.services.nl_hunt import _parse_and_validate_query_spec
        raw = json.dumps({
            "collection": "events",
            "pipeline": [
                {"$match": {"hostname": "test"}},
                {"$limit": 9999},
            ],
            "explanation": "test",
        })
        result = _parse_and_validate_query_spec(raw, "test")
        limits = [s["$limit"] for s in result["pipeline"] if "$limit" in s]
        assert all(l <= 500 for l in limits)

    def test_malformed_json_response(self):
        from watchtower.app.services.nl_hunt import _parse_and_validate_query_spec
        result = _parse_and_validate_query_spec("not valid json at all", "test question")
        assert result.get("error") == "translation_failed"

    def test_markdown_fenced_json_stripped(self):
        """LLM sometimes wraps JSON in ```json fences — should be stripped."""
        from watchtower.app.services.nl_hunt import _parse_and_validate_query_spec
        spec = {"collection": "events", "pipeline": [{"$match": {"hostname": "x"}}, {"$limit": 10}], "explanation": "test"}
        raw = f"```json\n{json.dumps(spec)}\n```"
        result = _parse_and_validate_query_spec(raw, "test")
        assert not result.get("error")

    def test_valid_query_passes(self):
        from watchtower.app.services.nl_hunt import _parse_and_validate_query_spec
        raw = json.dumps({
            "collection": "events",
            "pipeline": [
                {"$match": {"category": "authentication", "severity": "high"}},
                {"$sort": {"timestamp": -1}},
                {"$limit": 50},
            ],
            "explanation": "High severity auth events.",
            "suggested_visualisation": "timeline",
        })
        result = _parse_and_validate_query_spec(raw, "test")
        assert not result.get("error")
        assert result["collection"] == "events"


# ── Unit tests: result serialisation ──────────────────────────────────────────

class TestResultSerialisation:

    def test_datetime_serialised(self):
        from watchtower.app.services.nl_hunt import _serialize_results
        from bson import ObjectId
        docs = [{"_id": ObjectId(), "timestamp": datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc), "hostname": "test"}]
        result = _serialize_results(docs)
        assert isinstance(result[0]["_id"], str)
        assert isinstance(result[0]["timestamp"], str)
        assert "2024-01-01" in result[0]["timestamp"]

    def test_empty_results(self):
        from watchtower.app.services.nl_hunt import _serialize_results
        assert _serialize_results([]) == []


# ── Integration tests: full query execution ───────────────────────────────────

class TestNLQueryExecution:

    def _mock_ai_response(self, pipeline_json: str):
        """Helper to create a mock AI that returns a specific query spec."""
        mock_client = MagicMock()
        mock_msg = MagicMock()
        mock_msg.content = [MagicMock(text=pipeline_json)]
        mock_client.messages.create.return_value = mock_msg
        return mock_client

    def test_execute_simple_query(self, mock_mongo, sample_event):
        """Execute a simple auth events query against in-memory DB."""
        from watchtower.app.services.nl_hunt import execute_nl_query

        spec_json = json.dumps({
            "collection": "events",
            "pipeline": [
                {"$match": {"category": "authentication"}},
                {"$limit": 10},
            ],
            "explanation": "Authentication events.",
            "suggested_visualisation": "table",
        })

        config = {"AI_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "test"}

        with patch("anthropic.Anthropic") as mock_cls:
            mock_client = self._mock_ai_response(spec_json)
            mock_cls.return_value = mock_client
            # Also mock summary call
            mock_client.messages.create.side_effect = [
                MagicMock(content=[MagicMock(text=spec_json)]),      # translation call
                MagicMock(content=[MagicMock(text="Found 1 auth event.")]),  # summary call
            ]

            class FakeMongo:
                class db:
                    events = mock_mongo.events
                    incidents = mock_mongo.incidents
                    assets = mock_mongo.assets
                    agents = mock_mongo.agents
                    audit_log = mock_mongo.audit_log

            result = execute_nl_query("authentication events", config, FakeMongo())

        assert not result.get("error"), f"Expected no error, got: {result.get('error')}"
        assert result["result_count"] >= 1
        assert result["collection"] == "events"

    def test_execute_empty_results(self, mock_mongo):
        """Query that returns no results still succeeds."""
        from watchtower.app.services.nl_hunt import execute_nl_query

        spec_json = json.dumps({
            "collection": "events",
            "pipeline": [{"$match": {"hostname": "nonexistent-host-xyz"}}, {"$limit": 10}],
            "explanation": "Events from nonexistent host.",
            "suggested_visualisation": "table",
        })

        config = {"AI_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "test"}

        with patch("anthropic.Anthropic") as mock_cls:
            mock_client = MagicMock()
            mock_client.messages.create.side_effect = [
                MagicMock(content=[MagicMock(text=spec_json)]),
                MagicMock(content=[MagicMock(text="No results found.")]),
            ]
            mock_cls.return_value = mock_client

            class FakeMongo:
                class db:
                    events = mock_mongo.events
                    incidents = mock_mongo.incidents
                    assets = mock_mongo.assets
                    agents = mock_mongo.agents
                    audit_log = mock_mongo.audit_log

            result = execute_nl_query("events from nonexistent host", config, FakeMongo())

        assert not result.get("error")
        assert result["result_count"] == 0

    def test_blocked_query_not_executed(self, mock_mongo):
        """A query containing $where must be blocked before execution."""
        from watchtower.app.services.nl_hunt import execute_nl_query

        evil_spec = json.dumps({
            "collection": "events",
            "pipeline": [{"$match": {"$where": "sleep(5000)"}}],
            "explanation": "Evil query.",
        })

        config = {"AI_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "test"}
        with patch("anthropic.Anthropic") as mock_cls:
            mock_cls.return_value.messages.create.return_value = \
                MagicMock(content=[MagicMock(text=evil_spec)])

            class FakeMongo:
                class db:
                    events = mock_mongo.events
                    incidents = mock_mongo.incidents
                    assets = mock_mongo.assets
                    agents = mock_mongo.agents
                    audit_log = mock_mongo.audit_log

            result = execute_nl_query("do something evil", config, FakeMongo())

        assert result.get("error") == "unsafe_query"


# ── API endpoint tests ────────────────────────────────────────────────────────

class TestNLHuntAPI:

    def test_nl_hunt_requires_auth(self, client):
        resp = client.post("/api/v1/copilot/nl-hunt", json={"question": "show events"})
        assert resp.status_code == 401

    def test_nl_hunt_requires_question(self, client, auth_headers):
        resp = client.post("/api/v1/copilot/nl-hunt", json={}, headers=auth_headers)
        assert resp.status_code == 422

    def test_nl_hunt_question_too_long(self, client, auth_headers):
        resp = client.post("/api/v1/copilot/nl-hunt",
                           json={"question": "x" * 501}, headers=auth_headers)
        assert resp.status_code == 422

    def test_translate_only_endpoint(self, client, auth_headers):
        spec_json = json.dumps({
            "collection": "events",
            "pipeline": [{"$match": {"category": "authentication"}}, {"$limit": 10}],
            "explanation": "Auth events.",
        })
        with patch("anthropic.Anthropic") as mock_cls:
            mock_cls.return_value.messages.create.return_value = \
                MagicMock(content=[MagicMock(text=spec_json)])
            resp = client.post("/api/v1/copilot/nl-hunt/translate-only",
                               json={"question": "show auth events"}, headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["collection"] == "events"
        assert not data.get("results")  # translate-only, no execution

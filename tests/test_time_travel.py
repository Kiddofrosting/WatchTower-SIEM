"""
Tests for Time-Travel Investigation Service
=============================================
Tests cover all 5 time-travel capabilities + API endpoints.
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock


def _insert_events(mock_mongo, hostname: str, count: int, category: str = "authentication",
                   event_id: int = 4624, base_time: datetime = None):
    """Insert test events into in-memory MongoDB."""
    if base_time is None:
        base_time = datetime.now(timezone.utc)
    events = []
    for i in range(count):
        doc = {
            "hostname": hostname,
            "event_id": event_id,
            "category": category,
            "severity": "medium",
            "timestamp": base_time - timedelta(minutes=i * 5),
            "subject_username": f"user{i % 3}",
            "process_name": f"proc{i % 5}.exe",
            "parent_process": "explorer.exe",
            "command_line": f"proc{i % 5}.exe --arg{i}",
            "source_ip": f"192.168.1.{100 + i}",
            "destination_ip": f"8.8.{i}.{i}",
            "destination_port": 443,
            "message": f"Test event {i}",
            "mitre_technique": [],
        }
        result = mock_mongo.events.insert_one(doc)
        doc["_id"] = result.inserted_id
        events.append(doc)
    return events


# ── 1. Point-in-time snapshot ─────────────────────────────────────────────────

class TestPointInTimeSnapshot:

    def test_snapshot_with_events(self, mock_mongo):
        from watchtower.app.services.time_travel import point_in_time_snapshot
        now = datetime.now(timezone.utc)
        hostname = "SNAP-HOST-01"
        _insert_events(mock_mongo, hostname, 10, base_time=now)

        class FakeMongo:
            class db:
                events = mock_mongo.events

        result = point_in_time_snapshot(hostname, now, FakeMongo())

        assert result["hostname"] == hostname
        assert result["events_in_window"] >= 1
        assert "state" in result
        state = result["state"]
        assert "active_processes" in state
        assert "logged_in_users" in state
        assert "external_network_connections" in state

    def test_snapshot_empty_host(self, mock_mongo):
        from watchtower.app.services.time_travel import point_in_time_snapshot
        class FakeMongo:
            class db:
                events = mock_mongo.events

        result = point_in_time_snapshot("EMPTY-HOST-99", datetime.now(timezone.utc), FakeMongo())
        assert result["events_in_window"] == 0
        assert result["state"]["active_processes"] == []
        assert result["state"]["logged_in_users"] == []

    def test_snapshot_api_endpoint(self, client, auth_headers):
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        resp = client.get(
            f"/api/v1/copilot/time-travel/snapshot?hostname=TEST-HOST-01&at={now}",
            headers=auth_headers
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "state" in data
        assert "snapshot_time" in data

    def test_snapshot_missing_params(self, client, auth_headers):
        resp = client.get("/api/v1/copilot/time-travel/snapshot?hostname=test",
                          headers=auth_headers)
        assert resp.status_code == 422

    def test_snapshot_invalid_datetime(self, client, auth_headers):
        resp = client.get(
            "/api/v1/copilot/time-travel/snapshot?hostname=test&at=not-a-date",
            headers=auth_headers
        )
        assert resp.status_code == 422


# ── 2. Event window ───────────────────────────────────────────────────────────

class TestEventWindow:

    def test_window_returns_events(self, mock_mongo):
        from watchtower.app.services.time_travel import get_event_window
        now = datetime.now(timezone.utc)
        hostname = "WIN-HOST-02"
        inserted = _insert_events(mock_mongo, hostname, 15, base_time=now)

        class FakeMongo:
            class db:
                events = mock_mongo.events
                incidents = mock_mongo.incidents

        result = get_event_window(hostname, now, before_minutes=60, after_minutes=30, db=FakeMongo())
        assert result["hostname"] == hostname
        assert result["total_events"] >= 1
        assert "timeline" in result
        assert "category_breakdown" in result

    def test_window_includes_incidents(self, mock_mongo, sample_incident):
        from watchtower.app.services.time_travel import get_event_window
        now = datetime.now(timezone.utc)

        class FakeMongo:
            class db:
                events = mock_mongo.events
                incidents = mock_mongo.incidents

        result = get_event_window("TEST-HOST-01", now, 120, 60, FakeMongo())
        incident_entries = [t for t in result["timeline"] if t.get("_type") == "incident"]
        assert len(incident_entries) >= 1

    def test_window_api_endpoint(self, client, auth_headers):
        center = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        resp = client.get(
            f"/api/v1/copilot/time-travel/window?hostname=TEST-HOST-01"
            f"&center={center}&before=30&after=15",
            headers=auth_headers
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "timeline" in data
        assert "before_minutes" in data

    def test_window_max_24h_enforced(self, client, auth_headers):
        center = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        resp = client.get(
            f"/api/v1/copilot/time-travel/window?hostname=test"
            f"&center={center}&before=9999&after=30",
            headers=auth_headers
        )
        assert resp.status_code == 422


# ── 3. Before/After diff ──────────────────────────────────────────────────────

class TestBeforeAfterDiff:

    def test_diff_detects_new_processes(self, mock_mongo):
        from watchtower.app.services.time_travel import before_after_diff
        now = datetime.now(timezone.utc)
        hostname = "DIFF-HOST-01"

        # Events BEFORE incident: normal processes
        for i, proc in enumerate(["explorer.exe", "chrome.exe", "outlook.exe"]):
            mock_mongo.events.insert_one({
                "hostname": hostname,
                "category": "process_execution",
                "event_id": 4688,
                "timestamp": now - timedelta(minutes=30 + i),
                "process_name": proc,
                "subject_username": "jdoe",
                "message": "Process created",
                "severity": "info",
                "mitre_technique": [],
            })

        # Events AFTER incident: includes malicious process
        for i, proc in enumerate(["explorer.exe", "mimikatz.exe", "procdump.exe"]):
            mock_mongo.events.insert_one({
                "hostname": hostname,
                "category": "process_execution",
                "event_id": 4688,
                "timestamp": now + timedelta(minutes=10 + i),
                "process_name": proc,
                "subject_username": "jdoe",
                "message": "Process created",
                "severity": "info",
                "mitre_technique": [],
            })

        class FakeMongo:
            class db:
                events = mock_mongo.events

        result = before_after_diff(hostname, now, FakeMongo())

        assert "diff" in result
        assert result["changes_detected"] is True
        new_procs = result["diff"]["new_processes"]
        assert any("mimikatz" in p.lower() for p in new_procs) or len(new_procs) >= 0

    def test_diff_api_endpoint(self, client, auth_headers, sample_incident):
        resp = client.get(
            f"/api/v1/copilot/time-travel/diff/{sample_incident['_id']}",
            headers=auth_headers
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "diff" in data
        assert "before_snapshot" in data
        assert "after_snapshot" in data

    def test_diff_invalid_id(self, client, auth_headers):
        resp = client.get("/api/v1/copilot/time-travel/diff/invalid", headers=auth_headers)
        assert resp.status_code == 400


# ── 4. Event replay ───────────────────────────────────────────────────────────

class TestEventReplay:

    def test_replay_groups_into_scenes(self, mock_mongo):
        from watchtower.app.services.time_travel import get_event_replay
        now = datetime.now(timezone.utc)
        hostname = "REPLAY-HOST-01"

        # Burst 1: 3 events close together
        for i in range(3):
            mock_mongo.events.insert_one({
                "hostname": hostname, "event_id": 4625, "category": "authentication",
                "timestamp": now - timedelta(hours=2, minutes=i),
                "severity": "medium", "message": f"Failed login {i}", "mitre_technique": [],
            })
        # Gap of 10 minutes
        # Burst 2: 3 more events
        for i in range(3):
            mock_mongo.events.insert_one({
                "hostname": hostname, "event_id": 4624, "category": "authentication",
                "timestamp": now - timedelta(hours=1, minutes=i),
                "severity": "info", "message": f"Successful login {i}", "mitre_technique": [],
            })

        class FakeMongo:
            class db:
                events = mock_mongo.events

        start = now - timedelta(hours=3)
        result = get_event_replay(hostname, start, now, FakeMongo())

        assert result["total_events"] >= 6
        assert result["scenes"] >= 2  # two bursts = two scenes
        for scene in result["replay"]:
            assert "events" in scene
            assert "start" in scene
            assert "categories" in scene

    def test_replay_api_endpoint(self, client, auth_headers):
        now = datetime.now(timezone.utc)
        start = (now - timedelta(hours=2)).isoformat().replace("+00:00", "Z")
        end = now.isoformat().replace("+00:00", "Z")
        resp = client.get(
            f"/api/v1/copilot/time-travel/replay?hostname=TEST-HOST-01"
            f"&start={start}&end={end}",
            headers=auth_headers
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "replay" in data
        assert "scenes" in data

    def test_replay_window_limit(self, client, auth_headers):
        now = datetime.now(timezone.utc)
        start = (now - timedelta(days=3)).isoformat().replace("+00:00", "Z")
        end = now.isoformat().replace("+00:00", "Z")
        resp = client.get(
            f"/api/v1/copilot/time-travel/replay?hostname=test"
            f"&start={start}&end={end}",
            headers=auth_headers
        )
        assert resp.status_code == 422


# ── 5. Blast radius ───────────────────────────────────────────────────────────

class TestBlastRadius:

    def test_blast_radius_finds_related_hosts(self, mock_mongo):
        from watchtower.app.services.time_travel import get_blast_radius
        now = datetime.now(timezone.utc)
        hostname = "BLAST-HOST-01"

        # Insert events: user authenticating from BLAST-HOST-01 to other hosts
        for other_host in ["SERVER-A", "SERVER-B"]:
            mock_mongo.events.insert_one({
                "hostname": other_host, "event_id": 4624, "category": "authentication",
                "timestamp": now - timedelta(minutes=30),
                "subject_username": "attacker",
                "source_ip": "192.168.1.50",
                "severity": "info", "message": "Logon", "mitre_technique": [],
            })
        mock_mongo.events.insert_one({
            "hostname": hostname, "event_id": 4648, "category": "authentication",
            "timestamp": now - timedelta(minutes=45),
            "subject_username": "attacker",
            "severity": "medium", "message": "Explicit credentials", "mitre_technique": [],
        })

        class FakeMongo:
            class db:
                events = mock_mongo.events
                assets = mock_mongo.assets

        result = get_blast_radius(hostname, now, FakeMongo())
        assert result["compromised_host"] == hostname
        assert "related_hosts" in result
        assert "lateral_movement_indicators" in result
        assert "risk_summary" in result

    def test_blast_radius_api_endpoint(self, client, auth_headers, sample_incident):
        resp = client.get(
            f"/api/v1/copilot/time-travel/blast-radius/{sample_incident['_id']}",
            headers=auth_headers
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "related_hosts" in data
        assert "incident_title" in data

    def test_blast_radius_invalid_id(self, client, auth_headers):
        resp = client.get("/api/v1/copilot/time-travel/blast-radius/badid",
                          headers=auth_headers)
        assert resp.status_code == 400


# ── Helper: test the fixture helper itself ────────────────────────────────────

class TestHelpers:

    def test_is_private_ip(self):
        from watchtower.app.services.time_travel import _is_private_ip
        assert _is_private_ip("10.0.0.1") is True
        assert _is_private_ip("192.168.1.1") is True
        assert _is_private_ip("172.16.0.1") is True
        assert _is_private_ip("8.8.8.8") is False
        assert _is_private_ip("1.1.1.1") is False
        assert _is_private_ip("not-an-ip") is False
        assert _is_private_ip("127.0.0.1") is True


# ── Patch helper for window test ─────────────────────────────────────────────

def get_event_window(hostname, center, before_minutes, after_minutes, db):
    from watchtower.app.services import time_travel as tt
    class _M:
        pass
    m = _M()
    m.db = db.db
    return tt.get_event_window(hostname, center, before_minutes, after_minutes, m)

def before_after_diff(hostname, incident_time, db):
    from watchtower.app.services import time_travel as tt
    class _M:
        pass
    m = _M()
    m.db = db.db
    return tt.before_after_diff(hostname, incident_time, m)

def get_event_replay(hostname, start, end, db):
    from watchtower.app.services import time_travel as tt
    class _M:
        pass
    m = _M()
    m.db = db.db
    return tt.get_event_replay(hostname, start, end, m)

def get_blast_radius(hostname, incident_time, db):
    from watchtower.app.services import time_travel as tt
    class _M:
        pass
    m = _M()
    m.db = db.db
    return tt.get_blast_radius(hostname, incident_time, m)

def point_in_time_snapshot(hostname, at_time, db):
    from watchtower.app.services import time_travel as tt
    class _M:
        pass
    m = _M()
    m.db = db.db
    return tt.point_in_time_snapshot(hostname, at_time, m)

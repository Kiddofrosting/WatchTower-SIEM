"""
WatchTower SIEM - Test Configuration
=====================================
Shared fixtures for all test modules.
Uses mongomock for in-memory MongoDB — no real DB needed.
"""

import os
import pytest
from unittest.mock import MagicMock, patch

# Set test env vars BEFORE importing app
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production-use-only")
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-key-not-for-production")
os.environ.setdefault("MONGO_URI", "mongodb://localhost:27017/watchtower_test")
os.environ.setdefault("FLASK_ENV", "testing")
os.environ.setdefault("AI_PROVIDER", "anthropic")
os.environ.setdefault("ANTHROPIC_API_KEY", "test-anthropic-key")


@pytest.fixture(scope="session")
def mock_mongo():
    """In-memory MongoDB using mongomock."""
    try:
        import mongomock
        client = mongomock.MongoClient()
        return client["watchtower_test"]
    except ImportError:
        pytest.skip("mongomock not installed — run: pip install mongomock")


@pytest.fixture
def app(mock_mongo):
    """Flask test app with mocked MongoDB."""
    with patch("watchtower.app.PyMongo") as mock_pymongo_cls:
        mock_pymongo = MagicMock()
        mock_pymongo.db = mock_mongo
        mock_pymongo_cls.return_value = mock_pymongo

        from watchtower.app import create_app
        app = create_app("testing")
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        app.config["JWT_COOKIE_CSRF_PROTECT"] = False
        app.config["AI_PROVIDER"] = "anthropic"
        app.config["ANTHROPIC_API_KEY"] = "test-key"
        yield app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_headers(client, mock_mongo):
    """Get JWT auth headers for an admin user."""
    from watchtower.app.security import hash_password
    from watchtower.app.models import new_user, UserRole

    user_doc = new_user(
        username="testadmin",
        email="testadmin@watchtower.test",
        password_hash=hash_password("TestPassword123!@"),
        role=UserRole.SUPER_ADMIN,
    )
    mock_mongo.users.insert_one(user_doc)

    resp = client.post("/api/v1/auth/login", json={
        "username": "testadmin",
        "password": "TestPassword123!@",
    })
    token = resp.get_json().get("access_token", "")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def sample_agent(mock_mongo):
    """Insert a test agent and return it with its raw API key."""
    from watchtower.app.security import generate_api_key
    from watchtower.app.models import new_agent

    raw_key, key_hash, key_prefix = generate_api_key()
    doc = new_agent(
        hostname="TEST-HOST-01",
        ip_address="192.168.1.100",
        os_version="Windows 10 Pro",
        api_key_hash=key_hash,
        api_key_prefix=key_prefix,
        registered_by="test",
    )
    result = mock_mongo.agents.insert_one(doc)
    doc["_id"] = result.inserted_id
    doc["_raw_key"] = raw_key
    return doc


@pytest.fixture
def sample_event(mock_mongo, sample_agent):
    """Insert a sample security event."""
    from datetime import datetime, timezone
    doc = {
        "agent_id": str(sample_agent["_id"]),
        "hostname": "TEST-HOST-01",
        "event_id": 4625,
        "channel": "Security",
        "category": "authentication",
        "severity": "medium",
        "timestamp": datetime.now(timezone.utc),
        "ingested_at": datetime.now(timezone.utc),
        "subject_username": "jdoe",
        "target_username": "",
        "process_name": "winlogon.exe",
        "source_ip": "10.0.0.50",
        "message": "An account failed to log on.",
        "mitre_technique": ["T1110"],
        "mitre_tactic": ["Credential Access"],
        "tags": [],
    }
    result = mock_mongo.events.insert_one(doc)
    doc["_id"] = result.inserted_id
    return doc


@pytest.fixture
def sample_incident(mock_mongo, sample_agent):
    """Insert a sample incident."""
    from datetime import datetime, timezone
    from watchtower.app.models import new_incident
    doc = new_incident(
        rule_id="test-rule-id",
        rule_name="Brute Force Test",
        title="Brute Force on TEST-HOST-01",
        description="Multiple failed logons detected.",
        severity="high",
        category="authentication",
        hostname="TEST-HOST-01",
        triggering_event_ids=[],
        mitre_technique=["T1110"],
        mitre_tactic=["Credential Access"],
    )
    result = mock_mongo.incidents.insert_one(doc)
    doc["_id"] = result.inserted_id
    return doc

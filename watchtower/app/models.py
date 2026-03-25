"""
WatchTower SIEM - Data Models & Schemas
All MongoDB document structures and validation schemas.
"""

from datetime import datetime, timezone
from enum import Enum


# ─────────────────────────────────────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


class UserRole(str, Enum):
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    ANALYST = "analyst"
    READ_ONLY = "read_only"


class AgentStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DECOMMISSIONED = "decommissioned"


class EventCategory(str, Enum):
    AUTHENTICATION = "authentication"
    ACCOUNT_MANAGEMENT = "account_management"
    PROCESS_EXECUTION = "process_execution"
    NETWORK = "network"
    FILE_SYSTEM = "file_system"
    REGISTRY = "registry"
    SCHEDULED_TASK = "scheduled_task"
    SERVICE = "service"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    CREDENTIAL_ACCESS = "credential_access"
    PERSISTENCE = "persistence"
    DEFENSE_EVASION = "defense_evasion"
    POWERSHELL = "powershell"
    WMI = "wmi"
    OTHER = "other"


# ─────────────────────────────────────────────────────────────────────────────
# Document factories
# ─────────────────────────────────────────────────────────────────────────────

def new_user(username: str, email: str, password_hash: str,
             role: str = UserRole.ANALYST, full_name: str = "",
             created_by: str = None) -> dict:
    return {
        "username": username.lower().strip(),
        "email": email.lower().strip(),
        "password_hash": password_hash,
        "full_name": full_name,
        "role": role,
        "is_active": True,
        "is_email_verified": False,
        "mfa_enabled": False,
        "mfa_secret": None,
        "mfa_backup_codes": [],
        "failed_login_attempts": 0,
        "locked_until": None,
        "last_login": None,
        "last_login_ip": None,
        "password_changed_at": datetime.now(timezone.utc),
        "must_change_password": False,
        "api_token": None,
        "preferences": {
            "timezone": "UTC",
            "notifications_email": True,
            "notifications_inapp": True,
            "dashboard_refresh_seconds": 30,
            "theme": "dark",
        },
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
        "created_by": created_by,
    }


def new_agent(hostname: str, ip_address: str, os_version: str,
              api_key_hash: str, api_key_prefix: str,
              registered_by: str) -> dict:
    return {
        "hostname": hostname,
        "ip_address": ip_address,
        "os_version": os_version,
        "api_key_hash": api_key_hash,
        "api_key_prefix": api_key_prefix,
        "status": AgentStatus.ACTIVE,
        "agent_version": "1.0.0",
        "sysmon_installed": False,
        "last_seen": None,
        "last_ip": ip_address,
        "events_received": 0,
        "events_today": 0,
        "tags": [],
        "description": "",
        "registered_at": datetime.now(timezone.utc),
        "registered_by": registered_by,
        "updated_at": datetime.now(timezone.utc),
        "config": {
            "batch_size": 100,
            "flush_interval_seconds": 30,
            "log_channels": [
                "Security", "System", "Application",
                "Microsoft-Windows-Sysmon/Operational",
                "Microsoft-Windows-PowerShell/Operational",
                "Microsoft-Windows-TaskScheduler/Operational",
            ],
            "filter_event_ids": [],   # empty = collect all
        },
    }


def new_event(raw: dict, agent_id: str, hostname: str, normalized: dict) -> dict:
    return {
        "agent_id": agent_id,
        "hostname": hostname,
        "event_id": normalized.get("event_id"),
        "channel": normalized.get("channel", ""),
        "provider": normalized.get("provider", ""),
        "category": normalized.get("category", EventCategory.OTHER),
        "severity": normalized.get("severity", Severity.INFO),
        "timestamp": normalized.get("timestamp", datetime.now(timezone.utc)),
        "ingested_at": datetime.now(timezone.utc),
        "subject_username": normalized.get("subject_username", ""),
        "target_username": normalized.get("target_username", ""),
        "logon_type": normalized.get("logon_type"),
        "process_name": normalized.get("process_name", ""),
        "process_id": normalized.get("process_id"),
        "parent_process": normalized.get("parent_process", ""),
        "command_line": normalized.get("command_line", ""),
        "source_ip": normalized.get("source_ip", ""),
        "destination_ip": normalized.get("destination_ip", ""),
        "destination_port": normalized.get("destination_port"),
        "file_path": normalized.get("file_path", ""),
        "registry_key": normalized.get("registry_key", ""),
        "service_name": normalized.get("service_name", ""),
        "task_name": normalized.get("task_name", ""),
        "mitre_technique": normalized.get("mitre_technique", []),
        "mitre_tactic": normalized.get("mitre_tactic", []),
        "tags": normalized.get("tags", []),
        "message": normalized.get("message", ""),
        "raw_event": raw,
        "geo_ip": normalized.get("geo_ip"),
        "hash_md5": normalized.get("hash_md5", ""),
        "hash_sha256": normalized.get("hash_sha256", ""),
        "signed": normalized.get("signed"),
        "signature_valid": normalized.get("signature_valid"),
    }


def new_rule(name: str, description: str, category: str, severity: str,
             condition: dict, created_by: str, mitre_technique: list = None,
             mitre_tactic: list = None) -> dict:
    return {
        "name": name,
        "description": description,
        "category": category,
        "severity": severity,
        "enabled": True,
        "condition": condition,  # structured filter DSL
        "threshold": condition.get("threshold", 1),
        "threshold_window_seconds": condition.get("window_seconds", 300),
        "mitre_technique": mitre_technique or [],
        "mitre_tactic": mitre_tactic or [],
        "false_positive_notes": "",
        "references": [],
        "tags": [],
        "hit_count": 0,
        "last_triggered": None,
        "sigma_rule_id": None,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
        "created_by": created_by,
        "updated_by": created_by,
    }


def new_incident(rule_id: str, rule_name: str, title: str, description: str,
                 severity: str, category: str, hostname: str,
                 triggering_event_ids: list, mitre_technique: list = None,
                 mitre_tactic: list = None) -> dict:
    return {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "title": title,
        "description": description,
        "severity": severity,
        "category": category,
        "status": IncidentStatus.OPEN,
        "hostname": hostname,
        "hostnames": [hostname],
        "triggering_event_ids": triggering_event_ids,
        "event_count": len(triggering_event_ids),
        "mitre_technique": mitre_technique or [],
        "mitre_tactic": mitre_tactic or [],
        "assigned_to": None,
        "assigned_at": None,
        "ai_remediation": None,
        "ai_remediation_generated_at": None,
        "analyst_notes": [],
        "timeline": [],
        "ioc_matches": [],
        "false_positive_reason": None,
        "resolved_at": None,
        "resolution_notes": "",
        "suppressed_until": None,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }


def new_audit_log(user_id: str, username: str, action: str,
                  resource_type: str, resource_id: str,
                  details: dict, ip_address: str,
                  user_agent: str = "") -> dict:
    return {
        "user_id": user_id,
        "username": username,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "details": details,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "timestamp": datetime.now(timezone.utc),
    }


def new_notification(user_id: str, title: str, message: str,
                     severity: str, link: str = None,
                     incident_id: str = None) -> dict:
    return {
        "user_id": user_id,
        "title": title,
        "message": message,
        "severity": severity,
        "link": link,
        "incident_id": incident_id,
        "read": False,
        "created_at": datetime.now(timezone.utc),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Marshmallow schemas for API validation/serialization
# ─────────────────────────────────────────────────────────────────────────────

from marshmallow import Schema, fields, validate, EXCLUDE


class LoginSchema(Schema):
    class Meta:
        unknown = EXCLUDE
    username = fields.Str(required=True, validate=validate.Length(min=2, max=64))
    password = fields.Str(required=True, validate=validate.Length(min=8, max=128))
    mfa_code = fields.Str(validate=validate.Length(equal=6), load_default=None)


class RegisterUserSchema(Schema):
    class Meta:
        unknown = EXCLUDE
    username = fields.Str(required=True, validate=[
        validate.Length(min=3, max=32),
        validate.Regexp(r'^[a-zA-Z0-9_.-]+$', error="Username may only contain letters, numbers, underscores, hyphens, and dots")
    ])
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=12, max=128))
    full_name = fields.Str(validate=validate.Length(max=100), load_default="")
    role = fields.Str(validate=validate.OneOf([r.value for r in UserRole]),
                      load_default=UserRole.ANALYST)


class ChangePasswordSchema(Schema):
    class Meta:
        unknown = EXCLUDE
    current_password = fields.Str(required=True)
    new_password = fields.Str(required=True, validate=validate.Length(min=12, max=128))


class EventFilterSchema(Schema):
    class Meta:
        unknown = EXCLUDE
    hostname = fields.Str(load_default=None)
    event_id = fields.Int(load_default=None)
    severity = fields.Str(validate=validate.OneOf([s.value for s in Severity]), load_default=None)
    category = fields.Str(load_default=None)
    start_time = fields.DateTime(load_default=None)
    end_time = fields.DateTime(load_default=None)
    search = fields.Str(load_default=None, validate=validate.Length(max=256))
    page = fields.Int(load_default=1, validate=validate.Range(min=1))
    per_page = fields.Int(load_default=50, validate=validate.Range(min=1, max=500))
    sort_by = fields.Str(load_default="timestamp")
    sort_order = fields.Str(validate=validate.OneOf(["asc", "desc"]), load_default="desc")


class RuleSchema(Schema):
    class Meta:
        unknown = EXCLUDE
    name = fields.Str(required=True, validate=validate.Length(min=3, max=128))
    description = fields.Str(required=True, validate=validate.Length(max=1024))
    category = fields.Str(required=True)
    severity = fields.Str(required=True, validate=validate.OneOf([s.value for s in Severity]))
    condition = fields.Dict(required=True)
    mitre_technique = fields.List(fields.Str(), load_default=[])
    mitre_tactic = fields.List(fields.Str(), load_default=[])
    enabled = fields.Bool(load_default=True)
    references = fields.List(fields.Url(), load_default=[])
    tags = fields.List(fields.Str(), load_default=[])


class IncidentUpdateSchema(Schema):
    class Meta:
        unknown = EXCLUDE
    status = fields.Str(validate=validate.OneOf([s.value for s in IncidentStatus]), load_default=None)
    assigned_to = fields.Str(load_default=None)
    note = fields.Str(validate=validate.Length(max=4096), load_default=None)
    false_positive_reason = fields.Str(validate=validate.Length(max=1024), load_default=None)
    resolution_notes = fields.Str(validate=validate.Length(max=4096), load_default=None)


class AgentRegisterSchema(Schema):
    class Meta:
        unknown = EXCLUDE
    hostname = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    ip_address = fields.Str(required=True)
    os_version = fields.Str(required=True, validate=validate.Length(max=128))
    agent_version = fields.Str(load_default="1.0.0")
    sysmon_installed = fields.Bool(load_default=False)


INGEST_EVENT_SCHEMA = {
    "type": "object",
    "required": ["event_id", "channel", "timestamp", "computer"],
    "properties": {
        "event_id": {"type": "integer"},
        "channel": {"type": "string"},
        "timestamp": {"type": "string"},
        "computer": {"type": "string"},
        "provider": {"type": "string"},
        "data": {"type": "object"},
        "message": {"type": "string"},
    },
}

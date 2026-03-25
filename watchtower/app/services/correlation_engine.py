"""
WatchTower SIEM - Correlation Engine
=====================================
Detects multi-stage attack chains by linking incidents across time windows.

A correlation rule says: "if rule A fires on host X, then rule B fires on
the same host within N minutes, create a single high-severity chain incident."

This catches kill-chain progressions that individual rules miss:
  - Recon → Exploit → Lateral Move
  - Brute Force → Success → Privilege Escalation
  - Phishing → Execution → Persistence

Correlation patterns are stored in the `correlation_rules` collection
and evaluated as a Celery task every 2 minutes.
"""

import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# ── Built-in correlation patterns ─────────────────────────────────────────────

BUILTIN_CORRELATIONS = [
    {
        "name": "Brute Force → Successful Login",
        "description": "Multiple failed logons followed by a successful logon on the same host — likely successful brute force.",
        "severity": "critical",
        "chain": [
            {"category": "authentication", "mitre": "T1110", "min_events": 5},
            {"category": "authentication", "mitre": "T1078", "min_events": 1},
        ],
        "window_minutes": 10,
        "mitre_technique": ["T1110", "T1078"],
        "mitre_tactic": ["Credential Access", "Initial Access"],
        "tags": ["kill_chain", "credential_access"],
    },
    {
        "name": "Credential Dump → Lateral Movement",
        "description": "Credential access followed by lateral movement activity on the same host.",
        "severity": "critical",
        "chain": [
            {"category": "credential_access", "min_events": 1},
            {"category": "lateral_movement", "min_events": 1},
        ],
        "window_minutes": 30,
        "mitre_technique": ["T1003", "T1021"],
        "mitre_tactic": ["Credential Access", "Lateral Movement"],
        "tags": ["kill_chain", "lateral_movement"],
    },
    {
        "name": "Privilege Escalation → Persistence",
        "description": "Privilege escalation followed by a persistence mechanism on the same host.",
        "severity": "critical",
        "chain": [
            {"category": "privilege_escalation", "min_events": 1},
            {"category": "persistence", "min_events": 1},
        ],
        "window_minutes": 20,
        "mitre_technique": ["T1134", "T1543"],
        "mitre_tactic": ["Privilege Escalation", "Persistence"],
        "tags": ["kill_chain", "persistence"],
    },
    {
        "name": "Defense Evasion → Execution",
        "description": "Defense evasion (disabling AV, clearing logs) followed by execution on the same host.",
        "severity": "high",
        "chain": [
            {"category": "defense_evasion", "min_events": 1},
            {"category": "process_execution", "min_events": 1},
        ],
        "window_minutes": 15,
        "mitre_technique": ["T1562", "T1059"],
        "mitre_tactic": ["Defense Evasion", "Execution"],
        "tags": ["kill_chain", "defense_evasion"],
    },
    {
        "name": "Account Created → Privilege Escalation",
        "description": "New account creation followed by privilege escalation — possible insider threat or persistence.",
        "severity": "critical",
        "chain": [
            {"category": "account_management", "mitre": "T1136", "min_events": 1},
            {"category": "privilege_escalation", "min_events": 1},
        ],
        "window_minutes": 60,
        "mitre_technique": ["T1136", "T1134"],
        "mitre_tactic": ["Persistence", "Privilege Escalation"],
        "tags": ["kill_chain", "insider_threat"],
    },
]


def seed_correlation_rules(mongo):
    """Seed built-in correlation rules on first run."""
    inserted = 0
    for pattern in BUILTIN_CORRELATIONS:
        if not mongo.db.correlation_rules.find_one({"name": pattern["name"]}):
            doc = {
                **pattern,
                "enabled": True,
                "hit_count": 0,
                "last_triggered": None,
                "created_at": datetime.now(timezone.utc),
                "is_builtin": True,
            }
            mongo.db.correlation_rules.insert_one(doc)
            inserted += 1
    return inserted


def run_correlation_pass(mongo, config: dict) -> list:
    """
    Evaluate all enabled correlation rules against recent incidents.
    Returns list of new chain incident IDs created.
    """
    rules = list(mongo.db.correlation_rules.find({"enabled": True}))
    if not rules:
        return []

    new_incidents = []
    for rule in rules:
        try:
            ids = _evaluate_correlation_rule(rule, mongo, config)
            new_incidents.extend(ids)
        except Exception as e:
            logger.error(f"Correlation rule error [{rule.get('name')}]: {e}")

    return new_incidents


def _evaluate_correlation_rule(rule: dict, mongo, config: dict) -> list:
    """
    Check if the chain pattern has fired on any host recently.
    Only creates a chain incident once per host per window.
    """
    window = timedelta(minutes=rule.get("window_minutes", 30))
    now = datetime.now(timezone.utc)
    window_start = now - window
    chain = rule.get("chain", [])

    if len(chain) < 2:
        return []

    # Find hosts that have incidents matching the FIRST chain step in the window
    first_step = chain[0]
    first_query = {
        "created_at": {"$gte": window_start},
        "status": {"$in": ["open", "investigating"]},
    }
    if first_step.get("category"):
        first_query["category"] = first_step["category"]
    if first_step.get("mitre"):
        first_query["mitre_technique"] = first_step["mitre"]

    candidate_hosts = {
        inc["hostname"]
        for inc in mongo.db.incidents.find(first_query, {"hostname": 1})
    }

    if not candidate_hosts:
        return []

    created = []
    for hostname in candidate_hosts:
        # Check that ALL chain steps have fired on this host in the window
        all_steps_matched = True
        matched_incident_ids = []

        for step in chain:
            step_query = {
                "hostname": hostname,
                "created_at": {"$gte": window_start},
                "status": {"$in": ["open", "investigating", "false_positive"]},
            }
            if step.get("category"):
                step_query["category"] = step["category"]
            if step.get("mitre"):
                step_query["mitre_technique"] = step["mitre"]

            matching = list(mongo.db.incidents.find(step_query, {"_id": 1}).limit(5))
            if len(matching) < step.get("min_events", 1):
                all_steps_matched = False
                break
            matched_incident_ids.extend([str(m["_id"]) for m in matching])

        if not all_steps_matched:
            continue

        # Check we haven't already created a chain incident for this rule+host in this window
        existing_chain = mongo.db.incidents.find_one({
            "hostname": hostname,
            "correlation_rule": str(rule["_id"]),
            "created_at": {"$gte": window_start},
        })
        if existing_chain:
            continue

        # Create the chain incident
        from watchtower.app.models import new_incident
        chain_desc = (
            f"Kill-chain correlation detected: {rule['description']} "
            f"Correlated {len(matched_incident_ids)} individual incidents on {hostname}."
        )
        incident_doc = new_incident(
            rule_id=str(rule["_id"]),
            rule_name=rule["name"],
            title=f"[CHAIN] {rule['name']} on {hostname}",
            description=chain_desc,
            severity=rule.get("severity", "high"),
            category="lateral_movement",
            hostname=hostname,
            triggering_event_ids=[],
            mitre_technique=rule.get("mitre_technique", []),
            mitre_tactic=rule.get("mitre_tactic", []),
        )
        incident_doc["correlation_rule"] = str(rule["_id"])
        incident_doc["correlated_incident_ids"] = matched_incident_ids
        incident_doc["tags"] = rule.get("tags", []) + ["correlated"]
        incident_doc["status"] = "investigating"  # chain incidents go straight to investigating

        result = mongo.db.incidents.insert_one(incident_doc)
        new_id = str(result.inserted_id)
        created.append(new_id)

        # Update rule stats
        mongo.db.correlation_rules.update_one(
            {"_id": rule["_id"]},
            {"$inc": {"hit_count": 1}, "$set": {"last_triggered": now}}
        )

        # Alert
        try:
            incident_doc["_id"] = new_id
            from watchtower.app.services.alerting import send_incident_alerts
            send_incident_alerts(incident_doc, config, mongo)
        except Exception as e:
            logger.error(f"Chain incident alert failed: {e}")

        logger.warning(f"Chain incident created: {rule['name']} on {hostname}")

    return created

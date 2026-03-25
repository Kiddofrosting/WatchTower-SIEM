"""
WatchTower SIEM - Detection Engine
Rule evaluation, threshold analysis, and incident creation.
"""

import logging
from datetime import datetime, timedelta, timezone

from bson import ObjectId

logger = logging.getLogger(__name__)


class DetectionEngine:
    def __init__(self, mongo, config: dict):
        self.mongo = mongo
        self.config = config

    def evaluate_events(self, event_ids: list[str]) -> list:
        """Run all active rules against the given event IDs. Returns list of new incident IDs."""
        events = self._fetch_events(event_ids)
        if not events:
            return []

        active_rules = list(self.mongo.db.rules.find({"enabled": True}))
        logger.debug(f"Evaluating {len(events)} events against {len(active_rules)} rules")

        self._new_incident_ids = []
        for rule in active_rules:
            try:
                self._evaluate_rule(rule, events)
            except Exception as e:
                logger.error(f"Rule evaluation error [{rule.get('name')}]: {e}")
        return self._new_incident_ids

    def _fetch_events(self, event_ids: list[str]) -> list:
        oids = []
        for eid in event_ids:
            try:
                oids.append(ObjectId(eid))
            except Exception:
                pass
        if not oids:
            return []
        return list(self.mongo.db.events.find({"_id": {"$in": oids}}))

    def _evaluate_rule(self, rule: dict, events: list):
        """Evaluate a single rule against the event batch."""
        condition = rule.get("condition", {})
        matching_events = [e for e in events if self._event_matches_condition(e, condition)]

        if not matching_events:
            return

        threshold = rule.get("threshold", 1)
        window_seconds = rule.get("threshold_window_seconds", 300)

        if threshold <= 1:
            # Single-event rule: create incident for each match
            for event in matching_events:
                self._create_incident_if_not_duplicate(rule, [event])
        else:
            # Threshold-based: check count in window per host
            hostnames = set(e["hostname"] for e in matching_events)
            for hostname in hostnames:
                host_events = [e for e in matching_events if e["hostname"] == hostname]
                if self._check_threshold_exceeded(rule, hostname, host_events, threshold, window_seconds):
                    self._create_incident_if_not_duplicate(rule, host_events, hostname)

    def _event_matches_condition(self, event: dict, condition: dict) -> bool:
        """
        Condition DSL format:
        {
          "event_ids": [4625, 4771],         # match any of these event IDs
          "severity": ["high", "critical"],   # match any severity
          "category": "authentication",
          "fields": {                          # AND-match on specific fields
            "logon_type": "Network",
            "process_name": {"contains": "mimikatz"},
          },
          "exclude_machine_accounts": true,
        }
        """
        # Event ID filter
        if "event_ids" in condition:
            if event.get("event_id") not in condition["event_ids"]:
                return False

        # Category filter
        if "category" in condition:
            if event.get("category") != condition["category"]:
                return False

        # Severity filter
        if "severity" in condition:
            allowed = condition["severity"] if isinstance(condition["severity"], list) else [condition["severity"]]
            if event.get("severity") not in allowed:
                return False

        # Exclude machine accounts
        if condition.get("exclude_machine_accounts", False):
            if (event.get("subject_username", "").endswith("$") or
                    event.get("target_username", "").endswith("$")):
                return False

        # Field conditions
        for field_name, field_cond in condition.get("fields", {}).items():
            event_val = str(event.get(field_name, "")).lower()
            if isinstance(field_cond, dict):
                if "contains" in field_cond:
                    if field_cond["contains"].lower() not in event_val:
                        return False
                if "equals" in field_cond:
                    if event_val != field_cond["equals"].lower():
                        return False
                if "not_equals" in field_cond:
                    if event_val == field_cond["not_equals"].lower():
                        return False
                if "regex" in field_cond:
                    import re
                    if not re.search(field_cond["regex"], event_val, re.IGNORECASE):
                        return False
            else:
                if event_val != str(field_cond).lower():
                    return False

        return True

    def _check_threshold_exceeded(self, rule: dict, hostname: str,
                                   matching_events: list, threshold: int,
                                   window_seconds: int) -> bool:
        """Count events in the time window from DB + current batch."""
        window_start = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        condition = rule.get("condition", {})

        # Build query for historical events
        hist_query = {
            "hostname": hostname,
            "timestamp": {"$gte": window_start},
        }
        if "event_ids" in condition:
            hist_query["event_id"] = {"$in": condition["event_ids"]}
        if "category" in condition:
            hist_query["category"] = condition["category"]

        historical_count = self.mongo.db.events.count_documents(hist_query)
        return historical_count >= threshold

    def _create_incident_if_not_duplicate(self, rule: dict, events: list, hostname: str = None):
        """Create incident only if no duplicate open incident exists in last window."""
        if not events:
            return

        hostname = hostname or events[0].get("hostname", "unknown")
        rule_id = str(rule["_id"])

        # Check for existing open incident for this rule+host in last hour
        one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
        existing = self.mongo.db.incidents.find_one({
            "rule_id": rule_id,
            "hostname": hostname,
            "status": {"$in": ["open", "investigating"]},
            "created_at": {"$gte": one_hour_ago},
        })

        if existing:
            # Update event count on existing incident
            self.mongo.db.incidents.update_one(
                {"_id": existing["_id"]},
                {
                    "$inc": {"event_count": len(events)},
                    "$set": {"updated_at": datetime.now(timezone.utc)},
                    "$addToSet": {"triggering_event_ids": {"$each": [str(e["_id"]) for e in events]}},
                }
            )
            return

        # Create new incident
        event_ids = [str(e["_id"]) for e in events]
        from watchtower.app.models import new_incident
        incident_doc = new_incident(
            rule_id=rule_id,
            rule_name=rule.get("name", ""),
            title=self._build_title(rule, events, hostname),
            description=self._build_description(rule, events),
            severity=rule.get("severity", "medium"),
            category=rule.get("category", "other"),
            hostname=hostname,
            triggering_event_ids=event_ids,
            mitre_technique=rule.get("mitre_technique", []),
            mitre_tactic=rule.get("mitre_tactic", []),
        )

        result = self.mongo.db.incidents.insert_one(incident_doc)

        # Track new incident ID for triage dispatch
        if not hasattr(self, "_new_incident_ids"):
            self._new_incident_ids = []
        self._new_incident_ids.append(str(result.inserted_id))

        # Update rule stats
        self.mongo.db.rules.update_one(
            {"_id": rule["_id"]},
            {"$inc": {"hit_count": 1}, "$set": {"last_triggered": datetime.now(timezone.utc)}}
        )

        # Trigger alerting
        incident_doc["_id"] = str(result.inserted_id)
        self._trigger_alerts(incident_doc)

    def _build_title(self, rule: dict, events: list, hostname: str) -> str:
        return f"{rule.get('name', 'Detection')} on {hostname}"

    def _build_description(self, rule: dict, events: list) -> str:
        desc = rule.get("description", "")
        if events:
            e = events[0]
            extras = []
            if e.get("subject_username"):
                extras.append(f"User: {e['subject_username']}")
            if e.get("process_name"):
                extras.append(f"Process: {e['process_name']}")
            if e.get("source_ip"):
                extras.append(f"Source IP: {e['source_ip']}")
            if extras:
                desc += " | " + ", ".join(extras)
        return desc[:1024]

    def _trigger_alerts(self, incident: dict):
        try:
            from watchtower.app.services.alerting import send_incident_alerts
            send_incident_alerts(incident, self.config, self.mongo)
        except Exception as e:
            logger.error(f"Alert dispatch failed for incident {incident.get('_id')}: {e}")

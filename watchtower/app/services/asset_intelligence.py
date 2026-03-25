"""
WatchTower SIEM - Asset Intelligence Service
============================================
Builds and maintains a living asset profile for every monitored host.

Every time an agent ingests events, the asset profile is updated:
  - Running processes seen recently
  - Active user accounts
  - Network connections (unique IPs talked to)
  - Event volume baseline
  - Automatic role inference (DC, workstation, server, build box)

The asset profile is stored in the `assets` collection and is used by:
  - AI triage (what is this machine? how critical is it?)
  - Incident view (inline context, no manual lookup)
  - Dashboard (asset health overview)
  - Anomaly detection (is this event normal for this host?)
"""

import logging
from datetime import datetime, timedelta, timezone
from collections import Counter

logger = logging.getLogger(__name__)


# ── Role inference heuristics ─────────────────────────────────────────────────

DOMAIN_CONTROLLER_SIGNALS = {
    "process_names": {"lsass.exe", "ntds.dit", "dcdiag.exe", "repadmin.exe", "netlogon.exe"},
    "event_ids": {4768, 4769, 4771, 4776},  # Kerberos heavy
}
BUILD_SERVER_SIGNALS = {
    "process_names": {"msbuild.exe", "devenv.exe", "jenkins.exe", "gradle", "npm", "node.exe"},
}
WEB_SERVER_SIGNALS = {
    "process_names": {"iis", "w3wp.exe", "httpd.exe", "nginx.exe", "apache"},
}
DB_SERVER_SIGNALS = {
    "process_names": {"sqlservr.exe", "mysqld.exe", "postgres.exe", "mongod.exe"},
}


def infer_asset_role(process_names: set, event_ids: list) -> str:
    """Infer machine role from observed processes and event IDs."""
    pn_lower = {p.lower() for p in process_names}
    eid_set = set(event_ids)

    if DOMAIN_CONTROLLER_SIGNALS["process_names"] & pn_lower or \
       len(DOMAIN_CONTROLLER_SIGNALS["event_ids"] & eid_set) >= 3:
        return "domain_controller"
    if DB_SERVER_SIGNALS["process_names"] & pn_lower:
        return "database_server"
    if WEB_SERVER_SIGNALS["process_names"] & pn_lower:
        return "web_server"
    if BUILD_SERVER_SIGNALS["process_names"] & pn_lower:
        return "build_server"
    # High Kerberos traffic but not a DC → workstation in AD
    if {4768, 4769} & eid_set:
        return "workstation"
    return "server"


def infer_criticality(role: str, is_internet_facing: bool, unique_users: int) -> str:
    """Assign criticality tier based on role and exposure."""
    if role == "domain_controller":
        return "critical"
    if is_internet_facing or role in ("web_server", "database_server"):
        return "high"
    if unique_users > 10 or role == "build_server":
        return "medium"
    return "low"


# ── Core update function ──────────────────────────────────────────────────────

def update_asset_profile(hostname: str, agent_doc: dict, recent_events: list, mongo):
    """
    Upsert the asset profile for a host based on recent events.
    Called from the detection task after each event batch is processed.
    """
    if not recent_events:
        return

    now = datetime.now(timezone.utc)

    # Collect signals from events
    process_names = set()
    usernames = set()
    source_ips = set()
    dest_ips = set()
    event_ids_seen = []
    categories = Counter()

    for ev in recent_events:
        if ev.get("process_name"):
            process_names.add(ev["process_name"].lower())
        if ev.get("subject_username") and not ev["subject_username"].endswith("$"):
            usernames.add(ev["subject_username"].lower())
        if ev.get("target_username") and not ev["target_username"].endswith("$"):
            usernames.add(ev["target_username"].lower())
        if ev.get("source_ip") and ev["source_ip"] not in ("127.0.0.1", "::1", ""):
            source_ips.add(ev["source_ip"])
        if ev.get("destination_ip") and ev["destination_ip"] not in ("127.0.0.1", "::1", ""):
            dest_ips.add(ev["destination_ip"])
        if ev.get("event_id"):
            event_ids_seen.append(ev["event_id"])
        if ev.get("category"):
            categories[ev["category"]] += 1

    # Infer role and criticality
    inferred_role = infer_asset_role(process_names, event_ids_seen)
    is_internet_facing = bool(source_ips - _private_ips(source_ips))
    inferred_criticality = infer_criticality(inferred_role, is_internet_facing, len(usernames))

    # Compute hourly event rate baseline (exponential moving average)
    hourly_rate = len(recent_events)

    existing = mongo.db.assets.find_one({"hostname": hostname}) or {}

    # Merge known users (keep up to 50 most recent)
    known_users = set(existing.get("known_users", []))
    known_users.update(usernames)
    known_users = list(known_users)[:50]

    # Merge known processes (keep up to 100)
    known_processes = set(existing.get("known_processes", []))
    known_processes.update(process_names)
    known_processes = list(known_processes)[:100]

    # Merge known IPs
    known_ips = set(existing.get("known_external_ips", []))
    known_ips.update(dest_ips - _private_ips(dest_ips))
    known_ips = list(known_ips)[:200]

    # Smooth event rate (EMA, alpha=0.3)
    prev_rate = existing.get("avg_hourly_events", hourly_rate)
    smoothed_rate = round(0.3 * hourly_rate + 0.7 * prev_rate, 1)

    # Only overwrite role/criticality if not manually set
    role = existing.get("role") if existing.get("role_manually_set") else inferred_role
    criticality = existing.get("criticality") if existing.get("criticality_manually_set") \
        else inferred_criticality

    asset_doc = {
        "hostname": hostname,
        "ip_address": agent_doc.get("ip_address", existing.get("ip_address", "")),
        "os_version": agent_doc.get("os_version", existing.get("os_version", "")),
        "agent_id": str(agent_doc.get("_id", existing.get("agent_id", ""))),
        "agent_version": agent_doc.get("agent_version", existing.get("agent_version", "")),
        "sysmon_installed": agent_doc.get("sysmon_installed", existing.get("sysmon_installed", False)),

        # Inferred intelligence
        "role": role,
        "inferred_role": inferred_role,
        "criticality": criticality,
        "inferred_criticality": inferred_criticality,
        "is_internet_facing": is_internet_facing,

        # Behavioural baseline
        "known_users": known_users,
        "known_processes": known_processes,
        "known_external_ips": known_ips,
        "avg_hourly_events": smoothed_rate,
        "top_categories": dict(categories.most_common(5)),

        # Preserved manual fields
        "owner": existing.get("owner", ""),
        "owner_email": existing.get("owner_email", ""),
        "department": existing.get("department", ""),
        "description": existing.get("description", ""),
        "tags": existing.get("tags", []),
        "role_manually_set": existing.get("role_manually_set", False),
        "criticality_manually_set": existing.get("criticality_manually_set", False),

        # Stats
        "total_events_all_time": (existing.get("total_events_all_time", 0) + len(recent_events)),
        "last_seen": now,
        "first_seen": existing.get("first_seen", now),
        "updated_at": now,
    }

    mongo.db.assets.update_one(
        {"hostname": hostname},
        {"$set": asset_doc},
        upsert=True,
    )


def _private_ips(ips: set) -> set:
    """Return the subset of IPs that are RFC1918 private."""
    private = set()
    for ip in ips:
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                continue
            first, second = int(parts[0]), int(parts[1])
            if first == 10 or first == 127:
                private.add(ip)
            elif first == 172 and 16 <= second <= 31:
                private.add(ip)
            elif first == 192 and second == 168:
                private.add(ip)
        except Exception:
            pass
    return private

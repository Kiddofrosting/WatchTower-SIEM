"""
WatchTower SIEM - Time-Travel Investigation Service
====================================================
Reconstruct the exact state of a host at any point in time.

Answers questions like:
  - "What was running on SERVER-04 at 02:30 AM before the incident?"
  - "What happened between T-2h and T+30min around this incident?"
  - "Show me the before/after state comparison"
  - "Replay the sequence of events in slow motion"

No new data needed — builds everything from the existing events collection.

Key capabilities:
  1. point_in_time_snapshot  — What was the host state at time T?
  2. event_window            — All events in [T-before, T+after] window
  3. before_after_diff       — Compare host state before vs after an incident
  4. event_replay            — Ordered sequence for step-by-step reconstruction
  5. blast_radius            — What other hosts were active around the same time?
"""

import logging
from datetime import datetime, timedelta, timezone
from collections import defaultdict

logger = logging.getLogger(__name__)


# ── 1. Point-in-time snapshot ─────────────────────────────────────────────────

def point_in_time_snapshot(hostname: str, at_time: datetime, mongo) -> dict:
    """
    Reconstruct what we knew about a host at a specific moment.
    Uses events in the 2 hours preceding the snapshot time.
    """
    window_start = at_time - timedelta(hours=2)

    events = list(mongo.db.events.find(
        {"hostname": hostname, "timestamp": {"$gte": window_start, "$lte": at_time}},
        {"raw_event": 0}
    ).sort("timestamp", 1))

    # Build state from events
    active_processes = {}
    logged_in_users = set()
    network_connections = []
    recent_commands = []
    privilege_events = []

    for ev in events:
        cat = ev.get("category", "")
        pid = ev.get("process_id")
        proc = ev.get("process_name", "")
        user = ev.get("subject_username", "")

        if cat == "process_execution" and proc:
            active_processes[pid or proc] = {
                "name": proc,
                "pid": pid,
                "parent": ev.get("parent_process", ""),
                "user": user,
                "cmd": ev.get("command_line", "")[:200],
                "first_seen": ev.get("timestamp").isoformat() if isinstance(ev.get("timestamp"), datetime) else "",
            }
        if cat == "authentication" and ev.get("event_id") in (4624, 4648):
            if user and not user.endswith("$"):
                logged_in_users.add(user)
        if cat == "network" and ev.get("destination_ip"):
            network_connections.append({
                "dest_ip": ev.get("destination_ip"),
                "dest_port": ev.get("destination_port"),
                "process": proc,
                "timestamp": ev.get("timestamp").isoformat() if isinstance(ev.get("timestamp"), datetime) else "",
            })
        if ev.get("command_line"):
            recent_commands.append({
                "cmd": ev["command_line"][:200],
                "process": proc,
                "user": user,
                "timestamp": ev.get("timestamp").isoformat() if isinstance(ev.get("timestamp"), datetime) else "",
            })
        if cat == "privilege_escalation":
            privilege_events.append({
                "user": user,
                "event_id": ev.get("event_id"),
                "description": ev.get("message", "")[:100],
                "timestamp": ev.get("timestamp").isoformat() if isinstance(ev.get("timestamp"), datetime) else "",
            })

    # External connections only
    external_connections = [c for c in network_connections
                            if not _is_private_ip(c.get("dest_ip", ""))]

    return {
        "hostname": hostname,
        "snapshot_time": at_time.isoformat(),
        "window_start": window_start.isoformat(),
        "events_in_window": len(events),
        "state": {
            "active_processes": list(active_processes.values())[:30],
            "logged_in_users": list(logged_in_users),
            "external_network_connections": external_connections[:20],
            "recent_commands": recent_commands[-15:],  # last 15 commands
            "privilege_escalation_events": privilege_events[:10],
        },
    }


# ── 2. Event window ───────────────────────────────────────────────────────────

def get_event_window(hostname: str, center_time: datetime,
                     before_minutes: int, after_minutes: int, mongo) -> dict:
    """
    Pull all events in a window around a point in time.
    Perfect for reconstructing what happened around an incident.
    """
    window_start = center_time - timedelta(minutes=before_minutes)
    window_end = center_time + timedelta(minutes=after_minutes)

    events = list(mongo.db.events.find(
        {"hostname": hostname,
         "timestamp": {"$gte": window_start, "$lte": window_end}},
        {"raw_event": 0}
    ).sort("timestamp", 1).limit(500))

    # Also get incidents in this window
    incidents = list(mongo.db.incidents.find(
        {"hostname": hostname,
         "created_at": {"$gte": window_start, "$lte": window_end}},
        {"analyst_notes": 0, "ai_remediation": 0}
    ).sort("created_at", 1))

    # Serialise
    for e in events:
        e["_id"] = str(e["_id"])
        e["_type"] = "event"
        if isinstance(e.get("timestamp"), datetime):
            e["timestamp"] = e["timestamp"].isoformat()
    for i in incidents:
        i["_id"] = str(i["_id"])
        i["_type"] = "incident"
        i["timestamp"] = i["created_at"].isoformat() if isinstance(i.get("created_at"), datetime) else ""

    # Merge and sort
    timeline = sorted(events + incidents, key=lambda x: x.get("timestamp", ""))

    # Category breakdown
    categories = defaultdict(int)
    for e in events:
        categories[e.get("category", "unknown")] += 1

    return {
        "hostname": hostname,
        "center_time": center_time.isoformat(),
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "before_minutes": before_minutes,
        "after_minutes": after_minutes,
        "total_events": len(events),
        "total_incidents": len(incidents),
        "category_breakdown": dict(categories),
        "timeline": timeline,
    }


# ── 3. Before/After diff ──────────────────────────────────────────────────────

def before_after_diff(hostname: str, incident_time: datetime, mongo) -> dict:
    """
    Compare host state 2 hours before vs 30 minutes after an incident.
    Highlights what changed — new processes, new users, new connections.
    """
    before = point_in_time_snapshot(hostname, incident_time - timedelta(minutes=5), mongo)
    after = point_in_time_snapshot(hostname, incident_time + timedelta(minutes=30), mongo)

    before_state = before.get("state", {})
    after_state = after.get("state", {})

    # Diff processes
    before_procs = {p.get("name", "") for p in before_state.get("active_processes", [])}
    after_procs = {p.get("name", "") for p in after_state.get("active_processes", [])}
    new_processes = after_procs - before_procs
    disappeared_processes = before_procs - after_procs

    # Diff users
    before_users = set(before_state.get("logged_in_users", []))
    after_users = set(after_state.get("logged_in_users", []))
    new_users = after_users - before_users
    logged_off_users = before_users - after_users

    # Diff external connections
    before_ips = {c.get("dest_ip") for c in before_state.get("external_network_connections", [])}
    after_ips = {c.get("dest_ip") for c in after_state.get("external_network_connections", [])}
    new_connections = after_ips - before_ips

    return {
        "hostname": hostname,
        "incident_time": incident_time.isoformat(),
        "diff": {
            "new_processes": list(new_processes),
            "disappeared_processes": list(disappeared_processes),
            "new_users": list(new_users),
            "users_logged_off": list(logged_off_users),
            "new_external_connections": list(new_connections),
            "privilege_events_after": after_state.get("privilege_escalation_events", []),
            "new_commands": [
                c for c in after_state.get("recent_commands", [])
                if c not in before_state.get("recent_commands", [])
            ][:10],
        },
        "before_snapshot": before,
        "after_snapshot": after,
        "changes_detected": bool(
            new_processes or new_users or new_connections or
            after_state.get("privilege_escalation_events")
        ),
    }


# ── 4. Event replay ───────────────────────────────────────────────────────────

def get_event_replay(hostname: str, start_time: datetime, end_time: datetime, mongo) -> dict:
    """
    Return events in strict chronological order for step-by-step replay.
    Groups events into "scenes" — clusters of related activity.
    """
    events = list(mongo.db.events.find(
        {"hostname": hostname,
         "timestamp": {"$gte": start_time, "$lte": end_time}},
        {"raw_event": 0}
    ).sort("timestamp", 1).limit(300))

    for e in events:
        e["_id"] = str(e["_id"])
        if isinstance(e.get("timestamp"), datetime):
            e["timestamp"] = e["timestamp"].isoformat()

    # Group into scenes — bursts of activity within 2-minute windows
    scenes = []
    if events:
        current_scene = {"events": [events[0]], "start": events[0]["timestamp"]}
        for ev in events[1:]:
            prev_ts = current_scene["events"][-1].get("timestamp", "")
            curr_ts = ev.get("timestamp", "")
            try:
                delta = (datetime.fromisoformat(curr_ts.replace("Z", "+00:00")) -
                         datetime.fromisoformat(prev_ts.replace("Z", "+00:00"))).total_seconds()
                if delta > 120:  # > 2 minute gap → new scene
                    current_scene["end"] = prev_ts
                    current_scene["event_count"] = len(current_scene["events"])
                    current_scene["categories"] = list({e.get("category") for e in current_scene["events"]})
                    scenes.append(current_scene)
                    current_scene = {"events": [ev], "start": curr_ts}
                else:
                    current_scene["events"].append(ev)
            except Exception:
                current_scene["events"].append(ev)

        current_scene["end"] = events[-1].get("timestamp", "")
        current_scene["event_count"] = len(current_scene["events"])
        current_scene["categories"] = list({e.get("category") for e in current_scene["events"]})
        scenes.append(current_scene)

    return {
        "hostname": hostname,
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "total_events": len(events),
        "scenes": len(scenes),
        "replay": scenes,
    }


# ── 5. Blast radius ───────────────────────────────────────────────────────────

def get_blast_radius(hostname: str, incident_time: datetime, mongo) -> dict:
    """
    Find other hosts that were active and potentially connected to
    the compromised host around the time of the incident.
    """
    window_start = incident_time - timedelta(hours=2)
    window_end = incident_time + timedelta(hours=1)

    # Hosts that authenticated to/from this host
    auth_pipeline = [
        {"$match": {
            "timestamp": {"$gte": window_start, "$lte": window_end},
            "$or": [
                {"hostname": hostname, "category": "authentication"},
                {"source_ip": {"$exists": True, "$ne": ""},
                 "timestamp": {"$gte": window_start, "$lte": window_end}},
            ],
        }},
        {"$group": {
            "_id": "$hostname",
            "event_count": {"$sum": 1},
            "categories": {"$addToSet": "$category"},
        }},
        {"$match": {"_id": {"$ne": hostname}}},
        {"$sort": {"event_count": -1}},
        {"$limit": 20},
    ]
    related_hosts = list(mongo.db.events.aggregate(auth_pipeline))

    # Users who touched both this host and others in the window
    user_pipeline = [
        {"$match": {
            "hostname": hostname,
            "timestamp": {"$gte": window_start, "$lte": window_end},
            "subject_username": {"$exists": True, "$ne": "", "$not": {"$regex": "\\$$"}},
        }},
        {"$group": {"_id": "$subject_username"}},
    ]
    users_on_host = [r["_id"] for r in mongo.db.events.aggregate(user_pipeline)]

    lateral_moves = []
    for user in users_on_host[:10]:
        other_hosts = list(mongo.db.events.aggregate([
            {"$match": {
                "subject_username": user,
                "timestamp": {"$gte": window_start, "$lte": window_end},
                "hostname": {"$ne": hostname},
            }},
            {"$group": {"_id": "$hostname", "count": {"$sum": 1}}},
            {"$limit": 10},
        ]))
        if other_hosts:
            lateral_moves.append({
                "username": user,
                "other_hosts": [{"hostname": h["_id"], "events": h["count"]} for h in other_hosts],
            })

    # Get criticality of related hosts
    related_hostnames = [h["_id"] for h in related_hosts]
    asset_map = {}
    if related_hostnames:
        for asset in mongo.db.assets.find({"hostname": {"$in": related_hostnames}},
                                           {"hostname": 1, "criticality": 1, "role": 1}):
            asset_map[asset["hostname"]] = {
                "criticality": asset.get("criticality", "unknown"),
                "role": asset.get("role", "unknown"),
            }

    for h in related_hosts:
        h["asset_info"] = asset_map.get(h["_id"], {})

    return {
        "compromised_host": hostname,
        "incident_time": incident_time.isoformat(),
        "window": f"{window_start.isoformat()} to {window_end.isoformat()}",
        "related_hosts": related_hosts,
        "lateral_movement_indicators": lateral_moves,
        "affected_user_count": len(users_on_host),
        "affected_users": users_on_host[:10],
        "risk_summary": {
            "high_criticality_hosts_involved": sum(
                1 for h in related_hosts
                if asset_map.get(h["_id"], {}).get("criticality") in ("critical", "high")
            ),
            "potential_lateral_moves": len(lateral_moves),
        },
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_private_ip(ip: str) -> bool:
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        first, second = int(parts[0]), int(parts[1])
        return (first == 10 or first == 127 or
                (first == 172 and 16 <= second <= 31) or
                (first == 192 and second == 168))
    except Exception:
        return False

"""
WatchTower SIEM - Threat Intel Enrichment Service
==================================================
Automatically checks every ingested event against the IOC database.
Escalates severity and creates incidents when IOC matches are found.

Also provides optional external enrichment via AbuseIPDB (free tier).
"""
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def enrich_events_with_iocs(event_docs: list, mongo) -> list:
    """
    Check a batch of events against the IOC database.
    Mutates each event doc in place: adds ioc_matches list and escalates severity.
    Returns list of (event_doc, matched_ioc) for matched events.
    """
    if not event_docs:
        return []

    # Collect all IPs, domains, hashes from the batch
    ips = {e.get("source_ip") for e in event_docs if e.get("source_ip")} | \
          {e.get("destination_ip") for e in event_docs if e.get("destination_ip")}
    hashes = {e.get("hash_md5") for e in event_docs if e.get("hash_md5")} | \
             {e.get("hash_sha256") for e in event_docs if e.get("hash_sha256")}

    # Query IOC DB for all values at once
    all_values = (ips | hashes) - {None, ""}
    if not all_values:
        return []

    ioc_docs = list(mongo.db.threat_intel.find({
        "ioc_value": {"$in": list(all_values)},
        "expires_at": {"$gt": datetime.now(timezone.utc)},
    }))
    ioc_lookup = {ioc["ioc_value"]: ioc for ioc in ioc_docs}

    if not ioc_lookup:
        return []

    matched = []
    for event in event_docs:
        hits = []
        for field in ("source_ip", "destination_ip", "hash_md5", "hash_sha256"):
            val = event.get(field, "")
            if val and val in ioc_lookup:
                ioc = ioc_lookup[val]
                hits.append({
                    "ioc_value": val,
                    "ioc_type": ioc.get("ioc_type"),
                    "threat_type": ioc.get("threat_type", ""),
                    "confidence": ioc.get("confidence", 50),
                    "source": ioc.get("source", ""),
                    "field_matched": field,
                })

        if hits:
            event["ioc_matches"] = hits
            # Escalate severity based on highest confidence match
            max_confidence = max(h["confidence"] for h in hits)
            if max_confidence >= 80:
                event["severity"] = "critical"
            elif max_confidence >= 50:
                event["severity"] = "high"
            matched.append((event, hits))

    return matched


def create_ioc_incidents(matched_events: list, mongo, config: dict):
    """
    Create incidents for IOC-matched events.
    Groups by IOC value to avoid flooding.
    """
    from watchtower.app.models import new_incident
    from watchtower.app.services.alerting import send_incident_alerts

    grouped = {}  # ioc_value -> list of events
    for event, hits in matched_events:
        for hit in hits:
            key = (event.get("hostname", ""), hit["ioc_value"])
            grouped.setdefault(key, {"events": [], "hit": hit})
            grouped[key]["events"].append(event)

    created = []
    for (hostname, ioc_value), data in grouped.items():
        events = data["events"]
        hit = data["hit"]

        # Skip if open incident already exists for this IOC+host
        existing = mongo.db.incidents.find_one({
            "hostname": hostname,
            "status": {"$in": ["open", "investigating"]},
            "ioc_matches.ioc_value": ioc_value,
        })
        if existing:
            continue

        incident_doc = new_incident(
            rule_id="ioc_match",
            rule_name="Threat Intel IOC Match",
            title=f"IOC Match: {hit['ioc_type'].upper()} {ioc_value[:40]} on {hostname}",
            description=(
                f"Event matched known {hit['threat_type'] or 'malicious'} indicator "
                f"{ioc_value} ({hit['ioc_type']}) with {hit['confidence']}% confidence. "
                f"Source: {hit['source']}. Field: {hit['field_matched']}."
            ),
            severity="critical" if hit["confidence"] >= 80 else "high",
            category="credential_access",
            hostname=hostname,
            triggering_event_ids=[str(e.get("_id", "")) for e in events[:10]],
            mitre_technique=["T1071", "T1568"],
            mitre_tactic=["Command and Control"],
        )
        incident_doc["ioc_matches"] = [hit]
        result = mongo.db.incidents.insert_one(incident_doc)
        incident_doc["_id"] = str(result.inserted_id)
        created.append(str(result.inserted_id))

        try:
            send_incident_alerts(incident_doc, config, mongo)
        except Exception as e:
            logger.error(f"Failed to alert on IOC incident: {e}")

    return created

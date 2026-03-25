"""
WatchTower SIEM - Baseline Anomaly Detection
=============================================
Learns normal per-host event patterns and fires when behaviour deviates.

Runs as a nightly Beat task:
  1. Computes hourly event baselines per host (mean + std dev per hour-of-day)
  2. Checks last 2 hours against baseline
  3. Creates incidents for statistical outliers (Z-score > threshold)

No signatures needed — catches novel attacks that don't match any rule.
"""

import logging
import math
from datetime import datetime, timedelta, timezone
from collections import defaultdict

logger = logging.getLogger(__name__)

ZSCORE_THRESHOLD = 3.0        # standard deviations above mean = anomaly
MIN_BASELINE_DAYS = 7         # need at least 7 days of history to baseline
MIN_HOURLY_EVENTS = 5         # ignore hours with < 5 avg events (too noisy)


def compute_baselines(mongo):
    """
    Compute hourly event rate baselines per host.
    Stores results in `baselines` collection.
    Run nightly.
    """
    now = datetime.now(timezone.utc)
    baseline_window = now - timedelta(days=30)  # 30 days of history

    pipeline = [
        {"$match": {"timestamp": {"$gte": baseline_window, "$lt": now - timedelta(hours=2)}}},
        {"$group": {
            "_id": {
                "hostname": "$hostname",
                "hour": {"$hour": "$timestamp"},
                "date": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}},
            },
            "count": {"$sum": 1},
        }},
    ]

    # Aggregate into per-host, per-hour stats
    host_hour_counts = defaultdict(lambda: defaultdict(list))
    for r in mongo.db.events.aggregate(pipeline):
        hostname = r["_id"]["hostname"]
        hour = r["_id"]["hour"]
        host_hour_counts[hostname][hour].append(r["count"])

    updated = 0
    for hostname, hour_data in host_hour_counts.items():
        # Need enough days of data
        max_samples = max(len(v) for v in hour_data.values()) if hour_data else 0
        if max_samples < MIN_BASELINE_DAYS:
            continue

        hourly_stats = {}
        for hour, counts in hour_data.items():
            if len(counts) < 3:
                continue
            mean = sum(counts) / len(counts)
            variance = sum((c - mean) ** 2 for c in counts) / len(counts)
            std = math.sqrt(variance)
            hourly_stats[str(hour)] = {
                "mean": round(mean, 2),
                "std": round(std, 2),
                "samples": len(counts),
                "min": min(counts),
                "max": max(counts),
            }

        if hourly_stats:
            mongo.db.baselines.update_one(
                {"hostname": hostname},
                {"$set": {
                    "hostname": hostname,
                    "hourly_stats": hourly_stats,
                    "computed_at": now,
                    "window_days": 30,
                }},
                upsert=True,
            )
            updated += 1

    logger.info(f"Baselines computed for {updated} hosts")
    return updated


def check_anomalies(mongo, config: dict) -> list:
    """
    Compare the last 2 hours of event volumes against baselines.
    Create incidents for anomalous hosts.
    Returns list of new incident IDs.
    """
    now = datetime.now(timezone.utc)
    check_start = now - timedelta(hours=2)

    # Get current event counts per host per hour
    pipeline = [
        {"$match": {"timestamp": {"$gte": check_start}}},
        {"$group": {
            "_id": {
                "hostname": "$hostname",
                "hour": {"$hour": "$timestamp"},
            },
            "count": {"$sum": 1},
            "categories": {"$addToSet": "$category"},
        }},
    ]
    current = list(mongo.db.events.aggregate(pipeline))

    created_incidents = []
    for entry in current:
        hostname = entry["_id"]["hostname"]
        hour = str(entry["_id"]["hour"])
        count = entry["count"]

        baseline = mongo.db.baselines.find_one({"hostname": hostname})
        if not baseline:
            continue

        stats = baseline.get("hourly_stats", {}).get(hour)
        if not stats or stats["mean"] < MIN_HOURLY_EVENTS:
            continue

        mean = stats["mean"]
        std = stats["std"]
        if std < 1:
            std = 1  # avoid division by zero / hypersensitivity

        zscore = (count - mean) / std

        if zscore > ZSCORE_THRESHOLD:
            # Anomaly detected — check dedup
            existing = mongo.db.incidents.find_one({
                "hostname": hostname,
                "category": "other",
                "rule_name": "Baseline Anomaly",
                "created_at": {"$gte": now - timedelta(hours=4)},
            })
            if existing:
                continue

            from watchtower.app.models import new_incident
            inc = new_incident(
                rule_id="baseline_anomaly",
                rule_name="Baseline Anomaly",
                title=f"Anomalous Event Volume on {hostname}",
                description=(
                    f"Event volume at hour {hour}:00 UTC is {count} events "
                    f"(baseline mean: {mean:.0f} ± {std:.0f}, Z-score: {zscore:.1f}). "
                    f"This is {zscore:.1f} standard deviations above normal — "
                    f"possible attack, scanning, or misconfiguration."
                ),
                severity="high" if zscore > 5 else "medium",
                category="other",
                hostname=hostname,
                triggering_event_ids=[],
                mitre_technique=["T1498"],
                mitre_tactic=["Impact"],
            )
            inc["anomaly_zscore"] = round(zscore, 2)
            inc["anomaly_baseline_mean"] = mean
            inc["anomaly_actual_count"] = count
            inc["tags"] = ["anomaly", "baseline"]

            result = mongo.db.incidents.insert_one(inc)
            new_id = str(result.inserted_id)
            created_incidents.append(new_id)

            try:
                inc["_id"] = new_id
                from watchtower.app.services.alerting import send_incident_alerts
                send_incident_alerts(inc, config, mongo)
            except Exception as e:
                logger.error(f"Anomaly alert failed: {e}")

            logger.warning(f"Anomaly incident created for {hostname} (Z={zscore:.1f})")

    return created_incidents

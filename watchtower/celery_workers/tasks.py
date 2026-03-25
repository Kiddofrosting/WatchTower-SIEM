"""
WatchTower SIEM - Celery Tasks
detection, IOC enrichment, AI triage, AI remediation, asset profiling,
correlation, baseline anomaly, scheduled reports, retention, heartbeats.
"""

import structlog
from datetime import datetime, timedelta, timezone

from watchtower.celery_workers.celery_app import celery_app, get_flask_app

logger = structlog.get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Detection + IOC Enrichment + Asset Profiling + AI Triage
# ─────────────────────────────────────────────────────────────────────────────

@celery_app.task(
    bind=True,
    name="watchtower.celery_workers.tasks.process_events_batch",
    queue="detection",
    max_retries=3,
    default_retry_delay=10,
    acks_late=True,
)
def process_events_batch(self, event_ids: list, agent_id: str, hostname: str):
    """
    Pipeline per batch:
    1. IOC enrichment — match against threat intel, escalate severity, create IOC incidents
    2. Detection rules — evaluate all active rules, create rule incidents
    3. Asset intelligence — update host profile
    4. AI triage — score every new incident autonomously
    """
    if not event_ids:
        return {"status": "skipped", "reason": "empty_batch"}

    try:
        app = get_flask_app()
        with app.app_context():
            from bson import ObjectId
            from watchtower.app import mongo

            # Fetch full event docs
            oids = [ObjectId(e) for e in event_ids]
            event_docs = list(mongo.db.events.find({"_id": {"$in": oids}}))

            # ── Step 1: IOC enrichment ─────────────────────────────────────
            ioc_incident_ids = []
            try:
                from watchtower.app.services.threat_intel_enrichment import (
                    enrich_events_with_iocs, create_ioc_incidents
                )
                matched = enrich_events_with_iocs(event_docs, mongo)
                if matched:
                    # Update events with IOC match flags
                    for ev, hits in matched:
                        mongo.db.events.update_one(
                            {"_id": ev["_id"]},
                            {"$set": {"ioc_matches": hits, "severity": ev.get("severity")}}
                        )
                    ioc_incident_ids = create_ioc_incidents(matched, mongo, app.config)
                    logger.info("ioc_matches_found", count=len(matched), hostname=hostname)
            except Exception as e:
                logger.warning("ioc_enrichment_failed", error=str(e))

            # ── Step 2: Detection rules ────────────────────────────────────
            from watchtower.app.detection.engine import DetectionEngine
            engine = DetectionEngine(mongo, app.config)
            new_incident_ids = engine.evaluate_events(event_ids) or []
            all_new_incidents = list(set(new_incident_ids + ioc_incident_ids))

            logger.info("detection_complete", events=len(event_ids), hostname=hostname,
                        new_incidents=len(all_new_incidents))

            # ── Step 3: Asset intelligence ────────────────────────────────
            try:
                from watchtower.app.services.asset_intelligence import update_asset_profile
                agent_doc = mongo.db.agents.find_one({"_id": ObjectId(agent_id)}) or {}
                update_asset_profile(hostname, agent_doc, event_docs, mongo)
            except Exception as e:
                logger.warning("asset_profiling_failed", hostname=hostname, error=str(e))

            # ── Step 4: AI triage ─────────────────────────────────────────
            if all_new_incidents and (app.config.get("ANTHROPIC_API_KEY") or
                                       app.config.get("OPENAI_API_KEY")):
                for inc_id in all_new_incidents:
                    run_ai_triage.delay(inc_id)

            return {
                "status": "ok",
                "events_processed": len(event_ids),
                "rule_incidents": len(new_incident_ids),
                "ioc_incidents": len(ioc_incident_ids),
            }

    except Exception as exc:
        logger.error("detection_task_failed", hostname=hostname, error=str(exc))
        try:
            raise self.retry(exc=exc, countdown=10 * (self.request.retries + 1))
        except Exception:
            return {"status": "failed", "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# Autonomous AI Triage
# ─────────────────────────────────────────────────────────────────────────────

@celery_app.task(
    bind=True,
    name="watchtower.celery_workers.tasks.run_ai_triage",
    queue="ai",
    max_retries=1,
    default_retry_delay=15,
    time_limit=60,
    soft_time_limit=45,
)
def run_ai_triage(self, incident_id: str):
    """Autonomously triage a new incident before any human sees it."""
    from bson import ObjectId
    try:
        app = get_flask_app()
        with app.app_context():
            from watchtower.app import mongo
            try:
                oid = ObjectId(incident_id)
            except Exception:
                return {"status": "failed", "reason": "invalid_id"}

            incident = mongo.db.incidents.find_one({"_id": oid})
            if not incident:
                return {"status": "failed", "reason": "not_found"}
            if incident.get("ai_triage"):
                return {"status": "skipped", "reason": "already_triaged"}

            from watchtower.app.services.ai_triage import triage_incident
            result = triage_incident(incident, mongo, app.config)
            logger.info("ai_triage_complete", incident_id=incident_id,
                        score=result.get("triage", {}).get("true_positive_score"),
                        action=result.get("triage", {}).get("recommended_action"))
            return result
    except Exception as exc:
        logger.error("ai_triage_failed", incident_id=incident_id, error=str(exc))
        try:
            raise self.retry(exc=exc, countdown=15)
        except Exception:
            return {"status": "failed", "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# AI Remediation
# ─────────────────────────────────────────────────────────────────────────────

@celery_app.task(
    bind=True,
    name="watchtower.celery_workers.tasks.run_ai_remediation",
    queue="ai",
    max_retries=2,
    default_retry_delay=30,
    time_limit=120,
    soft_time_limit=90,
)
def run_ai_remediation(self, incident_id: str):
    from bson import ObjectId
    try:
        app = get_flask_app()
        with app.app_context():
            from watchtower.app import mongo
            try:
                oid = ObjectId(incident_id)
            except Exception:
                return {"status": "failed", "reason": "invalid_id"}
            incident = mongo.db.incidents.find_one({"_id": oid})
            if not incident:
                return {"status": "failed", "reason": "incident_not_found"}
            if incident.get("ai_remediation"):
                return {"status": "skipped", "reason": "already_generated"}
            from watchtower.app.services.ai_service import generate_remediation_sync
            text = generate_remediation_sync(incident, app.config)
            mongo.db.incidents.update_one(
                {"_id": oid},
                {"$set": {"ai_remediation": text,
                           "ai_remediation_generated_at": datetime.now(timezone.utc),
                           "updated_at": datetime.now(timezone.utc)}}
            )
            logger.info("ai_remediation_generated", incident_id=incident_id)
            return {"status": "ok", "incident_id": incident_id}
    except Exception as exc:
        logger.error("ai_remediation_failed", incident_id=incident_id, error=str(exc))
        try:
            raise self.retry(exc=exc, countdown=30)
        except Exception:
            return {"status": "failed", "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# Correlation Engine (runs every 2 minutes)
# ─────────────────────────────────────────────────────────────────────────────

@celery_app.task(
    name="watchtower.celery_workers.tasks.run_correlation_pass",
    queue="detection",
)
def run_correlation_pass():
    """Evaluate correlation rules to detect multi-stage attack chains."""
    try:
        app = get_flask_app()
        with app.app_context():
            from watchtower.app import mongo
            from watchtower.app.services.correlation_engine import (
                run_correlation_pass as _run, seed_correlation_rules
            )
            # Seed built-in patterns on first run
            seeded = seed_correlation_rules(mongo)
            if seeded:
                logger.info("correlation_rules_seeded", count=seeded)
            new_chains = _run(mongo, app.config)
            if new_chains:
                logger.warning("chain_incidents_created", count=len(new_chains), ids=new_chains)
            return {"status": "ok", "chains_created": len(new_chains)}
    except Exception as exc:
        logger.error("correlation_pass_failed", error=str(exc))
        return {"status": "failed", "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# Baseline Computation (runs nightly)
# ─────────────────────────────────────────────────────────────────────────────

@celery_app.task(
    name="watchtower.celery_workers.tasks.compute_baselines",
    queue="maintenance",
    time_limit=3600,
)
def compute_baselines():
    """Compute per-host hourly event baselines for anomaly detection."""
    try:
        app = get_flask_app()
        with app.app_context():
            from watchtower.app import mongo
            from watchtower.app.services.baseline_anomaly import compute_baselines as _compute
            updated = _compute(mongo)
            logger.info("baselines_computed", hosts_updated=updated)
            return {"status": "ok", "hosts_updated": updated}
    except Exception as exc:
        logger.error("baseline_computation_failed", error=str(exc))
        return {"status": "failed", "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# Anomaly Detection Check (runs every 30 minutes)
# ─────────────────────────────────────────────────────────────────────────────

@celery_app.task(
    name="watchtower.celery_workers.tasks.check_anomalies",
    queue="detection",
)
def check_anomalies():
    """Compare current event volumes against baselines, fire on outliers."""
    try:
        app = get_flask_app()
        with app.app_context():
            from watchtower.app import mongo
            from watchtower.app.services.baseline_anomaly import check_anomalies as _check
            incidents = _check(mongo, app.config)
            if incidents:
                logger.warning("anomaly_incidents_created", count=len(incidents))
            return {"status": "ok", "anomalies_found": len(incidents)}
    except Exception as exc:
        logger.error("anomaly_check_failed", error=str(exc))
        return {"status": "failed", "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# Scheduled Reports (runs every hour, checks DB for due schedules)
# ─────────────────────────────────────────────────────────────────────────────

@celery_app.task(
    name="watchtower.celery_workers.tasks.run_scheduled_reports",
    queue="maintenance",
)
def run_scheduled_reports():
    """Check for due report schedules and dispatch them by email."""
    try:
        app = get_flask_app()
        with app.app_context():
            from watchtower.app import mongo
            now = datetime.now(timezone.utc)
            due = list(mongo.db.report_schedules.find({
                "enabled": True,
                "next_run": {"$lte": now},
            }))
            sent = 0
            for schedule in due:
                try:
                    _dispatch_report(schedule, mongo, app)
                    from watchtower.app.api.reports import _next_run
                    next_dt = _next_run(schedule["frequency"], now)
                    mongo.db.report_schedules.update_one(
                        {"_id": schedule["_id"]},
                        {"$set": {"last_run": now, "next_run": next_dt}}
                    )
                    sent += 1
                except Exception as e:
                    logger.error("scheduled_report_failed",
                                 schedule_id=str(schedule["_id"]), error=str(e))
            return {"status": "ok", "reports_sent": sent}
    except Exception as exc:
        logger.error("scheduled_reports_task_failed", error=str(exc))
        return {"status": "failed", "error": str(exc)}


def _dispatch_report(schedule: dict, mongo, app):
    """Build and email a scheduled report."""
    from watchtower.app.api.reports import _build_executive_summary
    import json

    report_type = schedule.get("report_type", "executive_summary")
    days = schedule.get("days_lookback", 7)

    if report_type == "executive_summary":
        data = _build_executive_summary(days, mongo)
    else:
        data = {"report_type": report_type, "message": "Report type not yet implemented"}

    data["org_name"] = app.config.get("ORG_NAME", "Organization")
    data["schedule_name"] = schedule.get("name", "Scheduled Report")

    # Send via Flask-Mail
    from flask_mail import Message
    from watchtower.app import mail

    subject = f"[WatchTower] {schedule['name']} — {datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
    body_text = json.dumps(data, indent=2, default=str)

    msg = Message(
        subject=subject,
        recipients=schedule.get("recipients", []),
        body=f"WatchTower SIEM Scheduled Report\n\n{body_text}",
    )
    with app.app_context():
        mail.send(msg)


# ─────────────────────────────────────────────────────────────────────────────
# Retention Cleanup
# ─────────────────────────────────────────────────────────────────────────────

@celery_app.task(
    name="watchtower.celery_workers.tasks.run_retention_cleanup",
    queue="maintenance",
    time_limit=3600,
)
def run_retention_cleanup():
    try:
        app = get_flask_app()
        with app.app_context():
            from watchtower.app import mongo
            now = datetime.now(timezone.utc)
            stats = {}
            for col, cfg_key, days_default, query_field in [
                ("events", "RETENTION_RAW_EVENTS", 90, "timestamp"),
                ("audit_log", "RETENTION_AUDIT_LOG", 730, "timestamp"),
            ]:
                days = app.config.get(cfg_key, days_default)
                r = mongo.db[col].delete_many(
                    {query_field: {"$lt": now - timedelta(days=days)}}
                )
                stats[f"{col}_deleted"] = r.deleted_count

            inc_days = app.config.get("RETENTION_INCIDENTS", 365)
            r = mongo.db.incidents.delete_many({
                "created_at": {"$lt": now - timedelta(days=inc_days)},
                "status": {"$in": ["resolved", "closed", "false_positive"]},
            })
            stats["incidents_deleted"] = r.deleted_count
            mongo.db.token_blocklist.delete_many({"expires_at": {"$lt": now}})
            logger.info("retention_cleanup_complete", **stats)
            return {"status": "ok", "stats": stats}
    except Exception as exc:
        logger.error("retention_cleanup_failed", error=str(exc))
        return {"status": "failed", "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# Agent Heartbeat Check
# ─────────────────────────────────────────────────────────────────────────────

@celery_app.task(
    name="watchtower.celery_workers.tasks.check_agent_heartbeats",
    queue="maintenance",
)
def check_agent_heartbeats():
    try:
        app = get_flask_app()
        with app.app_context():
            from watchtower.app import mongo
            now = datetime.now(timezone.utc)
            stale = list(mongo.db.agents.find({
                "status": "active",
                "last_seen": {"$lt": now - timedelta(minutes=15), "$ne": None},
            }))
            stale_names = []
            for agent in stale:
                mongo.db.agents.update_one(
                    {"_id": agent["_id"]},
                    {"$set": {"status": "inactive", "updated_at": now}}
                )
                stale_names.append(agent["hostname"])
                try:
                    from watchtower.app.models import new_notification
                    from watchtower.app.services.alerting import send_agent_offline_alerts
                    admins = list(mongo.db.users.find(
                        {"is_active": True, "role": {"$in": ["super_admin", "admin", "analyst"]}},
                        {"_id": 1}
                    ))
                    notifs = [new_notification(
                        user_id=str(u["_id"]),
                        title=f"Agent Offline: {agent['hostname']}",
                        message=f"Agent {agent['hostname']} ({agent.get('ip_address','?')}) not seen for 15+ min.",
                        severity="medium", link="/dashboard/agents",
                    ) for u in admins]
                    if notifs:
                        mongo.db.notifications.insert_many(notifs)
                    send_agent_offline_alerts(agent, app.config)
                except Exception as e:
                    logger.warning("heartbeat_notification_failed", error=str(e))

            mongo.db.agents.update_many(
                {"status": "inactive", "last_seen": {"$gte": now - timedelta(minutes=5)}},
                {"$set": {"status": "active", "updated_at": now}}
            )
            if stale_names:
                logger.warning("agents_went_stale", hostnames=stale_names)
            return {"status": "ok", "stale_agents": len(stale_names)}
    except Exception as exc:
        logger.error("heartbeat_check_failed", error=str(exc))
        return {"status": "failed", "error": str(exc)}

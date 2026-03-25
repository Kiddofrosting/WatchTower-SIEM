"""WatchTower SIEM - Alerting Service"""
import logging
import smtplib
import ssl
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests

logger = logging.getLogger(__name__)

SEV_COLORS = {
    "critical": "#FF0000",
    "high": "#FF6600",
    "medium": "#FFA500",
    "low": "#FFFF00",
    "info": "#00AAFF",
}


def send_incident_alerts(incident: dict, config: dict, mongo):
    """Dispatch all configured alert channels for a new incident."""
    severity = incident.get("severity", "medium")
    min_sev = _get_setting(mongo, "alert_min_severity", "low")
    if not _severity_meets_threshold(severity, min_sev):
        return

    # Check maintenance window
    if _in_maintenance_window(mongo):
        logger.info(f"Alert suppressed (maintenance window) for incident {incident.get('_id')}")
        return

    if _get_setting(mongo, "email_alerts_enabled", True, config):
        _send_email_alert(incident, config, mongo)

    if _get_setting(mongo, "slack_alerts_enabled", True, config):
        _send_slack_alert(incident, config)

    if _get_setting(mongo, "webhook_enabled", False):
        _send_webhook_alert(incident, mongo)

    _create_inapp_notifications(incident, mongo)


def send_agent_offline_alerts(agent: dict, config: dict):
    """
    FIX: Send email + Slack when an agent goes offline.
    Previously only in-app notifications were created.
    """
    try:
        from flask import current_app
        mongo_obj = None
        try:
            from watchtower.app import mongo as m
            mongo_obj = m
        except Exception:
            pass

        incident_like = {
            "_id": str(agent.get("_id", "")),
            "title": f"Agent Offline: {agent.get('hostname', 'unknown')}",
            "severity": "medium",
            "category": "availability",
            "hostname": agent.get("hostname", "unknown"),
            "description": (
                f"Agent {agent.get('hostname')} ({agent.get('ip_address','?')}) "
                "has not reported in 15+ minutes and has been marked inactive."
            ),
            "mitre_technique": [],
            "mitre_tactic": [],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        from flask import current_app as app
        _send_email_alert(incident_like, app.config, mongo_obj, subject_prefix="[Agent Offline]")
        _send_slack_alert(incident_like, app.config, icon=":red_circle:")
    except Exception as e:
        logger.error(f"Agent offline alert failed: {e}")


def _in_maintenance_window(mongo) -> bool:
    """Return True if the current time falls inside a configured maintenance window."""
    try:
        settings = mongo.db.settings.find_one({"_id": "global"}) or {}
        mw = settings.get("maintenance_window")
        if not mw:
            return False
        now = datetime.now(timezone.utc)
        start = datetime.fromisoformat(mw.get("start", ""))
        end = datetime.fromisoformat(mw.get("end", ""))
        return start <= now <= end
    except Exception:
        return False


def _get_setting(mongo, key, default, config=None):
    settings = mongo.db.settings.find_one({"_id": "global"}) or {}
    val = settings.get(key)
    if val is None and config:
        val = config.get(key.upper())
    return val if val is not None else default


def _severity_meets_threshold(severity: str, min_sev: str) -> bool:
    order = ["info", "low", "medium", "high", "critical"]
    try:
        return order.index(severity) >= order.index(min_sev)
    except ValueError:
        return True


def _build_recipient_list(mongo, config: dict) -> list[str]:
    """
    FIX: Build recipient list from per-user alert preferences,
    not just the hardcoded SUPER_ADMIN_EMAIL.
    """
    recipients = set()
    # Always include configured admin email as fallback
    admin_email = config.get("SUPER_ADMIN_EMAIL", "")
    if admin_email:
        recipients.add(admin_email)
    # Add users who have email alerts enabled
    if mongo:
        try:
            users = mongo.db.users.find(
                {
                    "is_active": True,
                    "role": {"$in": ["super_admin", "admin", "analyst"]},
                    "preferences.notifications_email": {"$ne": False},
                    "email": {"$exists": True, "$ne": ""},
                },
                {"email": 1}
            )
            for u in users:
                if u.get("email"):
                    recipients.add(u["email"])
        except Exception:
            pass
    return list(recipients)


def _send_email_alert(incident: dict, config: dict, mongo=None, subject_prefix: str = "[WatchTower"):
    try:
        smtp_host = config.get("MAIL_SERVER", "localhost")
        smtp_port = int(config.get("MAIL_PORT", 587))
        username = config.get("MAIL_USERNAME", "")
        password = config.get("MAIL_PASSWORD", "")
        sender = config.get("MAIL_DEFAULT_SENDER", "WatchTower <noreply@localhost>")
        use_tls = config.get("MAIL_USE_TLS", True)

        recipients = _build_recipient_list(mongo, config)
        if not recipients:
            return

        sev = incident.get("severity", "medium").upper()
        if subject_prefix == "[WatchTower":
            subject = f"[WatchTower {sev}] {incident.get('title', 'Security Incident')}"
        else:
            subject = f"{subject_prefix} {incident.get('title', 'Agent Offline')}"

        body_html = f"""
<html><body style="font-family:Arial,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px;">
<div style="max-width:600px;margin:0 auto;background:#161b22;border-radius:8px;padding:24px;border:1px solid #30363d;">
  <div style="background:{SEV_COLORS.get(incident.get('severity','medium'),'#888')};border-radius:4px;padding:8px 16px;margin-bottom:20px;">
    <h2 style="margin:0;color:#fff;">&#128680; WatchTower Security Alert</h2>
  </div>
  <table style="width:100%;border-collapse:collapse;">
    <tr><td style="padding:8px;color:#8b949e;width:140px;">Severity</td>
        <td style="padding:8px;color:#f0f6fc;font-weight:bold;">{incident.get('severity','').upper()}</td></tr>
    <tr><td style="padding:8px;color:#8b949e;">Title</td>
        <td style="padding:8px;color:#f0f6fc;">{incident.get('title','')}</td></tr>
    <tr><td style="padding:8px;color:#8b949e;">Host</td>
        <td style="padding:8px;color:#f0f6fc;">{incident.get('hostname','')}</td></tr>
    <tr><td style="padding:8px;color:#8b949e;">Category</td>
        <td style="padding:8px;color:#f0f6fc;">{incident.get('category','')}</td></tr>
    <tr><td style="padding:8px;color:#8b949e;">MITRE</td>
        <td style="padding:8px;color:#f0f6fc;">{', '.join(incident.get('mitre_technique',[]))}</td></tr>
    <tr><td style="padding:8px;color:#8b949e;">Time</td>
        <td style="padding:8px;color:#f0f6fc;">{incident.get('created_at','')}</td></tr>
  </table>
  <p style="color:#8b949e;margin-top:20px;">{incident.get('description','')}</p>
  <a href="{config.get('BASE_URL','')}/dashboard/incidents/{incident.get('_id','')}"
     style="display:inline-block;margin-top:16px;padding:12px 24px;background:#1f6feb;color:#fff;text-decoration:none;border-radius:6px;">
    View Incident &#8594;
  </a>
  <p style="margin-top:24px;font-size:11px;color:#484f58;">WatchTower SIEM &middot; {config.get('ORG_NAME','')}</p>
</div></body></html>"""

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = ", ".join(recipients)
        msg.attach(MIMEText(body_html, "html"))

        ctx = ssl.create_default_context()
        if use_tls:
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.ehlo()
                server.starttls(context=ctx)
                if username:
                    server.login(username, password)
                server.sendmail(sender, recipients, msg.as_string())
        else:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, context=ctx) as server:
                if username:
                    server.login(username, password)
                server.sendmail(sender, recipients, msg.as_string())

        logger.info(f"Email alert sent for incident {incident.get('_id')}")
    except Exception as e:
        logger.error(f"Email alert failed: {e}")


def _send_slack_alert(incident: dict, config: dict, icon: str = ":rotating_light:"):
    webhook_url = config.get("SLACK_WEBHOOK_URL", "")
    if not webhook_url or not webhook_url.startswith("https://hooks.slack.com/"):
        return

    sev = incident.get("severity", "medium")
    color = SEV_COLORS.get(sev, "#888888")

    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{icon} WatchTower Alert [{sev.upper()}]"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Title:*\n{incident.get('title','')}"},
                    {"type": "mrkdwn", "text": f"*Host:*\n{incident.get('hostname','')}"},
                    {"type": "mrkdwn", "text": f"*Category:*\n{incident.get('category','')}"},
                    {"type": "mrkdwn", "text": f"*MITRE:*\n{', '.join(incident.get('mitre_technique',[]))}"},
                ]
            },
            {"type": "section", "text": {"type": "mrkdwn", "text": f"_{incident.get('description','')}_"}},
            {
                "type": "actions",
                "elements": [{
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View Incident"},
                    "url": f"{config.get('BASE_URL','')}/dashboard/incidents/{incident.get('_id','')}",
                    "style": "danger" if sev in ("critical", "high") else "primary",
                }]
            }
        ],
        "attachments": [{"color": color, "fallback": f"Incident: {incident.get('title','')}"}]
    }

    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        resp.raise_for_status()
        logger.info(f"Slack alert sent for incident {incident.get('_id')}")
    except Exception as e:
        logger.error(f"Slack alert failed: {e}")


def _send_webhook_alert(incident: dict, mongo):
    """Send a signed JSON payload to a configured outbound webhook URL."""
    import hashlib, hmac, json, time
    try:
        settings = mongo.db.settings.find_one({"_id": "global"}) or {}
        webhook_url = settings.get("webhook_url", "")
        webhook_secret = settings.get("webhook_secret", "")
        if not webhook_url:
            return

        payload = {
            "event": "incident.created",
            "timestamp": int(time.time()),
            "incident": {
                "id": str(incident.get("_id", "")),
                "title": incident.get("title", ""),
                "severity": incident.get("severity", ""),
                "category": incident.get("category", ""),
                "hostname": incident.get("hostname", ""),
                "mitre_technique": incident.get("mitre_technique", []),
                "created_at": incident.get("created_at", ""),
            }
        }
        body = json.dumps(payload, default=str).encode()
        sig = hmac.new(webhook_secret.encode(), body, hashlib.sha256).hexdigest() if webhook_secret else ""

        resp = requests.post(
            webhook_url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-WatchTower-Signature": sig,
                "X-WatchTower-Event": "incident.created",
            },
            timeout=10,
        )
        resp.raise_for_status()
        logger.info(f"Webhook alert sent for incident {incident.get('_id')}")
    except Exception as e:
        logger.error(f"Webhook alert failed: {e}")


def _create_inapp_notifications(incident: dict, mongo):
    """Create in-app notifications for all active analysts/admins."""
    try:
        from watchtower.app.models import new_notification
        recipients = list(mongo.db.users.find(
            {"is_active": True, "role": {"$in": ["super_admin", "admin", "analyst"]},
             "preferences.notifications_inapp": {"$ne": False}},
            {"_id": 1}
        ))
        notifs = [
            new_notification(
                user_id=str(u["_id"]),
                title=f"[{incident.get('severity','').upper()}] {incident.get('title','')}",
                message=incident.get("description", "")[:256],
                severity=incident.get("severity", "medium"),
                link=f"/dashboard/incidents/{incident.get('_id','')}",
                incident_id=str(incident.get("_id", "")),
            )
            for u in recipients
        ]
        if notifs:
            mongo.db.notifications.insert_many(notifs)
    except Exception as e:
        logger.error(f"In-app notification creation failed: {e}")

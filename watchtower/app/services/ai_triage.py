"""
WatchTower SIEM - Autonomous AI Triage Service
==============================================
Automatically scores every new incident before a human sees it:
  - True-positive probability (0-100)
  - Recommended action: auto_close | escalate | review
  - One-paragraph analyst brief
  - Key evidence points

Auto-closes obvious false positives (score < configurable threshold).
Auto-escalates critical true positives with a pre-written brief.

This runs as a Celery task immediately after incident creation,
meaning analysts only touch incidents that actually need them.
"""

import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ── Triage decision thresholds (overridable via DB settings) ──────────────────
DEFAULT_AUTO_CLOSE_THRESHOLD = 15   # score <= this → auto close as false positive
DEFAULT_AUTO_ESCALATE_THRESHOLD = 80  # score >= this → escalate immediately


def triage_incident(incident: dict, mongo, config: dict) -> dict:
    """
    Run autonomous triage on a newly created incident.
    Returns triage result dict and updates the incident in-place.
    """
    incident_id = str(incident.get("_id", ""))

    # Load thresholds from settings
    settings = mongo.db.settings.find_one({"_id": "global"}) or {}
    auto_close_threshold = int(settings.get("triage_auto_close_threshold", DEFAULT_AUTO_CLOSE_THRESHOLD))
    escalate_threshold = int(settings.get("triage_auto_escalate_threshold", DEFAULT_AUTO_ESCALATE_THRESHOLD))
    triage_enabled = settings.get("ai_triage_enabled", True)

    if not triage_enabled:
        return {"status": "skipped", "reason": "ai_triage_disabled"}

    # Gather rich context for triage
    context = _build_triage_context(incident, mongo)

    # Call AI
    try:
        result = _call_ai_triage(context, config)
    except Exception as e:
        logger.error(f"AI triage failed for {incident_id}: {e}")
        return {"status": "failed", "error": str(e)}

    score = result.get("true_positive_score", 50)
    action = result.get("recommended_action", "review")
    brief = result.get("analyst_brief", "")
    evidence = result.get("key_evidence", [])

    # Determine final action
    if score <= auto_close_threshold:
        action = "auto_close"
    elif score >= escalate_threshold:
        action = "escalate"

    # Persist triage result onto incident
    from bson import ObjectId
    triage_doc = {
        "true_positive_score": score,
        "recommended_action": action,
        "analyst_brief": brief,
        "key_evidence": evidence,
        "triaged_at": datetime.now(timezone.utc),
        "auto_closed": action == "auto_close",
        "escalated": action == "escalate",
    }

    update = {
        "$set": {
            "ai_triage": triage_doc,
            "updated_at": datetime.now(timezone.utc),
        }
    }

    # Auto-close false positives
    if action == "auto_close":
        update["$set"]["status"] = "false_positive"
        update["$set"]["false_positive_reason"] = f"Auto-closed by AI triage (score: {score}/100). {brief}"
        update["$set"]["resolved_at"] = datetime.now(timezone.utc)
        update["$push"] = {
            "timeline": {
                "timestamp": datetime.now(timezone.utc),
                "actor": "AI Triage",
                "action": "auto_closed",
                "detail": f"Auto-closed as false positive (confidence score: {score}/100)",
            }
        }
        logger.info(f"Auto-closed incident {incident_id} (score={score})")

    # Auto-escalate high-confidence true positives
    elif action == "escalate":
        update["$set"]["status"] = "investigating"
        update["$push"] = {
            "timeline": {
                "timestamp": datetime.now(timezone.utc),
                "actor": "AI Triage",
                "action": "auto_escalated",
                "detail": f"Auto-escalated by AI triage (confidence score: {score}/100): {brief[:200]}",
            }
        }
        logger.warning(f"Auto-escalated incident {incident_id} (score={score})")

    try:
        from bson import ObjectId as OID
        mongo.db.incidents.update_one({"_id": OID(incident_id)}, update)
    except Exception as e:
        logger.error(f"Failed to persist triage for {incident_id}: {e}")

    return {"status": "ok", "incident_id": incident_id, "triage": triage_doc}


def _build_triage_context(incident: dict, mongo) -> dict:
    """
    Build rich context for the triage prompt:
    - Incident fields
    - Asset intelligence for the affected host
    - Recent incident history on this host
    - Rule hit rate (noisy rule = more likely FP)
    - IOC matches
    """
    hostname = incident.get("hostname", "unknown")
    rule_id = incident.get("rule_id", "")

    # Asset profile
    asset = mongo.db.assets.find_one({"hostname": hostname}) or {}

    # Recent incidents on this host (last 7 days)
    from datetime import timedelta
    recent_cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    recent_on_host = mongo.db.incidents.count_documents({
        "hostname": hostname,
        "created_at": {"$gte": recent_cutoff},
    })
    fp_on_host = mongo.db.incidents.count_documents({
        "hostname": hostname,
        "status": "false_positive",
        "created_at": {"$gte": recent_cutoff},
    })

    # Rule reliability (FP rate)
    rule_doc = {}
    rule_fp_rate = 0.0
    if rule_id:
        try:
            from bson import ObjectId
            rule_doc = mongo.db.rules.find_one({"_id": ObjectId(rule_id)}) or {}
            total_hits = rule_doc.get("hit_count", 0)
            fp_count = mongo.db.incidents.count_documents({
                "rule_id": rule_id,
                "status": "false_positive",
            })
            rule_fp_rate = round(fp_count / total_hits * 100, 1) if total_hits > 5 else 0
        except Exception:
            pass

    # IOC matches on this incident
    ioc_matches = incident.get("ioc_matches", [])

    # Triggering events sample (first 3)
    sample_events = []
    if incident.get("triggering_event_ids"):
        try:
            from bson import ObjectId
            oids = [ObjectId(e) for e in incident["triggering_event_ids"][:3]]
            for ev in mongo.db.events.find({"_id": {"$in": oids}}, {"raw_event": 0}):
                sample_events.append({
                    "event_id": ev.get("event_id"),
                    "category": ev.get("category"),
                    "subject_username": ev.get("subject_username", ""),
                    "process_name": ev.get("process_name", ""),
                    "source_ip": ev.get("source_ip", ""),
                    "command_line": ev.get("command_line", "")[:200],
                    "message": ev.get("message", "")[:200],
                })
        except Exception:
            pass

    return {
        "incident": {
            "title": incident.get("title", ""),
            "severity": incident.get("severity", ""),
            "category": incident.get("category", ""),
            "description": incident.get("description", ""),
            "rule_name": incident.get("rule_name", ""),
            "mitre_technique": incident.get("mitre_technique", []),
            "mitre_tactic": incident.get("mitre_tactic", []),
            "event_count": incident.get("event_count", 0),
        },
        "asset": {
            "hostname": hostname,
            "role": asset.get("role", "unknown"),
            "criticality": asset.get("criticality", "medium"),
            "owner": asset.get("owner", "unknown"),
            "is_internet_facing": asset.get("is_internet_facing", False),
            "os_version": asset.get("os_version", ""),
            "tags": asset.get("tags", []),
        },
        "host_history": {
            "recent_incidents_7d": recent_on_host,
            "false_positives_7d": fp_on_host,
            "fp_rate_pct": round(fp_on_host / recent_on_host * 100, 1) if recent_on_host else 0,
        },
        "rule_reliability": {
            "rule_name": rule_doc.get("name", ""),
            "total_hits": rule_doc.get("hit_count", 0),
            "historical_fp_rate_pct": rule_fp_rate,
        },
        "ioc_matches": ioc_matches,
        "sample_events": sample_events,
    }


def _call_ai_triage(context: dict, config: dict) -> dict:
    """
    Call the LLM to triage the incident.
    Returns a structured dict: {true_positive_score, recommended_action, analyst_brief, key_evidence}
    """
    provider = config.get("AI_PROVIDER", "anthropic")
    model = config.get("AI_MODEL", "claude-sonnet-4-6")

    prompt = _build_triage_prompt(context)

    if provider == "anthropic":
        api_key = config.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise ValueError("Anthropic API key not configured")
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model=model,
            max_tokens=800,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = message.content[0].text
    elif provider == "openai":
        api_key = config.get("OPENAI_API_KEY", "")
        if not api_key:
            raise ValueError("OpenAI API key not configured")
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=800,
        )
        raw = resp.choices[0].message.content
    else:
        raise ValueError(f"Unknown AI provider: {provider}")

    return _parse_triage_response(raw)


def _build_triage_prompt(ctx: dict) -> str:
    inc = ctx["incident"]
    asset = ctx["asset"]
    hist = ctx["host_history"]
    rule = ctx["rule_reliability"]
    iocs = ctx["ioc_matches"]
    events = ctx["sample_events"]

    mitre = ", ".join(inc["mitre_technique"]) or "None"

    return f"""You are an autonomous SOC triage analyst. Your job is to quickly assess whether a security incident is a genuine threat or a false positive, and decide whether a human analyst needs to look at it.

## Incident
- Title: {inc['title']}
- Severity: {inc['severity'].upper()}
- Category: {inc['category']}
- Description: {inc['description']}
- Rule: {inc['rule_name']}
- MITRE: {mitre}
- Event count: {inc['event_count']}

## Affected Asset
- Hostname: {asset['hostname']}
- Role: {asset['role']}
- Criticality: {asset['criticality']}
- Internet-facing: {asset['is_internet_facing']}
- Owner: {asset['owner']}
- Tags: {', '.join(asset['tags']) or 'none'}

## Host History (last 7 days)
- Recent incidents: {hist['recent_incidents_7d']}
- False positives: {hist['false_positives_7d']} ({hist['fp_rate_pct']}% FP rate)

## Rule Reliability
- Historical FP rate: {rule['historical_fp_rate_pct']}%
- Total rule hits ever: {rule['total_hits']}

## IOC Matches
{json.dumps(iocs) if iocs else 'None'}

## Sample Events
{json.dumps(events, indent=2) if events else 'No event detail available'}

---

Respond with ONLY valid JSON, no markdown, no explanation outside the JSON:
{{
  "true_positive_score": <integer 0-100, where 100 = definitely real threat>,
  "recommended_action": "<auto_close|review|escalate>",
  "analyst_brief": "<one paragraph, max 3 sentences, explaining your assessment>",
  "key_evidence": ["<evidence point 1>", "<evidence point 2>", "<evidence point 3 max>"]
}}

Scoring guide:
- 0-15: Very likely false positive → auto_close
- 16-79: Uncertain, human review needed → review  
- 80-100: High confidence true positive on important asset → escalate

Be conservative: if in doubt, use review not auto_close. Only auto_close when the evidence strongly points to a false positive (e.g. high historical FP rate, known noisy rule, machine account, scheduled task, benign process)."""


def _parse_triage_response(raw: str) -> dict:
    """Parse the JSON response from the LLM, with fallback."""
    try:
        # Strip markdown code fences if present
        text = raw.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        result = json.loads(text.strip())
        # Validate and clamp score
        score = max(0, min(100, int(result.get("true_positive_score", 50))))
        action = result.get("recommended_action", "review")
        if action not in ("auto_close", "review", "escalate"):
            action = "review"
        return {
            "true_positive_score": score,
            "recommended_action": action,
            "analyst_brief": str(result.get("analyst_brief", ""))[:500],
            "key_evidence": result.get("key_evidence", [])[:5],
        }
    except Exception as e:
        logger.warning(f"Failed to parse triage response: {e} — raw: {raw[:200]}")
        return {
            "true_positive_score": 50,
            "recommended_action": "review",
            "analyst_brief": "Triage parsing failed — please review manually.",
            "key_evidence": [],
        }

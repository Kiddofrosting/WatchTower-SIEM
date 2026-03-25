"""WatchTower SIEM - AI Remediation Service"""
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def generate_remediation_sync(incident: dict, config: dict) -> str:
    """
    Call LLM API to generate remediation advice for an incident.
    Returns the AI-generated markdown string.
    """
    provider = config.get("AI_PROVIDER", "anthropic")
    # FIX: updated default model string
    model = config.get("AI_MODEL", "claude-sonnet-4-6")

    context = _build_incident_context(incident)
    prompt = _build_prompt(context)

    if provider == "anthropic":
        return _call_anthropic(prompt, model, config.get("ANTHROPIC_API_KEY", ""))
    elif provider == "openai":
        return _call_openai(prompt, model, config.get("OPENAI_API_KEY", ""))
    else:
        raise ValueError(f"Unknown AI provider: {provider}")


def _build_incident_context(incident: dict) -> dict:
    """Extract and sanitize incident fields for the AI prompt."""
    return {
        "title": incident.get("title", ""),
        "severity": incident.get("severity", ""),
        "category": incident.get("category", ""),
        "description": incident.get("description", ""),
        "hostname": incident.get("hostname", "REDACTED"),
        "mitre_technique": incident.get("mitre_technique", []),
        "mitre_tactic": incident.get("mitre_tactic", []),
        "rule_name": incident.get("rule_name", ""),
        "event_count": incident.get("event_count", 0),
        "created_at": str(incident.get("created_at", "")),
    }


def _build_prompt(ctx: dict) -> str:
    mitre_str = ", ".join(ctx["mitre_technique"]) if ctx["mitre_technique"] else "Unknown"
    tactic_str = ", ".join(ctx["mitre_tactic"]) if ctx["mitre_tactic"] else "Unknown"

    return f"""You are an expert Windows security analyst and incident responder.
Analyze the following security incident detected by WatchTower SIEM and provide actionable remediation guidance.

**Incident Details:**
- Title: {ctx['title']}
- Severity: {ctx['severity'].upper()}
- Category: {ctx['category']}
- Description: {ctx['description']}
- Detection Rule: {ctx['rule_name']}
- Events Triggered: {ctx['event_count']}
- MITRE ATT&CK Techniques: {mitre_str}
- MITRE Tactics: {tactic_str}
- Detected At: {ctx['created_at']}

Please provide:

## 1. Threat Assessment
Brief analysis of what this incident likely represents and its potential impact.

## 2. Immediate Containment Steps
Step-by-step actions to contain the threat right now (prioritize within the first 30 minutes).

## 3. Investigation Checklist
Specific artifacts to collect and investigate to confirm/deny the threat.

## 4. Remediation Actions
Technical steps to remove the threat and restore normal operations.

## 5. Prevention Recommendations
Configuration changes, patches, or controls to prevent recurrence.

## 6. MITRE ATT&CK Context
Brief explanation of the relevant techniques and how defenders can detect/prevent them.

Be specific, actionable, and prioritized. Use Windows-specific commands and tools where applicable.
Format your response in clear Markdown."""


def _call_anthropic(prompt: str, model: str, api_key: str) -> str:
    if not api_key:
        return "_AI remediation unavailable: Anthropic API key not configured._"
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model=model,
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}]
        )
        return message.content[0].text
    except Exception as e:
        logger.error(f"Anthropic API error: {e}")
        return f"_AI remediation generation failed: {str(e)[:200]}_"


def _call_openai(prompt: str, model: str, api_key: str) -> str:
    if not api_key:
        return "_AI remediation unavailable: OpenAI API key not configured._"
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=2048,
        )
        return response.choices[0].message.content
    except Exception as e:
        logger.error(f"OpenAI API error: {e}")
        return f"_AI remediation generation failed: {str(e)[:200]}_"


def generate_remediation_async(incident_id: str):
    """Called from API - delegates to Celery task."""
    from watchtower.celery_workers.tasks import run_ai_remediation
    return run_ai_remediation.delay(incident_id)

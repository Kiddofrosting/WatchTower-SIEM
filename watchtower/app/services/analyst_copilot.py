"""
WatchTower SIEM - Analyst Copilot Service
==========================================
Conversational AI assistant woven into every workflow.

Capabilities:
  1. explain_incident      - Plain English incident explanation (junior-friendly)
  2. weekly_summary        - Executive prose summary of the week's incidents
  3. priority_queue        - "What should I investigate next?" recommendation
  4. is_this_normal        - "Is this event normal for this host?" baseline check
  5. draft_playbook        - Generate a containment runbook for an attack type
  6. compliance_impact     - "What compliance controls does this incident affect?"
  7. chat                  - Free-form conversational interface with SIEM context

All responses are streamed via SSE where supported.
"""

import json
import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


# ── 1. Incident Explainer ──────────────────────────────────────────────────────

def explain_incident(incident: dict, asset: dict, config: dict) -> str:
    """
    Explain an incident in plain English for a junior analyst.
    No jargon. What happened, why it matters, what to do first.
    """
    mitre = ", ".join(incident.get("mitre_technique", [])) or "none identified"
    triage = incident.get("ai_triage", {})
    score = triage.get("true_positive_score", "not scored")
    brief = triage.get("analyst_brief", "")

    asset_ctx = ""
    if asset:
        asset_ctx = f"""
The affected machine ({asset.get('hostname')}) is a {asset.get('role', 'unknown role')} 
with {asset.get('criticality', 'unknown')} criticality, owned by {asset.get('owner') or 'unknown'}.
{"It is internet-facing." if asset.get('is_internet_facing') else "It is not directly internet-facing."}"""

    prompt = f"""You are a senior security analyst explaining an incident to a junior analyst who is new to the SOC.
Use plain English. Avoid jargon. Be concise but complete. Format with short paragraphs.

## Incident
- Title: {incident.get('title')}
- Severity: {incident.get('severity', '').upper()}
- Category: {incident.get('category')}
- Rule that fired: {incident.get('rule_name')}
- Description: {incident.get('description')}
- MITRE ATT&CK techniques: {mitre}
- Events that triggered this: {incident.get('event_count', 0)}
- AI triage confidence score: {score}/100
- AI brief: {brief}
{asset_ctx}

Explain in 3 sections:
**What happened** — describe the activity in plain English, what an attacker might be doing
**Why this matters** — business impact if this is real, why we care
**What to do first** — the top 3 immediate actions for a junior analyst, in plain language

Keep each section to 2-4 sentences. No bullet points in the first two sections."""

    return _call_ai(prompt, config, max_tokens=600)


# ── 2. Weekly Summary ─────────────────────────────────────────────────────────

def generate_weekly_summary(stats: dict, config: dict) -> str:
    """
    Write an executive prose summary of the week's security posture.
    Suitable for a weekly email to management.
    """
    prompt = f"""You are a CISO writing the weekly security operations summary for executive leadership.
Write in clear, professional prose. No bullet points. 3 paragraphs max. No fluff.

## This Week's Data
- Total events monitored: {stats.get('total_events', 0):,}
- New incidents: {stats.get('total_incidents', 0)} ({stats.get('critical_incidents', 0)} critical)
- Incidents resolved: {stats.get('resolved_incidents', 0)}
- Average resolution time: {stats.get('mttr_hours', 'N/A')} hours
- Auto-triaged by AI (closed as FP): {stats.get('auto_closed', 0)}
- Active monitored endpoints: {stats.get('active_agents', 0)}
- Top MITRE techniques seen: {', '.join(t['technique'] for t in stats.get('top_mitre', [])[:3]) or 'none'}
- Top affected hosts: {', '.join(h['hostname'] for h in stats.get('top_hosts', [])[:3]) or 'none'}
- Change vs prior week: incidents {stats.get('incident_change_pct', 'N/A')}%, events {stats.get('event_change_pct', 'N/A')}%
- Organisation: {stats.get('org_name', 'Organisation')}

Write a 3-paragraph executive summary:
1. Overall security posture and week highlights
2. Key threats detected and how they were handled
3. Trend and what to watch next week

Tone: confident, factual, appropriate for a board-level audience. Do not start with "This week"."""

    return _call_ai(prompt, config, max_tokens=500)


# ── 3. Priority Queue Advisor ─────────────────────────────────────────────────

def get_priority_queue(incidents: list, assets: dict, config: dict) -> dict:
    """
    Recommend which open incidents the analyst should tackle first.
    Returns ordered list with reasoning for each.
    """
    if not incidents:
        return {"recommendation": "No open incidents require attention.", "queue": []}

    # Build summary for LLM
    inc_summaries = []
    for i, inc in enumerate(incidents[:15]):
        asset = assets.get(inc.get("hostname", ""), {})
        triage = inc.get("ai_triage", {})
        inc_summaries.append({
            "rank": i + 1,
            "id": str(inc.get("_id", "")),
            "title": inc.get("title", ""),
            "severity": inc.get("severity", ""),
            "hostname": inc.get("hostname", ""),
            "asset_criticality": asset.get("criticality", "unknown"),
            "asset_role": asset.get("role", "unknown"),
            "triage_score": triage.get("true_positive_score", "not scored"),
            "age_hours": round((datetime.now(timezone.utc) - inc["created_at"]).total_seconds() / 3600, 1)
                if isinstance(inc.get("created_at"), datetime) else "unknown",
            "category": inc.get("category", ""),
            "mitre": inc.get("mitre_technique", [])[:2],
        })

    prompt = f"""You are a SOC team lead. Given these open incidents, recommend the priority order for an analyst.

Open incidents:
{json.dumps(inc_summaries, indent=2, default=str)}

Prioritisation factors (in order of importance):
1. AI triage confidence score (higher = more likely real)
2. Asset criticality (critical > high > medium > low)
3. Severity (critical > high > medium > low)
4. Age (older uninvestigated incidents are concerning)
5. MITRE technique (lateral movement, credential access, persistence > authentication, network)

Return ONLY valid JSON:
{{
  "recommendation": "<1-2 sentence overall recommendation>",
  "queue": [
    {{
      "id": "<incident id>",
      "priority": 1,
      "reason": "<one sentence why this should be first>"
    }},
    ...
  ]
}}

Include all incidents in the queue, ordered by recommended priority."""

    raw = _call_ai(prompt, config, max_tokens=800)
    try:
        text = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        return json.loads(text)
    except Exception:
        return {
            "recommendation": raw[:300],
            "queue": [{"id": str(i.get("_id", "")), "priority": n + 1, "reason": "Manual review needed"}
                      for n, i in enumerate(incidents[:10])],
        }


# ── 4. Is This Normal? ────────────────────────────────────────────────────────

def is_this_normal(event: dict, asset: dict, baseline: dict, config: dict) -> str:
    """
    Answer "is this event normal for this host?" using asset profile + baseline.
    """
    hostname = event.get("hostname", "unknown")
    process = event.get("process_name", "")
    known_processes = asset.get("known_processes", [])
    known_users = asset.get("known_users", [])
    subject_user = event.get("subject_username", "")
    avg_rate = asset.get("avg_hourly_events", "unknown")
    role = asset.get("role", "unknown")

    process_known = process.lower() in [p.lower() for p in known_processes] if process else None
    user_known = subject_user.lower() in [u.lower() for u in known_users] if subject_user else None

    prompt = f"""You are a security analyst assessing whether an event is normal for a specific host.
Answer in 2-3 sentences. Be direct. State clearly: normal, suspicious, or definitely abnormal.

## Event
- Type: {event.get('category', '')} — Event ID {event.get('event_id', '')}
- Description: {event.get('message', '')[:300]}
- Process: {process or 'not applicable'}
- User: {subject_user or 'not applicable'}
- Source IP: {event.get('source_ip', 'none')}
- Command line: {event.get('command_line', 'none')[:200]}

## Host Profile for {hostname}
- Role: {role}
- Criticality: {asset.get('criticality', 'unknown')}
- Is this process in the known process list? {process_known if process_known is not None else 'no process data'}
- Is this user in the known user list? {user_known if user_known is not None else 'no user data'}
- Average hourly event volume: {avg_rate}
- Known users on this host: {', '.join(known_users[:10]) or 'none recorded'}
- Known processes on this host: {', '.join(known_processes[:15]) or 'none recorded'}

Is this event normal for this host? Why or why not? What should the analyst do?"""

    return _call_ai(prompt, config, max_tokens=300)


# ── 5. Playbook Generator ─────────────────────────────────────────────────────

def draft_playbook(incident: dict, config: dict) -> str:
    """
    Generate a step-by-step containment and investigation playbook
    for the specific attack type detected.
    """
    mitre = ", ".join(incident.get("mitre_technique", [])) or "unknown technique"
    category = incident.get("category", "")
    severity = incident.get("severity", "medium")
    hostname = incident.get("hostname", "unknown")
    rule_name = incident.get("rule_name", "")

    prompt = f"""You are an incident response expert. Write a step-by-step playbook for a SOC analyst
responding to this specific incident. Use numbered steps. Be concrete and Windows-specific.

## Incident
- Rule triggered: {rule_name}
- Category: {category}
- Severity: {severity.upper()}
- Affected host: {hostname}
- MITRE techniques: {mitre}
- Description: {incident.get('description', '')}

Generate a playbook with these phases:

## Phase 1: Immediate Containment (0-15 minutes)
Numbered steps to stop the bleeding. Include specific Windows commands.

## Phase 2: Evidence Collection (15-60 minutes)
What to collect before making changes. Specific artifacts, logs, memory.

## Phase 3: Investigation (1-4 hours)
How to determine scope — what else was accessed, what lateral movement occurred.

## Phase 4: Eradication & Recovery
Steps to remove the threat and restore to known-good state.

## Phase 5: Post-Incident
Documentation, lessons learned, rule tuning.

Be specific. Use actual commands (PowerShell, Event Viewer paths, registry keys).
Format as numbered lists within each phase."""

    return _call_ai(prompt, config, max_tokens=1200)


# ── 6. Compliance Impact Analysis ─────────────────────────────────────────────

def compliance_impact(incident: dict, config: dict) -> dict:
    """
    Analyse which compliance controls this incident affects.
    Returns per-framework impact assessment.
    """
    mitre = incident.get("mitre_technique", [])
    category = incident.get("category", "")
    severity = incident.get("severity", "medium")

    prompt = f"""You are a compliance officer assessing the impact of a security incident on regulatory frameworks.

## Incident
- Category: {category}
- Severity: {severity}
- MITRE techniques: {', '.join(mitre) or 'unknown'}
- Description: {incident.get('description', '')[:400]}

For each relevant framework below, state:
1. Which specific controls are affected
2. Whether this is a reportable event under the framework
3. What documentation is required

Frameworks to assess: SOC 2 Type II, NIST CSF 2.0, ISO 27001:2022, GDPR (if user data involved), PCI-DSS (if payment systems involved)

Return ONLY valid JSON:
{{
  "affected_frameworks": [
    {{
      "framework": "<name>",
      "affected_controls": ["<control_id>: <name>"],
      "reportable": true/false,
      "reporting_deadline": "<if reportable, e.g. 72 hours for GDPR>",
      "required_actions": ["<action 1>", "<action 2>"],
      "risk_level": "low|medium|high|critical"
    }}
  ],
  "immediate_notification_required": true/false,
  "summary": "<one sentence summary of compliance impact>"
}}"""

    raw = _call_ai(prompt, config, max_tokens=700)
    try:
        text = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        return json.loads(text)
    except Exception:
        return {"summary": raw[:400], "affected_frameworks": [], "immediate_notification_required": False}


# ── 7. Free-form Chat ─────────────────────────────────────────────────────────

def copilot_chat(message: str, context: dict, history: list, config: dict) -> str:
    """
    Free-form conversational interface with SIEM context injected.
    context: {open_incidents, recent_events_count, active_agents, top_threat}
    history: list of {role, content} dicts (last 10 turns)
    """
    system = f"""You are WatchTower Copilot, an expert security analyst assistant built into the WatchTower SIEM.
You have access to the current state of the organisation's security posture.

## Current Context
- Open incidents: {context.get('open_incidents', 0)}
- Critical open incidents: {context.get('critical_incidents', 0)}
- Events in last 24h: {context.get('events_24h', 0):,}
- Active monitored endpoints: {context.get('active_agents', 0)}
- Most common threat category today: {context.get('top_category', 'none')}
- Highest triage score today: {context.get('max_triage_score', 'N/A')}

You can answer questions about:
- Security concepts, MITRE ATT&CK techniques, attacker TTPs
- How to investigate specific incident types
- What specific event IDs mean
- Compliance requirements and control mappings
- How to use WatchTower features
- General SOC best practices

Be concise, accurate, and security-focused. If asked about specific data you don't have access to,
suggest using the Natural Language Hunt feature or specific API endpoints.
Do not make up specific data — only use the context provided."""

    messages = []
    # Include last 10 conversation turns
    for turn in history[-10:]:
        messages.append({"role": turn["role"], "content": turn["content"]})
    messages.append({"role": "user", "content": message})

    provider = config.get("AI_PROVIDER", "anthropic")
    model = config.get("AI_MODEL", "claude-sonnet-4-6")

    try:
        if provider == "anthropic":
            import anthropic
            client = anthropic.Anthropic(api_key=config.get("ANTHROPIC_API_KEY", ""))
            msg = client.messages.create(
                model=model, max_tokens=800,
                system=system,
                messages=messages,
            )
            return msg.content[0].text
        elif provider == "openai":
            from openai import OpenAI
            client = OpenAI(api_key=config.get("OPENAI_API_KEY", ""))
            resp = client.chat.completions.create(
                model=model, max_tokens=800,
                messages=[{"role": "system", "content": system}] + messages,
            )
            return resp.choices[0].message.content
    except Exception as e:
        logger.error(f"Copilot chat failed: {e}")
        return "I'm having trouble connecting to the AI service. Please check the API key configuration."


# ── Shared AI caller ──────────────────────────────────────────────────────────

def _call_ai(prompt: str, config: dict, max_tokens: int = 600) -> str:
    provider = config.get("AI_PROVIDER", "anthropic")
    model = config.get("AI_MODEL", "claude-sonnet-4-6")

    try:
        if provider == "anthropic":
            import anthropic
            client = anthropic.Anthropic(api_key=config.get("ANTHROPIC_API_KEY", ""))
            msg = client.messages.create(
                model=model, max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}]
            )
            return msg.content[0].text
        elif provider == "openai":
            from openai import OpenAI
            client = OpenAI(api_key=config.get("OPENAI_API_KEY", ""))
            resp = client.chat.completions.create(
                model=model, max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}]
            )
            return resp.choices[0].message.content
    except Exception as e:
        logger.error(f"AI call failed: {e}")
        return f"AI service unavailable: {str(e)[:100]}"

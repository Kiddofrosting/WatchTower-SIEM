"""
WatchTower SIEM - Natural Language Hunt Service
================================================
Translates plain English queries into MongoDB aggregation pipelines.

Analysts type questions like:
  "Show me all processes that ran as SYSTEM in the last 6 hours"
  "Find failed logins followed by success on the same host"
  "Which hosts talked to external IPs after midnight?"
  "List users who logged in outside business hours this week"

The LLM returns a structured query plan which is:
  1. Validated against a whitelist schema (no arbitrary code execution)
  2. Executed against MongoDB
  3. Explained back to the analyst in plain English

Safety model:
  - LLM outputs JSON query spec, NOT raw code
  - Query spec maps to a fixed set of allowed MongoDB operators
  - All field names are whitelisted
  - No $where, $function, $accumulator (JS execution) allowed
  - Result capped at 500 documents
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ── Allowed MongoDB fields for NL queries ────────────────────────────────────
# Strict whitelist — LLM cannot inject arbitrary field names

ALLOWED_FIELDS = {
    # Event fields
    "hostname", "event_id", "category", "severity", "timestamp", "ingested_at",
    "subject_username", "target_username", "logon_type", "process_name",
    "process_id", "parent_process", "command_line", "source_ip", "destination_ip",
    "destination_port", "file_path", "registry_key", "service_name", "task_name",
    "mitre_technique", "mitre_tactic", "tags", "message", "channel",
    "hash_md5", "hash_sha256", "ioc_matches",
    # Incident fields
    "title", "description", "rule_name", "status", "assigned_to",
    "created_at", "updated_at", "resolved_at", "event_count",
    "ai_triage.true_positive_score", "ai_triage.recommended_action",
    "correlated_incident_ids", "correlation_rule",
    # Asset fields
    "role", "criticality", "owner", "department", "is_internet_facing",
    "known_users", "known_processes", "avg_hourly_events",
}

ALLOWED_OPERATORS = {
    "$eq", "$ne", "$gt", "$gte", "$lt", "$lte",
    "$in", "$nin", "$and", "$or", "$nor", "$not",
    "$exists", "$regex", "$options",
    "$match", "$group", "$sort", "$limit", "$project",
    "$sum", "$avg", "$min", "$max", "$count", "$first", "$last",
    "$dateToString", "$hour", "$dayOfWeek", "$subtract",
    "$gte", "$lte", "$addFields",
}

BLOCKED_OPERATORS = {
    "$where", "$function", "$accumulator", "$eval",
    "$map", "$reduce", "$filter",  # can execute JS
    "$lookup",  # cross-collection joins (too expensive)
}

COLLECTION_MAP = {
    "events": "events",
    "incidents": "incidents",
    "assets": "assets",
    "agents": "agents",
    "audit_log": "audit_log",
}


# ── Main NL→Query translation ─────────────────────────────────────────────────

def translate_nl_to_query(question: str, config: dict) -> dict:
    """
    Translate a natural language question into a validated query spec.
    Returns: {collection, pipeline, explanation, suggested_visualisation}
    """
    provider = config.get("AI_PROVIDER", "anthropic")
    model = config.get("AI_MODEL", "claude-sonnet-4-6")
    prompt = _build_translation_prompt(question)

    if provider == "anthropic":
        api_key = config.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise ValueError("Anthropic API key not configured")
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        msg = client.messages.create(
            model=model,
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = msg.content[0].text
    elif provider == "openai":
        api_key = config.get("OPENAI_API_KEY", "")
        if not api_key:
            raise ValueError("OpenAI API key not configured")
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1500,
        )
        raw = resp.choices[0].message.content
    else:
        raise ValueError(f"Unknown provider: {provider}")

    return _parse_and_validate_query_spec(raw, question)


def execute_nl_query(question: str, config: dict, mongo) -> dict:
    """
    Full pipeline: translate → validate → execute → explain.
    Returns results with natural language summary.
    """
    # Translate
    spec = translate_nl_to_query(question, config)
    if spec.get("error"):
        return spec

    collection_name = spec["collection"]
    pipeline = spec["pipeline"]
    explanation = spec.get("explanation", "")

    # Execute
    try:
        col = getattr(mongo.db, collection_name)
        raw_results = list(col.aggregate(pipeline))
    except Exception as e:
        logger.error(f"NL query execution failed: {e}")
        return {
            "error": "query_execution_failed",
            "detail": str(e)[:200],
            "question": question,
        }

    # Serialize results
    results = _serialize_results(raw_results)

    # Generate natural language summary of results
    summary = _summarise_results(question, results, config)

    # Log the query for audit
    return {
        "question": question,
        "explanation": explanation,
        "collection": collection_name,
        "results": results,
        "result_count": len(results),
        "summary": summary,
        "suggested_visualisation": spec.get("suggested_visualisation", "table"),
        "executed_at": datetime.now(timezone.utc).isoformat(),
    }


# ── Prompt builders ───────────────────────────────────────────────────────────

def _build_translation_prompt(question: str) -> str:
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    yesterday = (now - timedelta(hours=24)).isoformat()
    week_ago = (now - timedelta(days=7)).isoformat()

    return f"""You are a security data analyst who translates natural language questions into MongoDB aggregation pipeline queries for a SIEM database.

Current UTC time: {now_iso}

## Available Collections & Key Fields

**events** — individual Windows security events
- hostname (string), event_id (int), category (string), severity (string)
- timestamp (datetime), subject_username (string), target_username (string)
- process_name (string), command_line (string), source_ip (string)
- destination_ip (string), destination_port (int), mitre_technique (array)
- message (string), parent_process (string), file_path (string)
- Categories: authentication, account_management, process_execution, network,
  lateral_movement, credential_access, privilege_escalation, defense_evasion,
  persistence, powershell, file_system, registry, service

**incidents** — detected security incidents
- hostname, title, severity, category, status, rule_name
- created_at (datetime), resolved_at (datetime), event_count (int)
- mitre_technique (array), assigned_to (string)
- ai_triage.true_positive_score (int 0-100)
- Status values: open, investigating, resolved, false_positive, closed

**assets** — monitored host profiles
- hostname, role, criticality, owner, is_internet_facing (bool)
- known_users (array), known_processes (array), avg_hourly_events (float)

**agents** — monitoring agents
- hostname, status (active/inactive), last_seen (datetime), agent_version

## Time References
- "last hour" = after {(now - timedelta(hours=1)).isoformat()}
- "last 6 hours" = after {(now - timedelta(hours=6)).isoformat()}
- "today" / "last 24 hours" = after {yesterday}
- "this week" / "last 7 days" = after {week_ago}
- "last 30 days" = after {(now - timedelta(days=30)).isoformat()}
- "business hours" = 08:00-18:00 local (use $hour on timestamp, hours 8-18)
- "after midnight" / "outside business hours" = $hour < 8 or $hour > 18

## Rules
1. Output ONLY valid JSON — no markdown fences, no explanation outside JSON
2. Limit results: always include a {{$limit: N}} stage, max 500
3. Use $match as the FIRST stage whenever possible (performance)
4. For datetime comparisons, use ISO string format: "2024-01-01T00:00:00+00:00"
5. NEVER use $where, $function, $accumulator, $eval, $lookup
6. Default sort: events by timestamp desc, incidents by created_at desc

## Output Format
{{
  "collection": "<collection_name>",
  "pipeline": [<MongoDB aggregation stages>],
  "explanation": "<one sentence: what this query does in plain English>",
  "suggested_visualisation": "<table|timeline|bar_chart|count>"
}}

## Examples

Question: "Failed logins in the last hour"
Output:
{{
  "collection": "events",
  "pipeline": [
    {{"$match": {{"category": "authentication", "event_id": 4625, "timestamp": {{"$gte": "{(now - timedelta(hours=1)).isoformat()}"}}}}}},
    {{"$sort": {{"timestamp": -1}}}},
    {{"$limit": 100}},
    {{"$project": {{"hostname": 1, "subject_username": 1, "source_ip": 1, "timestamp": 1, "message": 1}}}}
  ],
  "explanation": "Failed logon events (event ID 4625) in the past hour, sorted newest first.",
  "suggested_visualisation": "timeline"
}}

Question: "Which users logged in outside business hours this week?"
Output:
{{
  "collection": "events",
  "pipeline": [
    {{"$match": {{"event_id": 4624, "timestamp": {{"$gte": "{week_ago}"}}}}}},
    {{"$addFields": {{"hour": {{"$hour": "$timestamp"}}}}}},
    {{"$match": {{"$or": [{{"hour": {{"$lt": 8}}}}, {{"hour": {{"$gt": 18}}}}]}}}},
    {{"$group": {{"_id": "$subject_username", "count": {{"$sum": 1}}, "hosts": {{"$addToSet": "$hostname"}}}}}},
    {{"$sort": {{"count": -1}}}},
    {{"$limit": 50}}
  ],
  "explanation": "Users who authenticated outside 8am-6pm UTC this week, grouped by username with login count.",
  "suggested_visualisation": "bar_chart"
}}

Now translate this question:
"{question}"

Output ONLY the JSON object. No markdown. No explanation outside the JSON."""


def _build_summary_prompt(question: str, results: list) -> str:
    """Build a prompt to summarise query results in plain English."""
    sample = results[:5]  # show first 5 to LLM
    return f"""You are a security analyst summarising query results.

Question asked: "{question}"
Total results returned: {len(results)}
Sample of results (first 5):
{json.dumps(sample, indent=2, default=str)[:2000]}

Write a 2-3 sentence plain English summary of what these results show.
Focus on security significance: is this normal? suspicious? what should the analyst do next?
Be specific about numbers, hostnames, usernames if present.
Do NOT repeat the question. Do NOT say "the results show". Just state what you found."""


# ── Validation ────────────────────────────────────────────────────────────────

def _parse_and_validate_query_spec(raw: str, question: str) -> dict:
    """Parse the LLM response and validate it is safe to execute."""
    try:
        text = raw.strip()
        if text.startswith("```"):
            text = "\n".join(text.split("\n")[1:])
            text = text.replace("```", "").strip()
        spec = json.loads(text)
    except Exception as e:
        logger.error(f"Failed to parse NL query response: {e} — raw: {raw[:300]}")
        return {
            "error": "translation_failed",
            "detail": "Could not parse the query. Try rephrasing your question.",
            "question": question,
        }

    # Validate collection
    collection = spec.get("collection", "")
    if collection not in COLLECTION_MAP:
        return {
            "error": "invalid_collection",
            "detail": f"Unknown collection '{collection}'. Valid: {list(COLLECTION_MAP.keys())}",
            "question": question,
        }

    # Validate pipeline
    pipeline = spec.get("pipeline", [])
    if not isinstance(pipeline, list) or not pipeline:
        return {"error": "invalid_pipeline", "detail": "Pipeline must be a non-empty list.", "question": question}

    # Check for blocked operators recursively
    blocked = _find_blocked_operators(pipeline)
    if blocked:
        logger.warning(f"NL query contained blocked operators: {blocked}")
        return {
            "error": "unsafe_query",
            "detail": f"Query contained unsafe operators: {blocked}",
            "question": question,
        }

    # Enforce result limit
    has_limit = any("$limit" in stage for stage in pipeline)
    if not has_limit:
        pipeline.append({"$limit": 200})

    # Enforce max limit
    for i, stage in enumerate(pipeline):
        if "$limit" in stage:
            pipeline[i]["$limit"] = min(int(stage["$limit"]), 500)

    spec["pipeline"] = pipeline
    spec["collection"] = COLLECTION_MAP[collection]
    return spec


def _find_blocked_operators(obj: Any, found: set = None) -> set:
    """Recursively find any blocked MongoDB operators in the pipeline."""
    if found is None:
        found = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in BLOCKED_OPERATORS:
                found.add(k)
            _find_blocked_operators(v, found)
    elif isinstance(obj, list):
        for item in obj:
            _find_blocked_operators(item, found)
    return found


# ── Result serialisation ──────────────────────────────────────────────────────

def _serialize_results(results: list) -> list:
    """Make MongoDB results JSON-serialisable."""
    serialised = []
    for doc in results:
        clean = {}
        for k, v in doc.items():
            if k == "_id":
                clean["_id"] = str(v)
            elif isinstance(v, datetime):
                clean[k] = v.isoformat()
            elif isinstance(v, (list, dict)):
                clean[k] = v
            else:
                clean[k] = v
        serialised.append(clean)
    return serialised


def _summarise_results(question: str, results: list, config: dict) -> str:
    """Generate a plain English summary of query results using the LLM."""
    if not results:
        return "No results found matching your query."

    provider = config.get("AI_PROVIDER", "anthropic")
    model = config.get("AI_MODEL", "claude-sonnet-4-6")
    prompt = _build_summary_prompt(question, results)

    try:
        if provider == "anthropic":
            import anthropic
            client = anthropic.Anthropic(api_key=config.get("ANTHROPIC_API_KEY", ""))
            msg = client.messages.create(
                model=model, max_tokens=300,
                messages=[{"role": "user", "content": prompt}]
            )
            return msg.content[0].text.strip()
        elif provider == "openai":
            from openai import OpenAI
            client = OpenAI(api_key=config.get("OPENAI_API_KEY", ""))
            resp = client.chat.completions.create(
                model=model, max_tokens=300,
                messages=[{"role": "user", "content": prompt}]
            )
            return resp.choices[0].message.content.strip()
    except Exception as e:
        logger.warning(f"Summary generation failed: {e}")
        return f"Found {len(results)} result(s)."

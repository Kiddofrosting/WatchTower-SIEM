"""
WatchTower SIEM - Detection Rules API
CRUD, rule testing, Sigma import, false-positive suppression.
"""

from datetime import datetime, timezone

from bson import ObjectId
from flask import Blueprint, jsonify, request

from watchtower.app import mongo
from watchtower.app.models import RuleSchema, UserRole, new_rule
from watchtower.app.security import require_auth, require_roles, audit_log_action

rules_bp = Blueprint("rules", __name__)
_rule_schema = RuleSchema()


@rules_bp.get("/")
@require_auth
def list_rules():
    query = {}
    if request.args.get("category"):
        query["category"] = request.args["category"]
    if request.args.get("severity"):
        query["severity"] = request.args["severity"]
    if request.args.get("enabled") is not None:
        query["enabled"] = request.args["enabled"].lower() == "true"

    rules = list(mongo.db.rules.find(query).sort("name", 1))
    for r in rules:
        r["_id"] = str(r["_id"])
        for f in ("created_at", "updated_at", "last_triggered"):
            if isinstance(r.get(f), datetime):
                r[f] = r[f].isoformat()
    return jsonify({"data": rules, "total": len(rules)}), 200


@rules_bp.get("/<rule_id>")
@require_auth
def get_rule(rule_id: str):
    try:
        oid = ObjectId(rule_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400
    rule = mongo.db.rules.find_one({"_id": oid})
    if not rule:
        return jsonify({"error": "not_found"}), 404
    rule["_id"] = str(rule["_id"])
    for f in ("created_at", "updated_at", "last_triggered"):
        if isinstance(rule.get(f), datetime):
            rule[f] = rule[f].isoformat()
    return jsonify(rule), 200


@rules_bp.post("/")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN)
def create_rule():
    from flask_jwt_extended import current_user
    data = request.get_json(silent=True) or {}
    errors = _rule_schema.validate(data)
    if errors:
        return jsonify({"error": "validation_error", "details": errors}), 422

    if mongo.db.rules.find_one({"name": data["name"]}):
        return jsonify({"error": "rule_name_exists"}), 409

    rule_doc = new_rule(
        name=data["name"],
        description=data["description"],
        category=data["category"],
        severity=data["severity"],
        condition=data["condition"],
        created_by=str(current_user["_id"]),
        mitre_technique=data.get("mitre_technique", []),
        mitre_tactic=data.get("mitre_tactic", []),
    )
    rule_doc["enabled"] = data.get("enabled", True)
    rule_doc["references"] = data.get("references", [])
    rule_doc["tags"] = data.get("tags", [])

    result = mongo.db.rules.insert_one(rule_doc)
    audit_log_action(current_user, "rule_created", "rule", str(result.inserted_id), {"name": data["name"]})
    return jsonify({"message": "Rule created", "rule_id": str(result.inserted_id)}), 201


@rules_bp.put("/<rule_id>")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN)
def update_rule(rule_id: str):
    from flask_jwt_extended import current_user
    try:
        oid = ObjectId(rule_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400

    if not mongo.db.rules.find_one({"_id": oid}):
        return jsonify({"error": "not_found"}), 404

    data = request.get_json(silent=True) or {}
    errors = _rule_schema.validate(data, partial=True)
    if errors:
        return jsonify({"error": "validation_error", "details": errors}), 422

    updates = {k: v for k, v in data.items() if k in _rule_schema.fields}
    updates["updated_at"] = datetime.now(timezone.utc)
    updates["updated_by"] = str(current_user["_id"])

    mongo.db.rules.update_one({"_id": oid}, {"$set": updates})
    audit_log_action(current_user, "rule_updated", "rule", rule_id, {"fields": list(updates.keys())})
    return jsonify({"message": "Rule updated"}), 200


@rules_bp.patch("/<rule_id>/toggle")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN)
def toggle_rule(rule_id: str):
    from flask_jwt_extended import current_user
    try:
        oid = ObjectId(rule_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400

    rule = mongo.db.rules.find_one({"_id": oid})
    if not rule:
        return jsonify({"error": "not_found"}), 404

    new_state = not rule.get("enabled", True)
    mongo.db.rules.update_one({"_id": oid}, {"$set": {"enabled": new_state, "updated_at": datetime.now(timezone.utc)}})
    audit_log_action(current_user, "rule_toggled", "rule", rule_id, {"enabled": new_state})
    return jsonify({"enabled": new_state}), 200


@rules_bp.delete("/<rule_id>")
@require_roles(UserRole.SUPER_ADMIN)
def delete_rule(rule_id: str):
    from flask_jwt_extended import current_user
    try:
        oid = ObjectId(rule_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400

    result = mongo.db.rules.delete_one({"_id": oid})
    if result.deleted_count == 0:
        return jsonify({"error": "not_found"}), 404

    audit_log_action(current_user, "rule_deleted", "rule", rule_id, {})
    return jsonify({"message": "Rule deleted"}), 200


# ── Rule Test / Simulation (NEW) ──────────────────────────────────────────────

@rules_bp.post("/<rule_id>/test")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.ANALYST)
def test_rule(rule_id: str):
    """
    Test a rule against a sample event payload without touching the database.
    Body: { "event": { ...sample event fields... } }
    Returns: { "matched": bool, "reason": str }
    """
    try:
        oid = ObjectId(rule_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400

    rule = mongo.db.rules.find_one({"_id": oid})
    if not rule:
        return jsonify({"error": "not_found"}), 404

    data = request.get_json(silent=True) or {}
    sample_event = data.get("event")
    if not sample_event or not isinstance(sample_event, dict):
        return jsonify({"error": "event object required in request body"}), 422

    from watchtower.app.detection.engine import DetectionEngine
    engine = DetectionEngine(mongo, {})
    matched = engine._event_matches_condition(sample_event, rule.get("condition", {}))

    return jsonify({
        "matched": matched,
        "rule_name": rule.get("name"),
        "condition": rule.get("condition"),
        "reason": "Event matches all conditions." if matched else "Event did not match one or more conditions.",
    }), 200


# ── Sigma Rule Import (NEW) ────────────────────────────────────────────────────

@rules_bp.post("/import-sigma")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN)
def import_sigma_rule():
    """
    Accept a Sigma YAML rule and convert it to a WatchTower detection rule.
    Body: { "sigma_yaml": "<yaml string>" }
    """
    from flask_jwt_extended import current_user
    import yaml

    data = request.get_json(silent=True) or {}
    sigma_yaml = data.get("sigma_yaml", "")
    if not sigma_yaml:
        return jsonify({"error": "sigma_yaml is required"}), 422

    try:
        sigma = yaml.safe_load(sigma_yaml)
    except Exception as e:
        return jsonify({"error": "invalid_yaml", "detail": str(e)}), 422

    # Basic Sigma transpilation
    title = sigma.get("title", "Imported Sigma Rule")
    description = sigma.get("description", "")
    sigma_id = sigma.get("id", "")
    tags = sigma.get("tags", [])
    level_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "informational": "info"}
    severity = level_map.get(sigma.get("level", "medium"), "medium")

    # Extract MITRE tags
    mitre_techniques = [t.replace("attack.t", "T").upper() for t in tags if t.lower().startswith("attack.t")]
    mitre_tactics = [t.replace("attack.", "").replace("_", " ").title() for t in tags
                     if t.lower().startswith("attack.") and not t.lower().startswith("attack.t")]

    # Attempt to extract event IDs from detection
    detection = sigma.get("detection", {})
    condition_dsl = {"fields": {}}
    event_ids = []

    for key, val in detection.items():
        if key == "condition":
            continue
        if isinstance(val, dict):
            for field, fval in val.items():
                if field.lower() in ("eventid", "event_id"):
                    ids = fval if isinstance(fval, list) else [fval]
                    event_ids.extend([int(i) for i in ids if str(i).isdigit()])
                else:
                    normalized_field = field.lower().replace(".", "_")
                    if isinstance(fval, list):
                        condition_dsl["fields"][normalized_field] = {"contains": fval[0]} if fval else {}
                    else:
                        condition_dsl["fields"][normalized_field] = {"contains": str(fval)}

    if event_ids:
        condition_dsl["event_ids"] = event_ids

    rule_name = title
    if mongo.db.rules.find_one({"name": rule_name}):
        rule_name = f"{title} (Sigma Import)"

    references = sigma.get("references", [])

    rule_doc = new_rule(
        name=rule_name,
        description=description,
        category=sigma.get("category", "other"),
        severity=severity,
        condition=condition_dsl,
        created_by=str(current_user["_id"]),
        mitre_technique=mitre_techniques,
        mitre_tactic=mitre_tactics,
    )
    rule_doc["sigma_rule_id"] = sigma_id
    rule_doc["tags"] = tags
    rule_doc["references"] = references

    result = mongo.db.rules.insert_one(rule_doc)
    audit_log_action(current_user, "rule_sigma_imported", "rule", str(result.inserted_id),
                     {"sigma_id": sigma_id, "title": title})

    return jsonify({
        "message": "Sigma rule imported successfully",
        "rule_id": str(result.inserted_id),
        "rule_name": rule_name,
        "notes": "Review the imported condition DSL — automatic transpilation may need tuning.",
    }), 201


# ── Rule Stats (NEW) ──────────────────────────────────────────────────────────

@rules_bp.get("/<rule_id>/stats")
@require_auth
def rule_stats(rule_id: str):
    """Return hit counts and daily trend for a rule."""
    from datetime import timedelta
    try:
        oid = ObjectId(rule_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400

    rule = mongo.db.rules.find_one({"_id": oid}, {"name": 1, "hit_count": 1, "last_triggered": 1})
    if not rule:
        return jsonify({"error": "not_found"}), 404

    now = datetime.now(timezone.utc)
    pipeline = [
        {"$match": {"rule_id": rule_id, "created_at": {"$gte": now - timedelta(days=30)}}},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$created_at"}},
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}},
    ]
    daily = list(mongo.db.incidents.aggregate(pipeline))

    return jsonify({
        "rule_id": rule_id,
        "rule_name": rule.get("name"),
        "total_hits": rule.get("hit_count", 0),
        "last_triggered": rule.get("last_triggered").isoformat() if rule.get("last_triggered") else None,
        "daily_trend_30d": [{"date": d["_id"], "count": d["count"]} for d in daily],
    }), 200


# ── Seed built-in rules (unchanged) ──────────────────────────────────────────

@rules_bp.post("/seed")
@require_roles(UserRole.SUPER_ADMIN)
def seed_builtin_rules():
    from flask_jwt_extended import current_user
    from watchtower.app.detection.builtin_rules import BUILTIN_RULES

    inserted = 0
    skipped = 0
    for rule_def in BUILTIN_RULES:
        if mongo.db.rules.find_one({"name": rule_def["name"]}):
            skipped += 1
            continue
        rule_doc = new_rule(
            name=rule_def["name"],
            description=rule_def["description"],
            category=rule_def["category"],
            severity=rule_def["severity"],
            condition=rule_def["condition"],
            created_by=str(current_user["_id"]),
            mitre_technique=rule_def.get("mitre_technique", []),
            mitre_tactic=rule_def.get("mitre_tactic", []),
        )
        rule_doc["references"] = rule_def.get("references", [])
        rule_doc["tags"] = rule_def.get("tags", [])
        rule_doc["sigma_rule_id"] = rule_def.get("sigma_rule_id")
        mongo.db.rules.insert_one(rule_doc)
        inserted += 1

    audit_log_action(current_user, "rules_seeded", "rules", "bulk",
                     {"inserted": inserted, "skipped": skipped})
    return jsonify({"message": f"Seeded {inserted} rules, skipped {skipped} existing"}), 200

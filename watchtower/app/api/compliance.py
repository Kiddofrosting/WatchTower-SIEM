"""
WatchTower SIEM - Compliance Posture Engine
===========================================
Maps real telemetry to compliance frameworks (SOC 2, NIST, CIS, ISO 27001, PCI-DSS).
Generates:
  - Live posture score per framework (0–100%)
  - Per-control status with evidence counts
  - Gap analysis (which MITRE techniques have no detection coverage)
  - One-click evidence package (JSON or PDF-ready)
  - IOC management
"""

from datetime import datetime, timedelta, timezone
from flask import Blueprint, jsonify, request, current_app
from watchtower.app import mongo
from watchtower.app.security import require_roles, require_auth, audit_log_action
from watchtower.app.models import UserRole

compliance_bp = Blueprint("compliance", __name__)

# ── Framework definitions ─────────────────────────────────────────────────────
# Each control has:
#   - required_categories: event categories that provide evidence
#   - required_mitre: MITRE techniques that rules should cover
#   - weight: importance for posture score

FRAMEWORKS = {
    "soc2": {
        "name": "SOC 2 Type II",
        "version": "2017",
        "controls": [
            {"id": "CC6.1", "name": "Logical Access Controls",
             "description": "Access to systems is restricted to authorized users",
             "required_categories": ["authentication"], "required_mitre": ["T1078", "T1110"],
             "weight": 3},
            {"id": "CC6.2", "name": "Access Provisioning",
             "description": "New accounts are authorized and documented",
             "required_categories": ["account_management"], "required_mitre": ["T1136"],
             "weight": 2},
            {"id": "CC6.3", "name": "Access Removal",
             "description": "Access is revoked timely upon termination",
             "required_categories": ["account_management"], "required_mitre": [],
             "weight": 2},
            {"id": "CC7.1", "name": "Vulnerability Detection",
             "description": "Vulnerabilities are identified and remediated",
             "required_categories": ["process_execution"], "required_mitre": ["T1059"],
             "weight": 2},
            {"id": "CC7.2", "name": "Anomaly Detection",
             "description": "Anomalies and indicators of compromise are detected",
             "required_categories": ["authentication", "network", "lateral_movement"],
             "required_mitre": ["T1021", "T1071"], "weight": 3},
            {"id": "CC7.3", "name": "Incident Response",
             "description": "Incidents are identified, responded to, and recovered from",
             "required_categories": [], "required_mitre": [], "weight": 3},
            {"id": "CC7.4", "name": "Incident Notification",
             "description": "Incidents are communicated to affected parties",
             "required_categories": [], "required_mitre": [], "weight": 1},
            {"id": "CC8.1", "name": "Change Management",
             "description": "Changes to infrastructure are authorized and tracked",
             "required_categories": ["registry", "service"], "required_mitre": ["T1543"],
             "weight": 2},
        ]
    },
    "nist_csf": {
        "name": "NIST Cybersecurity Framework 2.0",
        "version": "2.0",
        "controls": [
            {"id": "ID.AM", "name": "Asset Management",
             "description": "Assets are inventoried and managed",
             "required_categories": [], "required_mitre": [], "weight": 2,
             "uses_asset_intelligence": True},
            {"id": "PR.AC", "name": "Identity Management & Access Control",
             "description": "Access to assets is limited to authorized users",
             "required_categories": ["authentication", "privilege_escalation"],
             "required_mitre": ["T1078", "T1134"], "weight": 3},
            {"id": "PR.AT", "name": "Awareness & Training",
             "description": "Users understand their security responsibilities",
             "required_categories": [], "required_mitre": [], "weight": 1},
            {"id": "PR.DS", "name": "Data Security",
             "description": "Data is protected to meet confidentiality objectives",
             "required_categories": ["credential_access", "file_system"],
             "required_mitre": ["T1555", "T1083"], "weight": 2},
            {"id": "DE.CM", "name": "Continuous Monitoring",
             "description": "Assets are monitored to identify cybersecurity events",
             "required_categories": ["authentication", "process_execution", "network"],
             "required_mitre": [], "weight": 3},
            {"id": "DE.AE", "name": "Anomalies & Events",
             "description": "Anomalous activity is detected and analyzed",
             "required_categories": [], "required_mitre": [], "weight": 3},
            {"id": "RS.RP", "name": "Response Planning",
             "description": "Response processes are executed during/after incidents",
             "required_categories": [], "required_mitre": [], "weight": 2},
            {"id": "RS.CO", "name": "Communications",
             "description": "Response activities are coordinated with stakeholders",
             "required_categories": [], "required_mitre": [], "weight": 1},
            {"id": "RC.RP", "name": "Recovery Planning",
             "description": "Recovery processes are executed to restore systems",
             "required_categories": [], "required_mitre": [], "weight": 2},
        ]
    },
    "cis_v8": {
        "name": "CIS Controls v8",
        "version": "8.0",
        "controls": [
            {"id": "CIS-01", "name": "Inventory of Enterprise Assets",
             "description": "Actively manage all hardware assets",
             "required_categories": [], "required_mitre": [], "weight": 2,
             "uses_asset_intelligence": True},
            {"id": "CIS-04", "name": "Secure Configuration",
             "description": "Establish and maintain secure configurations",
             "required_categories": ["registry", "service"], "required_mitre": ["T1543"],
             "weight": 2},
            {"id": "CIS-05", "name": "Account Management",
             "description": "Manage the lifecycle of user accounts",
             "required_categories": ["account_management", "authentication"],
             "required_mitre": ["T1136", "T1078"], "weight": 3},
            {"id": "CIS-08", "name": "Audit Log Management",
             "description": "Collect, alert, review, and retain audit logs",
             "required_categories": [], "required_mitre": [], "weight": 3},
            {"id": "CIS-10", "name": "Malware Defense",
             "description": "Prevent and control malware installation",
             "required_categories": ["process_execution", "defense_evasion"],
             "required_mitre": ["T1059", "T1055"], "weight": 3},
            {"id": "CIS-13", "name": "Network Monitoring & Defense",
             "description": "Monitor and defend the network perimeter",
             "required_categories": ["network", "lateral_movement"],
             "required_mitre": ["T1021", "T1071"], "weight": 2},
            {"id": "CIS-16", "name": "Application Software Security",
             "description": "Manage security lifecycle of in-house software",
             "required_categories": [], "required_mitre": [], "weight": 1},
            {"id": "CIS-17", "name": "Incident Response Management",
             "description": "Establish and maintain an IR program",
             "required_categories": [], "required_mitre": [], "weight": 3},
        ]
    },
    "iso27001": {
        "name": "ISO/IEC 27001:2022",
        "version": "2022",
        "controls": [
            {"id": "A.5.9", "name": "Inventory of Information Assets",
             "description": "Assets associated with information are identified and inventoried",
             "required_categories": [], "required_mitre": [], "weight": 2,
             "uses_asset_intelligence": True},
            {"id": "A.5.15", "name": "Access Control",
             "description": "Rules for controlling access to information are established",
             "required_categories": ["authentication", "privilege_escalation"],
             "required_mitre": ["T1078"], "weight": 3},
            {"id": "A.5.24", "name": "Information Security Incident Management",
             "description": "Responsibilities for incident management are defined",
             "required_categories": [], "required_mitre": [], "weight": 3},
            {"id": "A.5.25", "name": "Assessment of IS Events",
             "description": "Security events are assessed and classified",
             "required_categories": [], "required_mitre": [], "weight": 2},
            {"id": "A.8.15", "name": "Logging",
             "description": "Logs that record activities are produced, stored and protected",
             "required_categories": ["authentication", "process_execution"],
             "required_mitre": [], "weight": 3},
            {"id": "A.8.16", "name": "Monitoring Activities",
             "description": "Networks and systems are monitored for anomalous behaviour",
             "required_categories": ["authentication", "network", "lateral_movement"],
             "required_mitre": [], "weight": 3},
            {"id": "A.8.22", "name": "Segregation of Networks",
             "description": "Groups of services and users are segregated",
             "required_categories": ["network", "lateral_movement"],
             "required_mitre": ["T1021"], "weight": 2},
        ]
    },
}


# ── Posture calculation ───────────────────────────────────────────────────────

def _score_control(control: dict, period_start: datetime, mongo) -> dict:
    """
    Score a single control 0–100 based on evidence in the database.
    Returns enriched control dict with status, score, evidence counts.
    """
    cats = control.get("required_categories", [])
    mitre = control.get("required_mitre", [])
    uses_assets = control.get("uses_asset_intelligence", False)

    evidence_counts = {}
    score = 0
    max_score = 0

    # Asset intelligence contribution
    if uses_assets:
        max_score += 30
        asset_count = mongo.db.assets.count_documents({})
        if asset_count > 0:
            owned = mongo.db.assets.count_documents({"owner": {"$nin": ["", None]}})
            coverage = owned / asset_count
            score += int(coverage * 30)
            evidence_counts["assets_inventoried"] = asset_count
            evidence_counts["assets_with_owner"] = owned

    # Event category coverage
    if cats:
        max_score += 40
        cats_with_events = 0
        for cat in cats:
            count = mongo.db.events.count_documents({
                "category": cat,
                "timestamp": {"$gte": period_start}
            })
            evidence_counts[f"events_{cat}"] = count
            if count > 0:
                cats_with_events += 1
        cat_coverage = cats_with_events / len(cats)
        score += int(cat_coverage * 40)

    # MITRE detection rule coverage
    if mitre:
        max_score += 30
        covered_techniques = 0
        for technique in mitre:
            has_rule = mongo.db.rules.count_documents({
                "enabled": True,
                "mitre_technique": technique,
            })
            if has_rule:
                covered_techniques += 1
        mitre_coverage = covered_techniques / len(mitre)
        score += int(mitre_coverage * 30)
        evidence_counts["mitre_techniques_covered"] = covered_techniques
        evidence_counts["mitre_techniques_required"] = len(mitre)

    # Incident response quality (for incident-related controls)
    if not cats and not mitre and not uses_assets:
        max_score += 100
        total_inc = mongo.db.incidents.count_documents({"created_at": {"$gte": period_start}})
        if total_inc == 0:
            # No incidents yet — can't score IR quality, give partial credit
            score += 50
        else:
            resolved = mongo.db.incidents.count_documents({
                "created_at": {"$gte": period_start},
                "status": {"$in": ["resolved", "closed", "false_positive"]}
            })
            resolution_rate = resolved / total_inc
            score += int(resolution_rate * 100)
        evidence_counts["total_incidents"] = total_inc

    # Normalise to 0–100
    final_score = min(100, int((score / max(max_score, 1)) * 100)) if max_score else 50

    # Determine status
    if final_score >= 80:
        status = "compliant"
    elif final_score >= 50:
        status = "partial"
    else:
        status = "gap"

    return {
        **control,
        "score": final_score,
        "status": status,
        "evidence": evidence_counts,
    }


# ── API endpoints ─────────────────────────────────────────────────────────────

@compliance_bp.get("/frameworks")
@require_auth
def list_frameworks():
    return jsonify({"frameworks": list(FRAMEWORKS.keys()),
                    "details": {k: {"name": v["name"], "version": v["version"],
                                    "control_count": len(v["controls"])}
                                for k, v in FRAMEWORKS.items()}}), 200


@compliance_bp.get("/posture")
@require_auth
def get_posture_summary():
    """Overall posture score across all frameworks — for the dashboard widget."""
    days = int(request.args.get("days", 30))
    period_start = datetime.now(timezone.utc) - timedelta(days=days)

    summary = {}
    for fw_id, fw in FRAMEWORKS.items():
        scored = [_score_control(c, period_start, mongo) for c in fw["controls"]]
        total_weight = sum(c.get("weight", 1) for c in fw["controls"])
        weighted_score = sum(
            c["score"] * c.get("weight", 1) for c in scored
        ) / max(total_weight, 1)
        compliant = sum(1 for c in scored if c["status"] == "compliant")
        summary[fw_id] = {
            "name": fw["name"],
            "overall_score": round(weighted_score, 1),
            "compliant_controls": compliant,
            "total_controls": len(scored),
            "status": "compliant" if weighted_score >= 80
                      else "partial" if weighted_score >= 50
                      else "at_risk",
        }

    return jsonify({"period_days": days, "frameworks": summary}), 200


@compliance_bp.get("/report/<framework_id>")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.ANALYST)
def generate_report(framework_id: str):
    """
    Full compliance report for a single framework:
    - Per-control scores with evidence
    - Gap analysis
    - MITRE coverage heatmap
    - Recommended actions
    """
    from flask_jwt_extended import current_user

    if framework_id not in FRAMEWORKS:
        return jsonify({"error": "unknown_framework"}), 404

    days = int(request.args.get("days", 30))
    period_start = datetime.now(timezone.utc) - timedelta(days=days)
    fw = FRAMEWORKS[framework_id]

    # Score every control
    scored_controls = [_score_control(c, period_start, mongo) for c in fw["controls"]]

    # Weighted overall score
    total_weight = sum(c.get("weight", 1) for c in fw["controls"])
    weighted_score = sum(
        c["score"] * c.get("weight", 1) for c in scored_controls
    ) / max(total_weight, 1)

    # Gap analysis — MITRE techniques with no enabled rule
    all_required_mitre = set()
    for c in fw["controls"]:
        all_required_mitre.update(c.get("required_mitre", []))

    coverage_gaps = []
    for technique in sorted(all_required_mitre):
        rules = list(mongo.db.rules.find(
            {"enabled": True, "mitre_technique": technique},
            {"name": 1, "severity": 1}
        ))
        if not rules:
            coverage_gaps.append({
                "technique": technique,
                "status": "no_coverage",
                "recommendation": f"Create a detection rule covering {technique}",
            })
        else:
            coverage_gaps.append({
                "technique": technique,
                "status": "covered",
                "rules": [{"id": str(r["_id"]), "name": r["name"]} for r in rules],
            })

    # Summary stats
    total_events = mongo.db.events.count_documents({"timestamp": {"$gte": period_start}})
    total_incidents = mongo.db.incidents.count_documents({"created_at": {"$gte": period_start}})
    resolved = mongo.db.incidents.count_documents({
        "created_at": {"$gte": period_start},
        "status": {"$in": ["resolved", "false_positive", "closed"]}
    })
    active_agents = mongo.db.agents.count_documents({"status": "active"})
    total_assets = mongo.db.assets.count_documents({})

    # Recommendations (top 3 gaps by weight)
    gaps = [c for c in scored_controls if c["status"] == "gap"]
    gaps.sort(key=lambda x: x.get("weight", 1), reverse=True)
    recommendations = []
    for g in gaps[:3]:
        rec = f"Address gap in {g['id']} ({g['name']}): "
        if g.get("required_categories"):
            rec += f"ensure events from categories {g['required_categories']} are being collected. "
        if g.get("required_mitre"):
            uncovered = [t for t in g["required_mitre"]
                        if not mongo.db.rules.count_documents({"enabled": True, "mitre_technique": t})]
            if uncovered:
                rec += f"Add detection rules for MITRE techniques: {', '.join(uncovered)}."
        recommendations.append(rec)

    audit_log_action(current_user, "compliance_report_generated", "compliance",
                     framework_id, {"days": days})

    return jsonify({
        "framework": fw["name"],
        "framework_id": framework_id,
        "version": fw["version"],
        "period_days": days,
        "period_start": period_start.isoformat(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": current_user["username"],
        "org_name": current_app.config.get("ORG_NAME", "Organization"),
        "overall_score": round(weighted_score, 1),
        "overall_status": "compliant" if weighted_score >= 80
                          else "partial" if weighted_score >= 50
                          else "at_risk",
        "summary": {
            "total_events_monitored": total_events,
            "total_incidents": total_incidents,
            "resolved_incidents": resolved,
            "resolution_rate_pct": round(resolved / total_incidents * 100, 1) if total_incidents else 100,
            "active_agents": active_agents,
            "assets_inventoried": total_assets,
            "compliant_controls": sum(1 for c in scored_controls if c["status"] == "compliant"),
            "partial_controls": sum(1 for c in scored_controls if c["status"] == "partial"),
            "gap_controls": sum(1 for c in scored_controls if c["status"] == "gap"),
            "total_controls": len(scored_controls),
        },
        "controls": scored_controls,
        "mitre_coverage": coverage_gaps,
        "recommendations": recommendations,
    }), 200


@compliance_bp.get("/mitre-coverage")
@require_auth
def mitre_coverage():
    """
    MITRE ATT&CK coverage heatmap data.
    Returns each technique with: has_rule, rule_count, incident_count_30d
    """
    days = int(request.args.get("days", 30))
    period_start = datetime.now(timezone.utc) - timedelta(days=days)

    # All techniques from enabled rules
    pipeline = [
        {"$match": {"enabled": True, "mitre_technique": {"$exists": True, "$ne": []}}},
        {"$unwind": "$mitre_technique"},
        {"$group": {
            "_id": "$mitre_technique",
            "rule_count": {"$sum": 1},
            "rule_names": {"$push": "$name"},
        }},
        {"$sort": {"_id": 1}},
    ]
    covered = {r["_id"]: r for r in mongo.db.rules.aggregate(pipeline)}

    # Incident counts per technique
    inc_pipeline = [
        {"$match": {"created_at": {"$gte": period_start}}},
        {"$unwind": "$mitre_technique"},
        {"$group": {"_id": "$mitre_technique", "count": {"$sum": 1}}},
    ]
    inc_counts = {r["_id"]: r["count"] for r in mongo.db.incidents.aggregate(inc_pipeline)}

    # All techniques required across all frameworks
    all_required = set()
    for fw in FRAMEWORKS.values():
        for c in fw["controls"]:
            all_required.update(c.get("required_mitre", []))

    result = []
    for technique in sorted(all_required | set(covered.keys())):
        cov = covered.get(technique, {})
        result.append({
            "technique": technique,
            "covered": technique in covered,
            "rule_count": cov.get("rule_count", 0),
            "rule_names": cov.get("rule_names", [])[:5],
            "incident_count_30d": inc_counts.get(technique, 0),
            "required_by_frameworks": [
                fw_id for fw_id, fw in FRAMEWORKS.items()
                if any(technique in c.get("required_mitre", []) for c in fw["controls"])
            ],
        })

    uncovered_count = sum(1 for r in result if not r["covered"])
    return jsonify({
        "total_techniques": len(result),
        "covered_techniques": len(result) - uncovered_count,
        "uncovered_techniques": uncovered_count,
        "coverage_pct": round((len(result) - uncovered_count) / max(len(result), 1) * 100, 1),
        "techniques": result,
    }), 200


@compliance_bp.get("/evidence-package/<framework_id>")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.ANALYST)
def evidence_package(framework_id: str):
    """
    Generate a machine-readable evidence package for auditors.
    Contains incident log, event counts, rule inventory, agent roster.
    """
    from flask_jwt_extended import current_user

    if framework_id not in FRAMEWORKS:
        return jsonify({"error": "unknown_framework"}), 404

    days = int(request.args.get("days", 90))
    period_start = datetime.now(timezone.utc) - timedelta(days=days)

    # Incidents in period
    incidents = list(mongo.db.incidents.find(
        {"created_at": {"$gte": period_start}},
        {"analyst_notes": 1, "title": 1, "severity": 1, "status": 1,
         "created_at": 1, "resolved_at": 1, "rule_name": 1, "hostname": 1,
         "mitre_technique": 1, "assigned_to": 1}
    ).sort("created_at", -1).limit(500))
    for i in incidents:
        i["_id"] = str(i["_id"])
        for f in ("created_at", "resolved_at"):
            if isinstance(i.get(f), datetime):
                i[f] = i[f].isoformat()

    # Active rules
    rules = list(mongo.db.rules.find(
        {"enabled": True},
        {"name": 1, "category": 1, "severity": 1, "mitre_technique": 1,
         "mitre_tactic": 1, "hit_count": 1, "last_triggered": 1}
    ))
    for r in rules:
        r["_id"] = str(r["_id"])
        if isinstance(r.get("last_triggered"), datetime):
            r["last_triggered"] = r["last_triggered"].isoformat()

    # Active agents
    agents = list(mongo.db.agents.find(
        {"status": "active"},
        {"hostname": 1, "ip_address": 1, "os_version": 1,
         "last_seen": 1, "events_received": 1, "agent_version": 1}
    ))
    for a in agents:
        a["_id"] = str(a["_id"])
        if isinstance(a.get("last_seen"), datetime):
            a["last_seen"] = a["last_seen"].isoformat()

    # Event volume by category
    ev_by_cat = list(mongo.db.events.aggregate([
        {"$match": {"timestamp": {"$gte": period_start}}},
        {"$group": {"_id": "$category", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]))

    audit_log_action(current_user, "evidence_package_generated", "compliance",
                     framework_id, {"days": days})

    return jsonify({
        "package_type": "compliance_evidence",
        "framework": FRAMEWORKS[framework_id]["name"],
        "framework_id": framework_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": current_user["username"],
        "org_name": current_app.config.get("ORG_NAME", "Organization"),
        "period_days": days,
        "period_start": period_start.isoformat(),
        "evidence": {
            "incident_log": incidents,
            "active_detection_rules": rules,
            "monitored_endpoints": agents,
            "event_volume_by_category": [{"category": r["_id"], "count": r["count"]}
                                          for r in ev_by_cat],
            "total_events_monitored": sum(r["count"] for r in ev_by_cat),
            "total_incidents": len(incidents),
            "total_rules": len(rules),
            "total_agents": len(agents),
        },
    }), 200


# ── IOC management (unchanged, cleaned up) ───────────────────────────────────

@compliance_bp.get("/threat-intel")
@require_auth
def list_threat_intel():
    page = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 50)), 500)
    skip = (page - 1) * per_page
    query = {}
    if request.args.get("ioc_type"):
        query["ioc_type"] = request.args["ioc_type"]
    if request.args.get("search"):
        query["ioc_value"] = {"$regex": request.args["search"], "$options": "i"}

    total = mongo.db.threat_intel.count_documents(query)
    iocs = list(mongo.db.threat_intel.find(query).sort("created_at", -1).skip(skip).limit(per_page))
    for ioc in iocs:
        ioc["_id"] = str(ioc["_id"])
        for f in ("created_at", "expires_at"):
            if isinstance(ioc.get(f), datetime):
                ioc[f] = ioc[f].isoformat()

    stats = {r["_id"]: r["count"] for r in mongo.db.threat_intel.aggregate(
        [{"$group": {"_id": "$ioc_type", "count": {"$sum": 1}}}]
    )}

    return jsonify({
        "data": iocs, "total": total, "stats": stats,
        "pagination": {"page": page, "per_page": per_page,
                       "pages": max(1, -(-total // per_page))}
    }), 200


@compliance_bp.post("/threat-intel")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.ANALYST)
def add_threat_intel():
    from flask_jwt_extended import current_user
    data = request.get_json(silent=True) or {}
    ioc_value = data.get("ioc_value", "").strip()
    ioc_type = data.get("ioc_type", "ip")
    if not ioc_value:
        return jsonify({"error": "ioc_value_required"}), 422
    if ioc_type not in ("ip", "domain", "hash", "url", "email"):
        return jsonify({"error": "invalid_ioc_type"}), 422
    if mongo.db.threat_intel.find_one({"ioc_value": ioc_value}):
        return jsonify({"error": "ioc_already_exists"}), 409

    ttl_days = int(data.get("ttl_days", 365))
    doc = {
        "ioc_value": ioc_value, "ioc_type": ioc_type,
        "threat_type": data.get("threat_type", ""),
        "confidence": min(100, max(0, int(data.get("confidence", 50)))),
        "source": data.get("source", "Manual"),
        "tags": data.get("tags", []),
        "created_by": str(current_user["_id"]),
        "created_at": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(days=ttl_days),
    }
    result = mongo.db.threat_intel.insert_one(doc)
    return jsonify({"message": "IOC added", "id": str(result.inserted_id)}), 201


@compliance_bp.delete("/threat-intel/<ioc_id>")
@require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN)
def delete_threat_intel(ioc_id: str):
    from flask_jwt_extended import current_user
    from bson import ObjectId
    try:
        oid = ObjectId(ioc_id)
    except Exception:
        return jsonify({"error": "invalid_id"}), 400
    result = mongo.db.threat_intel.delete_one({"_id": oid})
    if result.deleted_count == 0:
        return jsonify({"error": "not_found"}), 404
    audit_log_action(current_user, "ioc_deleted", "threat_intel", ioc_id, {})
    return jsonify({"message": "IOC deleted"}), 200

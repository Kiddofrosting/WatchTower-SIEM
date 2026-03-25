#!/usr/bin/env python3
"""
WatchTower SIEM - Database Seeder
Creates the initial super_admin user and seeds built-in detection rules.

Usage:
    python seed_admin.py
    python seed_admin.py --email admin@company.com --password MySecret@123!
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from dotenv import load_dotenv
load_dotenv()

os.environ.setdefault("SECRET_KEY", "seed-secret-not-used-in-runtime")
os.environ.setdefault("JWT_SECRET_KEY", "seed-jwt-not-used-in-runtime")
os.environ.setdefault("MONGO_URI", os.getenv("MONGO_URI", "mongodb://localhost:27017/watchtower_dev"))
os.environ.setdefault("SESSION_COOKIE_SECURE", "false")


def main():
    parser = argparse.ArgumentParser(description="Seed WatchTower SIEM database")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--email", default=os.getenv("SUPER_ADMIN_EMAIL", "admin@watchtower.local"))
    parser.add_argument("--password", default="Admin@WatchTower1!")
    parser.add_argument("--skip-rules", action="store_true", help="Skip seeding built-in rules")
    args = parser.parse_args()

    from watchtower.app import create_app, mongo
    app = create_app("development")

    with app.app_context():
        # ── Create super admin ────────────────────────────────────────────────
        existing = mongo.db.users.find_one({"username": args.username})
        if existing:
            print(f"[!] User '{args.username}' already exists. Skipping user creation.")
        else:
            from watchtower.app.security import hash_password, validate_password_policy
            from watchtower.app.models import new_user, UserRole

            valid, msg = validate_password_policy(args.password)
            if not valid:
                print(f"[ERROR] Password policy violation: {msg}")
                sys.exit(1)

            user_doc = new_user(
                username=args.username,
                email=args.email,
                password_hash=hash_password(args.password),
                role=UserRole.SUPER_ADMIN,
                full_name="System Administrator",
                created_by="seed_script",
            )
            user_doc["is_email_verified"] = True
            result = mongo.db.users.insert_one(user_doc)
            print(f"[+] Created super_admin user: {args.username} ({args.email})")
            print(f"    User ID: {result.inserted_id}")
            print(f"    Password: {args.password}")
            print(f"    IMPORTANT: Change this password after first login!")

        # ── Seed global settings ──────────────────────────────────────────────
        if not mongo.db.settings.find_one({"_id": "global"}):
            mongo.db.settings.insert_one({
                "_id": "global",
                "org_name": os.getenv("ORG_NAME", "WatchTower Organization"),
                "org_contact_email": os.getenv("ORG_CONTACT_EMAIL", args.email),
                "email_alerts_enabled": True,
                "slack_alerts_enabled": False,
                "alert_min_severity": "medium",
                "retention_raw_events_days": 90,
                "retention_incidents_days": 365,
                "retention_audit_log_days": 730,
                "auto_close_fp_days": 7,
            })
            print("[+] Created global settings document")

        # ── Seed built-in detection rules ─────────────────────────────────────
        if not args.skip_rules:
            from watchtower.app.detection.builtin_rules import BUILTIN_RULES
            from watchtower.app.models import new_rule

            seeded = 0
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
                    created_by="seed_script",
                    mitre_technique=rule_def.get("mitre_technique", []),
                    mitre_tactic=rule_def.get("mitre_tactic", []),
                )
                rule_doc["references"] = rule_def.get("references", [])
                rule_doc["tags"] = rule_def.get("tags", [])
                rule_doc["sigma_rule_id"] = rule_def.get("sigma_rule_id")
                mongo.db.rules.insert_one(rule_doc)
                seeded += 1

            print(f"[+] Seeded {seeded} built-in detection rules ({skipped} already existed)")

        print("\n[✓] Database seeding complete!")
        print(f"    Login URL: http://localhost:5000/login")


if __name__ == "__main__":
    main()

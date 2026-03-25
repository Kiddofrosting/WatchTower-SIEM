"""
WatchTower SIEM - Event Normalizer
Parses raw Windows Event Log data into a normalized schema.
Maps Event IDs to categories, severities, and MITRE ATT&CK techniques.
"""

from datetime import datetime, timezone
from dateutil import parser as dateutil_parser

from watchtower.app.models import EventCategory, Severity

# ─────────────────────────────────────────────────────────────────────────────
# Event ID mappings
# ─────────────────────────────────────────────────────────────────────────────

EVENT_ID_MAP = {
    # Authentication
    4624: {"category": EventCategory.AUTHENTICATION, "severity": Severity.INFO,
           "desc": "Successful logon",
           "mitre": ["T1078"], "tactic": ["Initial Access", "Defense Evasion", "Persistence", "Privilege Escalation"]},
    4625: {"category": EventCategory.AUTHENTICATION, "severity": Severity.MEDIUM,
           "desc": "Failed logon",
           "mitre": ["T1110"], "tactic": ["Credential Access"]},
    4634: {"category": EventCategory.AUTHENTICATION, "severity": Severity.INFO,
           "desc": "Account logoff", "mitre": [], "tactic": []},
    4647: {"category": EventCategory.AUTHENTICATION, "severity": Severity.INFO,
           "desc": "User initiated logoff", "mitre": [], "tactic": []},
    4648: {"category": EventCategory.AUTHENTICATION, "severity": Severity.MEDIUM,
           "desc": "Logon with explicit credentials",
           "mitre": ["T1134", "T1078"], "tactic": ["Privilege Escalation", "Defense Evasion"]},
    4672: {"category": EventCategory.PRIVILEGE_ESCALATION, "severity": Severity.MEDIUM,
           "desc": "Special privileges assigned to new logon",
           "mitre": ["T1078.002"], "tactic": ["Privilege Escalation"]},
    4768: {"category": EventCategory.AUTHENTICATION, "severity": Severity.INFO,
           "desc": "Kerberos TGT requested", "mitre": ["T1558"], "tactic": ["Credential Access"]},
    4769: {"category": EventCategory.AUTHENTICATION, "severity": Severity.INFO,
           "desc": "Kerberos service ticket requested",
           "mitre": ["T1558.003"], "tactic": ["Credential Access"]},
    4771: {"category": EventCategory.AUTHENTICATION, "severity": Severity.MEDIUM,
           "desc": "Kerberos pre-authentication failed",
           "mitre": ["T1110"], "tactic": ["Credential Access"]},
    4776: {"category": EventCategory.AUTHENTICATION, "severity": Severity.INFO,
           "desc": "NTLM authentication attempt", "mitre": ["T1550.002"], "tactic": ["Lateral Movement"]},
    4798: {"category": EventCategory.CREDENTIAL_ACCESS, "severity": Severity.MEDIUM,
           "desc": "User local group membership enumerated",
           "mitre": ["T1069.001"], "tactic": ["Discovery"]},
    4799: {"category": EventCategory.CREDENTIAL_ACCESS, "severity": Severity.MEDIUM,
           "desc": "Security-enabled group membership enumerated",
           "mitre": ["T1069.001"], "tactic": ["Discovery"]},

    # Account Management
    4720: {"category": EventCategory.ACCOUNT_MANAGEMENT, "severity": Severity.HIGH,
           "desc": "User account created",
           "mitre": ["T1136.001"], "tactic": ["Persistence"]},
    4722: {"category": EventCategory.ACCOUNT_MANAGEMENT, "severity": Severity.MEDIUM,
           "desc": "User account enabled", "mitre": [], "tactic": []},
    4723: {"category": EventCategory.ACCOUNT_MANAGEMENT, "severity": Severity.MEDIUM,
           "desc": "Password change attempt", "mitre": ["T1098"], "tactic": ["Persistence"]},
    4724: {"category": EventCategory.ACCOUNT_MANAGEMENT, "severity": Severity.HIGH,
           "desc": "Password reset attempt", "mitre": ["T1098"], "tactic": ["Persistence"]},
    4725: {"category": EventCategory.ACCOUNT_MANAGEMENT, "severity": Severity.MEDIUM,
           "desc": "User account disabled", "mitre": [], "tactic": []},
    4726: {"category": EventCategory.ACCOUNT_MANAGEMENT, "severity": Severity.HIGH,
           "desc": "User account deleted",
           "mitre": ["T1531"], "tactic": ["Impact"]},
    4728: {"category": EventCategory.ACCOUNT_MANAGEMENT, "severity": Severity.HIGH,
           "desc": "Member added to global security group",
           "mitre": ["T1098"], "tactic": ["Persistence"]},
    4732: {"category": EventCategory.ACCOUNT_MANAGEMENT, "severity": Severity.HIGH,
           "desc": "Member added to local security group",
           "mitre": ["T1098.001"], "tactic": ["Persistence"]},
    4740: {"category": EventCategory.ACCOUNT_MANAGEMENT, "severity": Severity.HIGH,
           "desc": "User account locked out",
           "mitre": ["T1110"], "tactic": ["Credential Access"]},
    4756: {"category": EventCategory.ACCOUNT_MANAGEMENT, "severity": Severity.HIGH,
           "desc": "Member added to universal security group",
           "mitre": ["T1098"], "tactic": ["Persistence"]},

    # Process Execution
    4688: {"category": EventCategory.PROCESS_EXECUTION, "severity": Severity.INFO,
           "desc": "New process created",
           "mitre": ["T1059"], "tactic": ["Execution"]},
    4689: {"category": EventCategory.PROCESS_EXECUTION, "severity": Severity.INFO,
           "desc": "Process terminated", "mitre": [], "tactic": []},

    # Privilege Use / Escalation
    4673: {"category": EventCategory.PRIVILEGE_ESCALATION, "severity": Severity.MEDIUM,
           "desc": "Privileged service called", "mitre": ["T1548"], "tactic": ["Privilege Escalation"]},
    4674: {"category": EventCategory.PRIVILEGE_ESCALATION, "severity": Severity.MEDIUM,
           "desc": "Operation attempted on privileged object",
           "mitre": ["T1548"], "tactic": ["Privilege Escalation"]},

    # Scheduled Tasks
    4698: {"category": EventCategory.SCHEDULED_TASK, "severity": Severity.HIGH,
           "desc": "Scheduled task created",
           "mitre": ["T1053.005"], "tactic": ["Persistence", "Privilege Escalation", "Execution"]},
    4699: {"category": EventCategory.SCHEDULED_TASK, "severity": Severity.HIGH,
           "desc": "Scheduled task deleted",
           "mitre": ["T1070"], "tactic": ["Defense Evasion"]},
    4700: {"category": EventCategory.SCHEDULED_TASK, "severity": Severity.MEDIUM,
           "desc": "Scheduled task enabled", "mitre": ["T1053.005"], "tactic": ["Persistence"]},
    4701: {"category": EventCategory.SCHEDULED_TASK, "severity": Severity.MEDIUM,
           "desc": "Scheduled task disabled", "mitre": [], "tactic": []},
    4702: {"category": EventCategory.SCHEDULED_TASK, "severity": Severity.HIGH,
           "desc": "Scheduled task updated",
           "mitre": ["T1053.005"], "tactic": ["Persistence"]},

    # Services
    7045: {"category": EventCategory.SERVICE, "severity": Severity.HIGH,
           "desc": "New service installed",
           "mitre": ["T1543.003"], "tactic": ["Persistence", "Privilege Escalation"]},
    7040: {"category": EventCategory.SERVICE, "severity": Severity.MEDIUM,
           "desc": "Service start type changed",
           "mitre": ["T1543.003"], "tactic": ["Persistence"]},

    # Audit Policy
    4719: {"category": EventCategory.DEFENSE_EVASION, "severity": Severity.CRITICAL,
           "desc": "Audit policy changed",
           "mitre": ["T1562.002"], "tactic": ["Defense Evasion"]},
    4739: {"category": EventCategory.DEFENSE_EVASION, "severity": Severity.HIGH,
           "desc": "Domain policy changed", "mitre": ["T1484"], "tactic": ["Defense Evasion"]},

    # Remote Access / Lateral Movement
    4778: {"category": EventCategory.LATERAL_MOVEMENT, "severity": Severity.MEDIUM,
           "desc": "RDP session reconnected",
           "mitre": ["T1021.001"], "tactic": ["Lateral Movement"]},
    4779: {"category": EventCategory.LATERAL_MOVEMENT, "severity": Severity.INFO,
           "desc": "RDP session disconnected", "mitre": [], "tactic": []},

    # PowerShell (Sysmon / PS logging)
    4103: {"category": EventCategory.POWERSHELL, "severity": Severity.MEDIUM,
           "desc": "PowerShell pipeline execution",
           "mitre": ["T1059.001"], "tactic": ["Execution"]},
    4104: {"category": EventCategory.POWERSHELL, "severity": Severity.HIGH,
           "desc": "PowerShell script block logging",
           "mitre": ["T1059.001"], "tactic": ["Execution"]},

    # Sysmon events
    1:   {"category": EventCategory.PROCESS_EXECUTION, "severity": Severity.INFO,
           "desc": "Sysmon: Process creation",
           "mitre": ["T1059"], "tactic": ["Execution"]},
    3:   {"category": EventCategory.NETWORK, "severity": Severity.INFO,
           "desc": "Sysmon: Network connection",
           "mitre": ["T1071"], "tactic": ["Command and Control"]},
    7:   {"category": EventCategory.PROCESS_EXECUTION, "severity": Severity.MEDIUM,
           "desc": "Sysmon: Image loaded", "mitre": ["T1129"], "tactic": ["Execution"]},
    8:   {"category": EventCategory.DEFENSE_EVASION, "severity": Severity.HIGH,
           "desc": "Sysmon: CreateRemoteThread",
           "mitre": ["T1055"], "tactic": ["Defense Evasion", "Privilege Escalation"]},
    10:  {"category": EventCategory.CREDENTIAL_ACCESS, "severity": Severity.HIGH,
           "desc": "Sysmon: ProcessAccess (possible credential dumping)",
           "mitre": ["T1003"], "tactic": ["Credential Access"]},
    11:  {"category": EventCategory.FILE_SYSTEM, "severity": Severity.INFO,
           "desc": "Sysmon: FileCreate", "mitre": [], "tactic": []},
    12:  {"category": EventCategory.REGISTRY, "severity": Severity.INFO,
           "desc": "Sysmon: RegistryEvent (Object created/deleted)",
           "mitre": ["T1112"], "tactic": ["Defense Evasion"]},
    13:  {"category": EventCategory.REGISTRY, "severity": Severity.MEDIUM,
           "desc": "Sysmon: RegistryEvent (Value set)",
           "mitre": ["T1112"], "tactic": ["Defense Evasion"]},
    22:  {"category": EventCategory.NETWORK, "severity": Severity.INFO,
           "desc": "Sysmon: DNS query", "mitre": ["T1071.004"], "tactic": ["Command and Control"]},
    25:  {"category": EventCategory.DEFENSE_EVASION, "severity": Severity.HIGH,
           "desc": "Sysmon: ProcessTampering",
           "mitre": ["T1055"], "tactic": ["Defense Evasion"]},
}

# Logon type descriptions
LOGON_TYPES = {
    2: "Interactive", 3: "Network", 4: "Batch", 5: "Service",
    7: "Unlock", 8: "NetworkCleartext", 9: "NewCredentials",
    10: "RemoteInteractive", 11: "CachedInteractive", 12: "CachedRemoteInteractive",
}

SUSPICIOUS_PROCESSES = {
    "mimikatz.exe", "meterpreter", "cobalt", "metasploit",
    "powersploit", "empire", "sharphound", "bloodhound",
    "psexec.exe", "wce.exe", "fgdump.exe", "gsecdump.exe",
    "lsass", "procdump.exe",
}

SUSPICIOUS_CMDLINE_PATTERNS = [
    "invoke-mimikatz", "invoke-expression", "-encodedcommand",
    "downloadstring", "downloadfile", "-nop ", "-w hidden",
    "-noninteractive", "frombase64string", "iex(", "bypass",
    "net user /add", "net localgroup administrators /add",
    "vssadmin delete shadows", "wmic shadowcopy delete",
    "bcdedit /set {default} recoveryenabled no",
    "reg add.*run", "schtasks /create",
]


def normalize_event(raw: dict, hostname: str) -> dict:
    """Convert raw Windows Event Log dict to normalized WatchTower schema."""
    event_id = int(raw.get("event_id", 0))
    data = raw.get("data", {})
    channel = raw.get("channel", "")
    provider = raw.get("provider", "")

    # Timestamp parsing
    ts_raw = raw.get("timestamp", "")
    try:
        ts = dateutil_parser.parse(ts_raw)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
    except Exception:
        ts = datetime.now(timezone.utc)

    # Lookup event info
    ev_info = EVENT_ID_MAP.get(event_id, {
        "category": EventCategory.OTHER,
        "severity": Severity.INFO,
        "desc": f"Windows Event {event_id}",
        "mitre": [],
        "tactic": [],
    })

    # Extract common fields
    subject_username = (data.get("SubjectUserName") or data.get("SubjectAccount", "")).strip()
    target_username = (data.get("TargetUserName") or data.get("TargetAccount", "")).strip()
    logon_type_raw = data.get("LogonType")
    logon_type = LOGON_TYPES.get(int(logon_type_raw), str(logon_type_raw)) if logon_type_raw else None

    process_name = (
        data.get("NewProcessName") or
        data.get("ProcessName") or
        data.get("Image") or ""
    ).strip()
    process_id = data.get("NewProcessId") or data.get("ProcessId")
    parent_process = (
        data.get("ParentProcessName") or
        data.get("ParentImage") or ""
    ).strip()
    command_line = (
        data.get("CommandLine") or
        data.get("ProcessCommandLine") or ""
    ).strip()

    source_ip = (
        data.get("IpAddress") or
        data.get("SourceIp") or
        data.get("SourceAddress") or ""
    ).strip().replace("::ffff:", "")
    dest_ip = (
        data.get("DestinationIp") or
        data.get("DestAddress") or ""
    ).strip()
    dest_port = data.get("DestinationPort") or data.get("DestPort")

    file_path = (data.get("TargetFilename") or data.get("ObjectName") or "").strip()
    registry_key = (data.get("TargetObject") or "").strip()
    service_name = (data.get("ServiceName") or "").strip()
    task_name = (data.get("TaskName") or "").strip()

    # Compute severity adjustments
    severity = ev_info["severity"]
    tags = []

    # Elevate severity on suspicious process names
    proc_lower = process_name.lower()
    if any(s in proc_lower for s in SUSPICIOUS_PROCESSES):
        severity = Severity.CRITICAL
        tags.append("suspicious_process")

    # Elevate on suspicious command line
    cmd_lower = command_line.lower()
    if any(p in cmd_lower for p in SUSPICIOUS_CMDLINE_PATTERNS):
        severity = Severity.CRITICAL
        tags.append("suspicious_cmdline")

    # Nullify machine accounts (end with $) from username fields
    if subject_username.endswith("$"):
        subject_username = subject_username  # keep but tag
        tags.append("machine_account")

    # Build message
    message = raw.get("message") or ev_info["desc"]

    return {
        "event_id": event_id,
        "channel": channel,
        "provider": provider,
        "category": ev_info["category"],
        "severity": severity,
        "timestamp": ts,
        "subject_username": subject_username,
        "target_username": target_username,
        "logon_type": logon_type,
        "process_name": process_name,
        "process_id": process_id,
        "parent_process": parent_process,
        "command_line": command_line[:2048],
        "source_ip": source_ip,
        "destination_ip": dest_ip,
        "destination_port": dest_port,
        "file_path": file_path,
        "registry_key": registry_key,
        "service_name": service_name,
        "task_name": task_name,
        "mitre_technique": ev_info["mitre"],
        "mitre_tactic": ev_info["tactic"],
        "tags": tags,
        "message": message[:1024],
        "hash_md5": data.get("Hashes", "").split("MD5=")[-1].split(",")[0] if "MD5=" in data.get("Hashes", "") else "",
        "hash_sha256": data.get("Hashes", "").split("SHA256=")[-1].split(",")[0] if "SHA256=" in data.get("Hashes", "") else "",
        "signed": data.get("Signed"),
        "signature_valid": data.get("SignatureStatus") == "Valid" if data.get("SignatureStatus") else None,
    }

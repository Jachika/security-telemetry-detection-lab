from __future__ import annotations
import ipaddress

RULES = [
    {
        "id": "DET-001",
        "name": "Encoded PowerShell",
        "attack": "T1059.001",
        "event_type": "process_create",
    },
    {
        "id": "DET-002",
        "name": "Suspicious LSASS Process Access",
        "attack": "T1003.001",
        "event_type": "process_access",
    },
    {
        "id": "DET-003",
        "name": "Remote Interactive Logon",
        "attack": "T1021.001",
        "event_type": "authentication",
    },
    {
        "id": "DET-004",
        "name": "Unusual Outbound Admin Tool Connection",
        "attack": "T1041",
        "event_type": "network_connect",
    },
]

TRUSTED_REMOTE_USERS = {"admin", "svc_backup"}
KNOWN_PUBLIC_IPS = {"20.42.1.20", "52.96.10.15", "13.107.42.14", "8.8.8.8", "1.1.1.1"}

def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def detect(event: dict, tuned: bool = False):
    alerts = []
    et = event["event_type"]

    if et == "process_create":
        cmd = event["command_line"].lower()
        # Baseline intentionally noisy: any PowerShell with "encoded" token.
        hit = event["process_name"] == "powershell.exe" and "encoded" in cmd
        if tuned:
            hit = hit and event["parent_process"] in {"winword.exe", "excel.exe", "outlook.exe"}
        if hit:
            alerts.append(_alert(event, RULES[0]))

    if et == "process_access":
        hit = event["target_process"] == "lsass.exe"
        if tuned:
            hit = hit and event["process_name"] != "msmpeng.exe"
        if hit:
            alerts.append(_alert(event, RULES[1]))

    if et == "authentication":
        hit = event["logon_type"] == 10
        if tuned:
            hit = hit and event["user"] not in TRUSTED_REMOTE_USERS
        if hit:
            alerts.append(_alert(event, RULES[2]))

    if et == "network_connect":
        hit = event["dst_port"] not in {53, 80, 123, 443}
        if tuned:
            hit = hit and event["process_name"] in {"powershell.exe", "rundll32.exe"} and event["dst_ip"] not in KNOWN_PUBLIC_IPS
        if hit:
            alerts.append(_alert(event, RULES[3]))

    return alerts

def _alert(event: dict, rule: dict):
    return {
        "event_id": event["event_id"],
        "ts": event["ts"],
        "host": event["host"],
        "user": event["user"],
        "rule_id": rule["id"],
        "rule_name": rule["name"],
        "mitre_attack": rule["attack"],
        "scenario": event.get("scenario", "unknown"),
    }

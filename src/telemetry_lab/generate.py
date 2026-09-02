from __future__ import annotations
import random
import uuid
from datetime import datetime, timedelta, timezone
from .schema import Event

BENIGN_PROCS = [
    ("explorer.exe", "winlogon.exe"),
    ("chrome.exe", "explorer.exe"),
    ("msedge.exe", "explorer.exe"),
    ("teams.exe", "explorer.exe"),
    ("outlook.exe", "explorer.exe"),
    ("python.exe", "code.exe"),
    ("powershell.exe", "explorer.exe"),
]
USERS = ["alice", "bob", "carol", "dave", "svc_backup", "admin"]
HOSTS = [f"ws-{i:03d}" for i in range(1, 81)]
PUBLIC_IPS = ["20.42.1.20", "52.96.10.15", "13.107.42.14", "8.8.8.8", "1.1.1.1"]

def _ts(i: int) -> str:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return (start + timedelta(seconds=i * 3)).isoformat()

def generate_events(n: int = 120_000, seed: int = 42):
    rng = random.Random(seed)
    for i in range(n):
        r = rng.random()
        host = rng.choice(HOSTS)
        user = rng.choice(USERS)

        # Roughly 1% simulated malicious records.
        attack = rng.random() < 0.01
        scenario = "benign"

        if r < 0.45:
            proc, parent = rng.choice(BENIGN_PROCS)
            cmd = proc
            if proc == "powershell.exe":
                cmd = "powershell.exe -NoProfile Get-Process"

            if attack:
                proc = "powershell.exe"
                parent = "winword.exe"
                cmd = "powershell.exe -NoProfile -EncodedCommand <synthetic>"
                scenario = "encoded_powershell"

            yield Event(
                event_id=str(uuid.uuid4()),
                ts=_ts(i), host=host, event_type="process_create", user=user,
                process_name=proc, parent_process=parent, command_line=cmd,
                is_attack=attack, scenario=scenario
            )
        elif r < 0.70:
            logon_type = rng.choice([2, 3, 7, 10])
            src = f"10.0.{rng.randint(0, 10)}.{rng.randint(1, 254)}"
            if attack:
                logon_type = 10
                src = f"198.51.100.{rng.randint(1, 254)}"
                user = rng.choice(["alice", "bob", "carol", "dave"])
                scenario = "remote_interactive_logon"
            yield Event(
                event_id=str(uuid.uuid4()),
                ts=_ts(i), host=host, event_type="authentication", user=user,
                src_ip=src, logon_type=logon_type,
                is_attack=attack, scenario=scenario
            )
        elif r < 0.93:
            proc = rng.choice(["chrome.exe", "msedge.exe", "teams.exe", "svchost.exe", "python.exe"])
            dst = rng.choice(PUBLIC_IPS)
            port = rng.choice([53, 80, 443, 123])
            if attack:
                proc = rng.choice(["powershell.exe", "rundll32.exe"])
                dst = f"203.0.113.{rng.randint(1, 254)}"
                port = rng.choice([4444, 8081, 9001])
                scenario = "unusual_outbound"
            yield Event(
                event_id=str(uuid.uuid4()),
                ts=_ts(i), host=host, event_type="network_connect", user=user,
                process_name=proc, dst_ip=dst, dst_port=port,
                is_attack=attack, scenario=scenario
            )
        else:
            proc = rng.choice(["taskmgr.exe", "procexp64.exe", "MsMpEng.exe"])
            target = rng.choice(["explorer.exe", "lsass.exe", "svchost.exe"])
            access = rng.choice(["0x1000", "0x1410", "0x0010"])
            if attack:
                proc = rng.choice(["rundll32.exe", "unknown.exe"])
                target = "lsass.exe"
                access = "0x1fffff"
                scenario = "lsass_access"
            yield Event(
                event_id=str(uuid.uuid4()),
                ts=_ts(i), host=host, event_type="process_access", user=user,
                process_name=proc, target_process=target, granted_access=access,
                is_attack=attack, scenario=scenario
            )

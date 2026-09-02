from __future__ import annotations

def normalize_event(event: dict) -> dict:
    """Normalize a raw event into a stable schema used by the detector."""
    def low(x):
        return str(x or "").strip().lower()

    out = {
        "event_id": str(event.get("event_id", "")),
        "ts": str(event.get("ts", "")),
        "host": low(event.get("host")),
        "event_type": low(event.get("event_type")),
        "user": low(event.get("user")),
        "process_name": low(event.get("process_name")),
        "parent_process": low(event.get("parent_process")),
        "command_line": str(event.get("command_line", "")),
        "src_ip": str(event.get("src_ip", "")),
        "dst_ip": str(event.get("dst_ip", "")),
        "dst_port": int(event.get("dst_port", 0) or 0),
        "logon_type": int(event.get("logon_type", 0) or 0),
        "target_process": low(event.get("target_process")),
        "granted_access": low(event.get("granted_access")),
        # Kept for offline benchmark ground truth; detector ignores it.
        "is_attack": bool(event.get("is_attack", False)),
        "scenario": str(event.get("scenario", "unknown")),
    }
    return out

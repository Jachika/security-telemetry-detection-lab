from dataclasses import dataclass, asdict
from typing import Optional

@dataclass
class Event:
    event_id: str
    ts: str
    host: str
    event_type: str
    user: str
    process_name: str = ""
    parent_process: str = ""
    command_line: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    logon_type: int = 0
    target_process: str = ""
    granted_access: str = ""
    is_attack: bool = False
    scenario: str = "benign"

    def to_dict(self):
        return asdict(self)

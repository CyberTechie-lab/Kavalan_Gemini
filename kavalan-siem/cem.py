"""
cem.py - Common Event Model (CEM) definition and validation.

The CEM contract is FROZEN for Kavalan SIEM Phase 1:
{
  "ts": 1760930000,            // epoch seconds, UTC (integer)
  "host": "web-01",            // monitored machine id (string)
  "source_ip": "203.0.113.5",  // actor address (string)
  "log_type": "web",           // "web" | "auth" | "dns" | "firewall" | "db"
  "action": "GET /admin",      // what happened (string)
  "target": "/admin",          // what it hit (string)
  "outcome": "fail",           // "ok" | "fail" | "denied" | "error"
  "status": 404,               // optional integer (HTTP code, etc.)
  "user": "root",              // optional string
  "raw": "...original line...",// optional string
  "meta": {}                   // optional object, source-specific
}
"""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional, Set

VALID_OUTCOMES: Set[str] = {"ok", "fail", "denied", "error"}
VALID_LOG_TYPES: Set[str] = {"web", "auth", "dns", "firewall", "db", "fim", "syscheck", "syscollector", "inventory"}
REQUIRED_FIELDS = {"ts", "host", "source_ip", "log_type", "action", "target", "outcome"}


@dataclass
class CEMEvent:
    ts: int
    host: str
    source_ip: str
    log_type: str
    action: str
    target: str
    outcome: str
    status: Optional[int] = None
    user: Optional[str] = None
    raw: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ts": self.ts,
            "host": self.host,
            "source_ip": self.source_ip,
            "log_type": self.log_type,
            "action": self.action,
            "target": self.target,
            "outcome": self.outcome,
            "status": self.status,
            "user": self.user,
            "raw": self.raw,
            "meta": self.meta,
        }


def validate_event(data: Any) -> CEMEvent:
    """
    Validates a dictionary against the frozen Common Event Model (CEM) contract.
    Returns a validated CEMEvent dataclass instance or raises ValueError.
    """
    if not isinstance(data, dict):
        raise ValueError(f"Event must be a dict, got {type(data).__name__}")

    missing = REQUIRED_FIELDS - set(data.keys())
    if missing:
        raise ValueError(f"Missing required CEM fields: {sorted(missing)}")

    ts = data.get("ts")
    if not isinstance(ts, int) or isinstance(ts, bool):
        raise ValueError(f"'ts' must be an integer (epoch seconds), got {type(ts).__name__}")

    host = data.get("host")
    if not isinstance(host, str) or not host.strip():
        raise ValueError("'host' must be a non-empty string")

    source_ip = data.get("source_ip")
    if not isinstance(source_ip, str) or not source_ip.strip():
        raise ValueError("'source_ip' must be a non-empty string")

    log_type = data.get("log_type")
    if not isinstance(log_type, str) or not log_type.strip():
        raise ValueError("'log_type' must be a non-empty string")

    action = data.get("action")
    if not isinstance(action, str) or not action.strip():
        raise ValueError("'action' must be a non-empty string")

    target = data.get("target")
    if not isinstance(target, str):
        raise ValueError(f"'target' must be a string, got {type(target).__name__}")

    outcome = data.get("outcome")
    if outcome not in VALID_OUTCOMES:
        raise ValueError(f"'outcome' must be one of {sorted(VALID_OUTCOMES)}, got {outcome!r}")

    status = data.get("status")
    if status is not None and (not isinstance(status, int) or isinstance(status, bool)):
        raise ValueError(f"'status' must be an integer or None, got {type(status).__name__}")

    user = data.get("user")
    if user is not None and not isinstance(user, str):
        raise ValueError(f"'user' must be a string or None, got {type(user).__name__}")

    raw = data.get("raw")
    if raw is not None and not isinstance(raw, str):
        raise ValueError(f"'raw' must be a string or None, got {type(raw).__name__}")

    meta = data.get("meta")
    if meta is not None and not isinstance(meta, dict):
        raise ValueError(f"'meta' must be a dict or None, got {type(meta).__name__}")

    return CEMEvent(
        ts=ts,
        host=host.strip(),
        source_ip=source_ip.strip(),
        log_type=log_type.strip(),
        action=action,
        target=target,
        outcome=outcome,
        status=status,
        user=user,
        raw=raw,
        meta=meta if meta is not None else {},
    )

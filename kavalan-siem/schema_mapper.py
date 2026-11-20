"""
schema_mapper.py - Bidirectional OCSF & ECS Schema Normalization for Kavalan SIEM

Maps Kavalan Common Event Model (CEM) documents to:
  1. OCSF (Open Cybersecurity Schema Framework v1.1.0)
  2. ECS (Elastic Common Schema v8.x)

Enables Sigma rules, external SIEM analytics, and threat sharing without proprietary translation.
"""

from datetime import datetime, timezone
from typing import Any, Dict
from cem import CEMEvent


def _normalize_event(ev: Any) -> CEMEvent:
    if isinstance(ev, CEMEvent):
        return ev
    if isinstance(ev, dict):
        return CEMEvent(
            ts=int(ev.get("ts") or ev.get("timestamp") or time.time()),
            host=str(ev.get("host") or "unknown"),
            source_ip=str(ev.get("source_ip") or "127.0.0.1"),
            log_type=str(ev.get("log_type") or "system"),
            action=str(ev.get("action") or ""),
            target=str(ev.get("target") or ""),
            outcome=str(ev.get("outcome") or "unknown"),
            status=ev.get("status") or 0,
            user=ev.get("user"),
            raw=str(ev.get("raw") or ""),
            meta=ev.get("meta") if isinstance(ev.get("meta"), dict) else {}
        )
    raise TypeError(f"Expected CEMEvent or dict, got {type(ev)}")


def cem_to_ocsf(event: Any) -> Dict[str, Any]:
    """
    Transforms a CEMEvent into standard OCSF v1.1.0 JSON format.
    Categories:
      1: System Activity
      3: Identity & Access Management (Authentication 3001, Account Change 3002)
      4: Network Activity (Network 4001, HTTP 4002, DNS 4003)
      6: Application Activity (API 6003)
    """
    event = _normalize_event(event)
    dt = datetime.fromtimestamp(event.ts, tz=timezone.utc).isoformat()
    log_type = event.log_type.lower()
    
    # Class & Category mapping
    if log_type in ("auth", "ssh", "winlogon"):
        cat_uid = 3
        class_uid = 3001
        class_name = "Authentication"
    elif log_type == "web":
        cat_uid = 4
        class_uid = 4002
        class_name = "HTTP Activity"
    elif log_type == "dns":
        cat_uid = 4
        class_uid = 4003
        class_name = "DNS Activity"
    elif log_type in ("cloud", "k8s"):
        cat_uid = 6
        class_uid = 6003
        class_name = "API Activity"
    else:
        cat_uid = 4
        class_uid = 4001
        class_name = "Network Activity"

    status_id = 1 if event.outcome == "ok" else 2  # 1: Success, 2: Failure

    ocsf_doc: Dict[str, Any] = {
        "metadata": {
            "version": "1.1.0",
            "product": {
                "name": "Kavalan Autonomous SIEM",
                "vendor_name": "Kavalan Security",
                "version": "2.0.0"
            }
        },
        "time": event.ts * 1000,
        "time_dt": dt,
        "category_uid": cat_uid,
        "class_uid": class_uid,
        "class_name": class_name,
        "activity_name": event.action,
        "status_id": status_id,
        "status": event.outcome.upper(),
        "severity_id": 1 if event.outcome == "ok" else (3 if event.status and event.status >= 500 else 2),
        "src_endpoint": {
            "ip": event.source_ip,
            "hostname": event.host
        },
        "device": {
            "hostname": event.host
        },
        "raw_data": event.raw or ""
    }

    if event.user:
        ocsf_doc["actor"] = {"user": {"name": event.user}}

    if log_type == "web":
        method = event.meta.get("method") or event.action.split()[0] if event.action else "GET"
        ocsf_doc["http_request"] = {
            "http_method": method,
            "url": {"path": event.target}
        }
        if event.status:
            ocsf_doc["http_response"] = {"code": event.status}

    if log_type == "dns":
        ocsf_doc["dns_query"] = {
            "hostname": event.target,
            "type": event.meta.get("qtype", "A"),
            "rcode": event.meta.get("rcode", "NOERROR")
        }

    return ocsf_doc


def cem_to_ecs(event: Any) -> Dict[str, Any]:
    """
    Transforms a CEMEvent into Elastic Common Schema (ECS v8.x) format.
    """
    event = _normalize_event(event)
    dt = datetime.fromtimestamp(event.ts, tz=timezone.utc).isoformat()
    log_type = event.log_type.lower()

    if log_type in ("auth", "ssh"):
        category = ["authentication"]
    elif log_type == "web":
        category = ["web", "network"]
    elif log_type == "dns":
        category = ["network", "dns"]
    else:
        category = ["network"]

    ecs_doc: Dict[str, Any] = {
        "ecs": {
            "version": "8.11.0"
        },
        "@timestamp": dt,
        "event": {
            "kind": "event",
            "category": category,
            "type": ["access"] if event.outcome == "ok" else ["denied"],
            "action": event.action,
            "outcome": "success" if event.outcome == "ok" else "failure",
            "dataset": f"kavalan.{log_type}"
        },
        "host": {
            "name": event.host,
            "hostname": event.host
        },
        "source": {
            "ip": event.source_ip,
            "address": event.source_ip
        },
        "message": event.raw or f"{event.action} on {event.target} ({event.outcome})"
    }

    if event.user:
        ecs_doc["user"] = {"name": event.user}

    if log_type == "web":
        ecs_doc["url"] = {"path": event.target}
        if event.status:
            ecs_doc["http"] = {
                "response": {"status_code": event.status}
            }

    if log_type == "dns":
        ecs_doc["dns"] = {
            "question": {
                "name": event.target,
                "type": event.meta.get("qtype", "A")
            },
            "response_code": event.meta.get("rcode", "NOERROR")
        }

    return ecs_doc

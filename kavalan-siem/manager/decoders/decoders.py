"""
decoders.py - Hierarchical Log Decoders for Kavalan SIEM

Extracts raw log strings into structured Common Event Model (CEM) documents.
Supports:
  1. Web Access Logs (Nginx / Apache Combined)
  2. SSH Auth Logs (RFC3164 BSD & RFC5424 ISO-8601 Syslog)
  3. Generic Syslog (sudo, pam, kernel, cron, systemd)
  4. JSON Logs (Suricata EVE, auditd, docker, cloud logs)
  5. File Integrity Monitoring (FIM) Events
  6. System Inventory (Syscollector) Events
"""

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure parent and ml paths are available
CURRENT_DIR = Path(__file__).resolve().parent
SIEM_ROOT = CURRENT_DIR.parent.parent
KAVALAN_ML_DIR = SIEM_ROOT.parent / "kavalan-ml"
for p in (str(SIEM_ROOT), str(KAVALAN_ML_DIR)):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

import detector
import kavalan_multi
from cem import CEMEvent


class BaseDecoder:
    name: str = "base"

    def match(self, raw_line: str) -> bool:
        raise NotImplementedError

    def decode(self, raw_line: str, host: str = "unknown", year: Optional[int] = None) -> Optional[CEMEvent]:
        raise NotImplementedError


class WebAccessDecoder(BaseDecoder):
    """Decodes standard Nginx/Apache combined access logs."""
    name = "web_access_combined"

    def match(self, raw_line: str) -> bool:
        return bool(detector.LOG_RE.match(raw_line))

    def decode(self, raw_line: str, host: str = "unknown", year: Optional[int] = None) -> Optional[CEMEvent]:
        m = detector.LOG_RE.match(raw_line)
        if not m:
            return None

        try:
            dt = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
            ts = int(dt.timestamp())
        except Exception:
            return None

        ip = m["ip"]
        method = m["method"]
        path = m["path"]
        status_code = int(m["status"])
        ua = m["ua"] or ""

        action = f"{method} {path}"
        target = path.split("?", 1)[0]

        if status_code < 400:
            outcome = "ok"
        elif status_code in (401, 403):
            outcome = "denied"
        elif 400 <= status_code < 500:
            outcome = "fail"
        else:
            outcome = "error"

        meta = {
            "method": method,
            "path": path,
            "ua": ua,
            "decoder": self.name,
        }

        return CEMEvent(
            ts=ts,
            host=host,
            source_ip=ip,
            log_type="web",
            action=action,
            target=target,
            outcome=outcome,
            status=status_code,
            user=None,
            raw=raw_line.rstrip("\r\n"),
            meta=meta,
        )


class SshdAuthDecoder(BaseDecoder):
    """Decodes Linux sshd syslog lines (failed, invalid user, accepted)."""
    name = "sshd_syslog"

    def match(self, raw_line: str) -> bool:
        return bool(kavalan_multi.AUTH_RE.match(raw_line))

    def decode(self, raw_line: str, host: str = "unknown", year: Optional[int] = None) -> Optional[CEMEvent]:
        m = kavalan_multi.AUTH_RE.match(raw_line)
        if not m:
            return None

        msg = m["msg"]
        fm = kavalan_multi.FAIL_RE.search(msg) or kavalan_multi.INVALID_RE.search(msg)
        om = kavalan_multi.OK_RE.search(msg)

        if fm:
            hit, outcome, status_code = fm, "fail", 1
        elif om:
            hit, outcome, status_code = om, "ok", 0
        else:
            return None

        actual_year = year or datetime.now(timezone.utc).year
        try:
            dt = datetime.strptime(f"{actual_year} {m['ts']}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
            ts = int(dt.timestamp())
        except Exception:
            return None

        ip = hit["ip"]
        user = hit["user"]
        action = f"ssh_{outcome}"
        target = "sshd"
        meta = {"service": "sshd", "decoder": self.name}

        return CEMEvent(
            ts=ts,
            host=host,
            source_ip=ip,
            log_type="auth",
            action=action,
            target=target,
            outcome=outcome,
            status=status_code,
            user=user,
            raw=raw_line.rstrip("\r\n"),
            meta=meta,
        )


class SyslogGenericDecoder(BaseDecoder):
    """Decodes standard Linux RFC3164 and RFC5424 syslog messages (e.g., sudo, pam, kernel)."""
    name = "syslog_generic"

    RFC3164_RE = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<daemon>[a-zA-Z0-9_\-\.]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$")
    RFC5424_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:\d{2}))\s+(?P<host>\S+)\s+(?P<daemon>[a-zA-Z0-9_\-\.]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$")

    def match(self, raw_line: str) -> bool:
        return bool(self.RFC3164_RE.match(raw_line) or self.RFC5424_RE.match(raw_line))

    def decode(self, raw_line: str, host: str = "unknown", year: Optional[int] = None) -> Optional[CEMEvent]:
        m = self.RFC5424_RE.match(raw_line)
        actual_year = year or datetime.now(timezone.utc).year
        if m:
            ts_str = m.group("ts")
            try:
                # ISO-8601 parsing
                ts_clean = re.sub(r"([+\-]\d{2}):(\d{2})$", r"\1\2", ts_str)
                dt = datetime.fromisoformat(ts_clean)
                ts = int(dt.timestamp())
            except Exception:
                ts = int(time.time())
        else:
            m = self.RFC3164_RE.match(raw_line)
            if not m:
                return None
            try:
                dt = datetime.strptime(f"{actual_year} {m.group('ts')}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
                ts = int(dt.timestamp())
            except Exception:
                ts = int(time.time())

        daemon = m.group("daemon")
        msg = m.group("msg")
        pid = m.group("pid")
        log_host = m.group("host") or host

        # Extract user or IP from message if present
        user_match = re.search(r"\buser[ =]([a-zA-Z0-9_\-]+)", msg, re.I)
        user = user_match.group(1) if user_match else None

        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", msg)
        ip = ip_match.group(0) if ip_match else "127.0.0.1"

        outcome = "ok"
        if any(term in msg.lower() for term in ("fail", "error", "denied", "invalid", "unauthorized")):
            outcome = "fail"

        return CEMEvent(
            ts=ts,
            host=log_host,
            source_ip=ip,
            log_type="auth" if daemon in ("sudo", "su", "pam", "login") else "system",
            action=f"{daemon}_event",
            target=daemon,
            outcome=outcome,
            status=1 if outcome == "fail" else 0,
            user=user,
            raw=raw_line.rstrip("\r\n"),
            meta={"daemon": daemon, "pid": pid, "decoder": self.name},
        )


class JsonLogDecoder(BaseDecoder):
    """Decodes generic structured JSON log formats (e.g. Suricata EVE, auditd, docker)."""
    name = "json_decoder"

    def match(self, raw_line: str) -> bool:
        s = raw_line.strip()
        return s.startswith("{") and s.endswith("}")

    def decode(self, raw_line: str, host: str = "unknown", year: Optional[int] = None) -> Optional[CEMEvent]:
        try:
            d = json.loads(raw_line.strip())
            if not isinstance(d, dict):
                return None
        except Exception:
            return None

        # Determine timestamp
        ts = int(time.time())
        for k in ("ts", "timestamp", "@timestamp", "time"):
            if k in d:
                val = d[k]
                if isinstance(val, (int, float)):
                    ts = int(val)
                elif isinstance(val, str):
                    try:
                        ts = int(datetime.fromisoformat(val.replace("Z", "+00:00")).timestamp())
                    except Exception:
                        pass
                break

        src_ip = d.get("source_ip") or d.get("src_ip") or d.get("srcip") or d.get("ip") or "127.0.0.1"
        log_type = d.get("log_type") or d.get("event_type") or "json"
        action = d.get("action") or d.get("event") or "json_event"
        target = d.get("target") or d.get("dest") or d.get("url") or "unknown"
        outcome = d.get("outcome") or ("fail" if d.get("status_code", 0) >= 400 else "ok")

        return CEMEvent(
            ts=ts,
            host=d.get("host", host),
            source_ip=str(src_ip),
            log_type=str(log_type),
            action=str(action),
            target=str(target),
            outcome=str(outcome) if str(outcome) in ("ok", "fail", "denied", "error") else "ok",
            status=d.get("status") or d.get("status_code"),
            user=d.get("user") or d.get("username"),
            raw=raw_line.rstrip("\r\n"),
            meta={"json_data": d, "decoder": self.name},
        )


class FimDecoder(BaseDecoder):
    """Decodes Agent File Integrity Monitoring (FIM) event lines."""
    name = "fim_decoder"

    FIM_RE = re.compile(r"^FIM:\s+File\s+(?P<action>created|modified|deleted):\s+(?P<path>\S+)(?:\s+\((?P<extra>.*)\))?")

    def match(self, raw_line: str) -> bool:
        return bool(self.FIM_RE.match(raw_line.strip()))

    def decode(self, raw_line: str, host: str = "unknown", year: Optional[int] = None) -> Optional[CEMEvent]:
        m = self.FIM_RE.match(raw_line.strip())
        if not m:
            return None

        action_word = m.group("action")
        path = m.group("path")
        extra = m.group("extra") or ""

        return CEMEvent(
            ts=int(time.time()),
            host=host,
            source_ip="127.0.0.1",
            log_type="fim",
            action=f"file_{action_word}",
            target=path,
            outcome="ok",
            status=0,
            user="system",
            raw=raw_line.rstrip("\r\n"),
            meta={"path": path, "change_type": action_word, "extra": extra, "decoder": self.name},
        )


class SyscollectorDecoder(BaseDecoder):
    """Decodes Agent Syscollector port & package inventory change lines."""
    name = "syscollector_decoder"

    SYSCOL_RE = re.compile(r"^Syscollector:\s+(?:New listening port opened|Listening port closed):\s+(?P<proto>tcp|udp)/(?P<port>\d+)(?:\s+on\s+(?P<addr>\S+))?")

    def match(self, raw_line: str) -> bool:
        return bool(self.SYSCOL_RE.match(raw_line.strip()))

    def decode(self, raw_line: str, host: str = "unknown", year: Optional[int] = None) -> Optional[CEMEvent]:
        m = self.SYSCOL_RE.match(raw_line.strip())
        if not m:
            return None

        proto = m.group("proto")
        port = int(m.group("port"))
        addr = m.group("addr") or "0.0.0.0"
        action = "port_opened" if "opened" in raw_line else "port_closed"

        return CEMEvent(
            ts=int(time.time()),
            host=host,
            source_ip=addr,
            log_type="syscollector",
            action=action,
            target=f"{proto}:{port}",
            outcome="ok",
            status=port,
            user="system",
            raw=raw_line.rstrip("\r\n"),
            meta={"proto": proto, "port": port, "address": addr, "decoder": self.name},
        )


class DecoderPipeline:
    """Hierarchical sequential decoder matching engine."""

    def __init__(self):
        # Base decoders
        self.decoders: List[Any] = [
            FimDecoder(),
            SyscollectorDecoder(),
            JsonLogDecoder(),
            WebAccessDecoder(),
            SshdAuthDecoder(),
            SyslogGenericDecoder(),
        ]
        # Dynamically load enterprise decoders (Windows, CloudTrail, Entra, DNS, K8s)
        try:
            from .enterprise_decoders import (
                WindowsSecurityEventDecoder,
                CloudTrailDecoder,
                MicrosoftEntraDecoder,
                DnsLogDecoder,
                KubernetesAuditDecoder
            )
            self.decoders.extend([
                WindowsSecurityEventDecoder(),
                CloudTrailDecoder(),
                MicrosoftEntraDecoder(),
                DnsLogDecoder(),
                KubernetesAuditDecoder()
            ])
        except Exception:
            pass

    def decode_line(self, line: str, host: str = "unknown", year: Optional[int] = None) -> Optional[CEMEvent]:
        if not line or not line.strip():
            return None
        for dec in self.decoders:
            if dec.match(line):
                return dec.decode(line, host=host, year=year)
        return None

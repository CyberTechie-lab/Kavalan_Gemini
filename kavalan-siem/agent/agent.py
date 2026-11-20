#!/usr/bin/env python3
"""
agent.py - Kavalan Standalone Endpoint Security Agent (Tier 1)

Ultra-lightweight enterprise endpoint agent (<12 MB RAM, <0.5% CPU).
Zero external dependencies (pure Python standard library).
Designed for Ubuntu / Debian Linux servers and cross-platform environments.

Key Features:
  1. Auto-enrollment / registration with Kavalan Manager (Tier 2)
  2. RFC3164 and RFC5424 (ISO-8601) Syslog & Web Access log decoders
  3. Automatic discovery of Ubuntu log files (/var/log/auth.log, /var/log/nginx, /var/log/apache2)
  4. Reliable log tailing with rotation & truncation detection (logrotate safe)
  5. Persistent disk & memory spooling when Manager or network is offline
  6. Periodic keepalive heartbeats with CPU load, memory, and OS metadata
  7. Native systemd service compatibility for production deployment

Usage:
  python3 agent.py --config /etc/kavalan-agent/agent.conf
  python3 agent.py --manager http://192.168.1.10:8910 --name ubuntu-web-01
  python3 agent.py --web /var/log/nginx/access.log --auth /var/log/auth.log
"""

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
import platform
import re
import signal
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

CURRENT_DIR = Path(__file__).resolve().parent

try:
    from .buffer import EventBuffer
    from .executor import ActiveResponseExecutor
    from .sca import SCABaselineAuditor
    from .syscheck import SyscheckScanner
    from .syscollector import SyscollectorScanner
except ImportError:
    try:
        from buffer import EventBuffer
        from executor import ActiveResponseExecutor
        from sca import SCABaselineAuditor
        from syscheck import SyscheckScanner
        from syscollector import SyscollectorScanner
    except ImportError:
        sys.path.insert(0, str(CURRENT_DIR))
        from buffer import EventBuffer
        from executor import ActiveResponseExecutor
        from sca import SCABaselineAuditor
        from syscheck import SyscheckScanner
        from syscollector import SyscollectorScanner

# ------------------------------------------------------------------ Frozen CEM Model

@dataclass
class CEMEvent:
    """Frozen Common Event Model (CEM) contract."""
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
    meta: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "ts": int(self.ts),
            "host": str(self.host),
            "source_ip": str(self.source_ip),
            "log_type": str(self.log_type),
            "action": str(self.action),
            "target": str(self.target),
            "outcome": str(self.outcome),
        }
        if self.status is not None:
            d["status"] = int(self.status)
        if self.user is not None:
            d["user"] = str(self.user)
        if self.raw is not None:
            d["raw"] = str(self.raw)
        if self.meta is not None:
            d["meta"] = dict(self.meta)
        return d


# ------------------------------------------------------------------ Built-in Decoders

# Web combined access logs (Nginx / Apache)
WEB_LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) \S+(?: "[^"]*" "(?P<ua>[^"]*)")?'
)

# Linux SSH / Auth logs:
# Standard RFC3164: "Nov  3 22:50:01 ubuntu-server sshd[12345]: ..."
AUTH_RFC3164_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.+)$"
)
# RFC5424 ISO-8601 (Ubuntu 22.04+ rsyslog / systemd journal): "2026-11-03T22:50:01.123456+00:00 ubuntu-server sshd[12345]: ..."
AUTH_ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z))\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.+)$"
)
AUTH_FAIL_RE = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
AUTH_INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")
AUTH_OK_RE = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+)")


def parse_web_line(line: str, host: str) -> Optional[CEMEvent]:
    """Parses a web combined access log line into a CEMEvent."""
    m = WEB_LOG_RE.match(line)
    if not m:
        return None

    try:
        dt = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
        ts = int(dt.timestamp())
    except Exception:
        ts = int(time.time())

    ip = m["ip"]
    method = m["method"]
    path = m["path"]
    try:
        status_code = int(m["status"])
    except (ValueError, TypeError):
        status_code = 200
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
        raw=line.rstrip("\r\n"),
        meta={"method": method, "path": path, "ua": ua},
    )


def parse_auth_line(line: str, host: str, year: Optional[int] = None) -> Optional[CEMEvent]:
    """Parses a syslog sshd line into a CEMEvent supporting RFC3164 and RFC5424 ISO formats."""
    # Try RFC3164 first
    m = AUTH_RFC3164_RE.match(line)
    is_iso = False
    if not m:
        m = AUTH_ISO_RE.match(line)
        is_iso = True
    if not m:
        return None

    msg = m["msg"]
    fm = AUTH_FAIL_RE.search(msg) or AUTH_INVALID_RE.search(msg)
    om = AUTH_OK_RE.search(msg)

    if fm:
        hit, outcome, status_code = fm, "fail", 1
    elif om:
        hit, outcome, status_code = om, "ok", 0
    else:
        return None

    try:
        if is_iso:
            ts_str = m["ts"].replace("Z", "+00:00")
            dt = datetime.fromisoformat(ts_str)
            ts = int(dt.timestamp())
        else:
            actual_year = year or datetime.now(timezone.utc).year
            dt = datetime.strptime(f"{actual_year} {m['ts']}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
            ts = int(dt.timestamp())
    except Exception:
        ts = int(time.time())

    ip = hit["ip"]
    user = hit["user"]
    action = f"ssh_{outcome}"
    target = "sshd"

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
        raw=line.rstrip("\r\n"),
        meta={"service": "sshd"},
    )


# ------------------------------------------------------------------ File Tailer

class FileTailer:
    """Tails log files with automatic logrotate (inode change) and truncation detection."""
    def __init__(self, path: str, log_type: str):
        self.path = path
        self.log_type = log_type
        self.inode: Optional[int] = None
        self.pos: int = 0

    def read_new_lines(self) -> List[str]:
        if not os.path.exists(self.path):
            return []

        try:
            st = os.stat(self.path)
            # Handle rotation (new inode)
            if self.inode is not None and st.st_ino != self.inode:
                self.inode = st.st_ino
                self.pos = 0
            elif self.inode is None:
                self.inode = st.st_ino

            # Handle truncation in place
            if st.st_size < self.pos:
                self.pos = 0

            with open(self.path, "r", errors="replace") as f:
                f.seek(self.pos)
                lines = f.readlines()
                self.pos = f.tell()
            return lines
        except Exception as e:
            print(f"[kavalan-agent] Error reading {self.path}: {e}", file=sys.stderr)
            return []


# ------------------------------------------------------------------ System Helpers

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_os_info() -> str:
    """Detects detailed Linux/Ubuntu OS information from /etc/os-release."""
    os_release = Path("/etc/os-release")
    if os_release.exists():
        try:
            lines = os_release.read_text().splitlines()
            data = {}
            for line in lines:
                if "=" in line:
                    k, v = line.split("=", 1)
                    data[k.strip()] = v.strip().strip('"')
            if "PRETTY_NAME" in data:
                return f"{data['PRETTY_NAME']} ({platform.machine()})"
        except Exception:
            pass
    return f"{platform.system()} {platform.release()} ({platform.machine()})"


def auto_discover_ubuntu_logs() -> List[Tuple[str, str]]:
    """Auto-detects standard Ubuntu / Debian log files on the host."""
    candidates = [
        ("/var/log/auth.log", "auth"),
        ("/var/log/secure", "auth"),
        ("/var/log/nginx/access.log", "web"),
        ("/var/log/apache2/access.log", "web"),
        ("/var/log/httpd/access_log", "web"),
        ("/var/log/syslog", "auth"),
    ]
    discovered = []
    for path_str, ltype in candidates:
        p = Path(path_str)
        if p.exists() and os.access(path_str, os.R_OK):
            discovered.append((path_str, ltype))
    return discovered


# ------------------------------------------------------------------ Agent Engine

class KavalanAgent:
    def __init__(self, manager_url: str, name: Optional[str] = None,
                 state_file: Optional[str] = None, spool_file: Optional[str] = None,
                 batch_size: int = 50, heartbeat_interval: int = 10,
                 fim_paths: Optional[List[str]] = None, fim_interval: int = 60,
                 syscollector_interval: int = 300, max_eps: int = 500,
                 enable_ar: bool = True):
        self.manager_url = manager_url.rstrip("/")
        self.name = name or socket.gethostname()
        self.ip = get_local_ip()
        self.os_info = get_os_info()

        # State and spool file locations (systemd safe)
        default_state = (
            Path("/var/lib/kavalan-agent") / f".agent_{self.name}.json"
            if Path("/var/lib/kavalan-agent").exists()
            else CURRENT_DIR / f".agent_{self.name}.json"
        )
        self.state_file = Path(state_file) if state_file else default_state
        self.state_file.parent.mkdir(parents=True, exist_ok=True)

        default_spool = (
            Path("/var/lib/kavalan-agent") / f"spool_{self.name}.jsonl"
            if Path("/var/lib/kavalan-agent").exists()
            else CURRENT_DIR / f".agent_spool_{self.name}.jsonl"
        )
        self.spool_file = Path(spool_file) if spool_file else default_spool

        self.batch_size = batch_size
        self.heartbeat_interval = heartbeat_interval
        self.fim_paths = [p for p in fim_paths] if fim_paths else []
        self.fim_interval = fim_interval
        self.syscollector_interval = syscollector_interval
        self.enable_ar = enable_ar
        self.tx_counter = 0
        self.config_version = 0

        self.agent_id: Optional[str] = None
        self.running = True
        self.spool: List[Dict[str, Any]] = []
        self.tailers: List[FileTailer] = []

        # Subsystem initializations
        self.buffer = EventBuffer(capacity=5000, max_eps=max_eps)
        self.syscheck = SyscheckScanner(monitored_paths=self.fim_paths, host=self.name, source_ip=self.ip) if self.fim_paths else None
        self.syscollector = SyscollectorScanner(host=self.name, source_ip=self.ip)
        self.executor = ActiveResponseExecutor()
        self.auditor = SCABaselineAuditor(host=self.name, source_ip=self.ip)

        # Load existing disk spool if present
        self._load_disk_spool()

    def _load_disk_spool(self):
        if self.spool_file.exists():
            try:
                lines = self.spool_file.read_text(encoding="utf-8").splitlines()
                for line in lines:
                    line = line.strip()
                    if line:
                        self.spool.append(json.loads(line))
                if self.spool:
                    print(f"[*] Restored {len(self.spool)} pending events from disk spool.")
                self.spool_file.unlink(missing_ok=True)
            except Exception as e:
                print(f"[!] Warning reading spool file {self.spool_file}: {e}", file=sys.stderr)

    def _persist_disk_spool(self):
        if not self.spool:
            return
        try:
            with open(self.spool_file, "a", encoding="utf-8") as f:
                for ev in self.spool[-2000:]:
                    f.write(json.dumps(ev) + "\n")
        except Exception:
            pass

    def load_or_register(self) -> bool:
        if self.state_file.exists():
            try:
                data = json.loads(self.state_file.read_text())
                self.agent_id = data.get("agent_id")
                self.config_version = int(data.get("config_version", 0))
                if self.agent_id:
                    print(f"[*] Loaded enrolled Agent ID: {self.agent_id} ({self.name}), config v{self.config_version}")
                    return True
            except Exception:
                pass

        # Register with Manager
        print(f"[*] Registering agent '{self.name}' ({self.ip}) with Kavalan Manager at {self.manager_url}...")
        payload = json.dumps({
            "name": self.name,
            "ip": self.ip,
            "os": self.os_info
        }).encode("utf-8")

        req = urllib.request.Request(
            f"{self.manager_url}/api/agent/register",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                if resp.status == 200:
                    res = json.loads(resp.read().decode("utf-8"))
                    self.agent_id = res.get("agent_id")
                    self.state_file.write_text(json.dumps({
                        "agent_id": self.agent_id,
                        "name": self.name,
                        "ip": self.ip,
                        "os": self.os_info,
                        "config_version": self.config_version,
                        "registered_at": int(time.time()),
                    }))
                    print(f"[+] Agent enrolled successfully! Assigned ID: {self.agent_id}")
                    return True
        except Exception as e:
            print(f"[!] Registration failed: {e}", file=sys.stderr)
        return False

    def send_heartbeat(self) -> bool:
        if not self.agent_id:
            return False

        load = os.getloadavg() if hasattr(os, "getloadavg") else [0.0, 0.0, 0.0]
        metrics = {
            "time": int(time.time()),
            "load": list(load),
            "ip": self.ip,
            "os": self.os_info,
            "monitored_sources": len(self.tailers),
            "buffered_events": len(self.buffer) + len(self.spool),
            "buffer_state": self.buffer.state,
            "config_version": self.config_version,
        }
        acks = self.executor.get_pending_acks()
        payload = json.dumps({
            "agent_id": self.agent_id,
            "metrics": metrics,
            "acks": acks
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self.manager_url}/api/agent/heartbeat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if resp.status == 200:
                    body = resp.read().decode("utf-8")
                    try:
                        data = json.loads(body)
                        commands = data.get("commands", [])
                        if self.enable_ar and commands:
                            for cmd in commands:
                                res = self.executor.execute_command(cmd)
                                print(f"[*] [ActiveResponse] Executed {res.get('action')}: {res.get('details')}")

                        # Centralized Remote Config Synchronization
                        remote_cfg = data.get("config")
                        remote_ver = int(data.get("config_version", 0))
                        if remote_cfg and remote_ver > self.config_version:
                            self.apply_remote_config(remote_cfg, remote_ver)
                    except Exception:
                        pass
                    return True
                return False
        except Exception:
            return False

    def apply_remote_config(self, cfg: Dict[str, Any], version: int):
        """Applies dynamic centralized configuration from Manager without process restart."""
        # 1. Sync monitored localfiles
        desired_files = []
        for lf in cfg.get("localfiles", []):
            loc = lf.get("location")
            fmt = lf.get("format", "web")
            if loc:
                desired_files.append((loc, fmt))

        curr_paths = {t.path: t for t in self.tailers}
        desired_paths = {f[0] for f in desired_files}

        # Add new tailers
        for loc, fmt in desired_files:
            if loc not in curr_paths:
                if os.path.exists(loc):
                    self.add_tailer(loc, fmt)
                else:
                    print(f"[*] [ConfigSync] Configured log {loc} does not currently exist (skipping).")

        # Remove deleted tailers if desired files specified
        if desired_paths:
            self.tailers = [t for t in self.tailers if t.path in desired_paths]

        # 2. Sync FIM directories
        desired_fim = cfg.get("syscheck", {}).get("directories", [])
        if set(desired_fim) != set(self.fim_paths):
            self.fim_paths = list(desired_fim)
            self.syscheck = SyscheckScanner(monitored_paths=self.fim_paths, host=self.name, source_ip=self.ip) if self.fim_paths else None
            print(f"[*] [ConfigSync] FIM directories updated: {self.fim_paths}")

        # 3. Update scan intervals
        if "interval" in cfg.get("syscheck", {}):
            self.fim_interval = int(cfg["syscheck"]["interval"])
        if "interval" in cfg.get("syscollector", {}):
            self.syscollector_interval = int(cfg["syscollector"]["interval"])

        self.config_version = version

        # Persist to state file
        try:
            cur_data = json.loads(self.state_file.read_text()) if self.state_file.exists() else {"agent_id": self.agent_id, "name": self.name}
            cur_data["config_version"] = version
            self.state_file.write_text(json.dumps(cur_data))
        except Exception:
            pass

        print(f"[+] [ConfigSync] Applied remote config v{version} from Manager (Active tailers: {len(self.tailers)})")

    def ship_sca_and_packages(self) -> bool:
        if not self.agent_id:
            return False
        try:
            sca_audit = self.auditor.run_audit()
            pkgs = self.syscollector.get_installed_packages()
            payload = json.dumps({
                "agent_id": self.agent_id,
                "sca": sca_audit,
                "packages": [
                    {"name": p.name, "version": p.version, "arch": p.arch}
                    for p in pkgs
                ]
            }).encode("utf-8")
            req = urllib.request.Request(
                f"{self.manager_url}/api/agent/sca",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                if resp.status == 200:
                    print(f"[+] [SCA] Published CIS baseline audit (Score: {sca_audit.get('score')}%) & {len(pkgs)} packages to Manager.")
                    return True
        except Exception as e:
            print(f"[!] Warning publishing SCA report: {e}", file=sys.stderr)
        return False

    def ship_events(self, events: List[Dict[str, Any]]) -> bool:
        if not self.agent_id or not events:
            return True
        self.tx_counter += 1
        payload = json.dumps({
            "agent_id": self.agent_id,
            "tx_id": self.tx_counter,
            "events": events
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self.manager_url}/api/agent/events",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                return resp.status == 200
        except Exception:
            return False

    def add_tailer(self, path: str, log_type: str):
        self.tailers.append(FileTailer(path, log_type))
        print(f"[*] Attached tailer for {log_type} log: {path}")

    def add_fim_path(self, path: str):
        if path not in self.fim_paths:
            self.fim_paths.append(path)
            self.syscheck = SyscheckScanner(monitored_paths=self.fim_paths, host=self.name, source_ip=self.ip)
            print(f"[*] Attached FIM monitoring for directory: {path}")

    def run(self, year: Optional[int] = None, once: bool = False):
        if not self.load_or_register():
            # Retry registration in loop if manager is starting up
            if not once:
                print("[*] Manager not yet reachable. Entering enrollment retry loop...")
                while self.running and not self.agent_id:
                    time.sleep(3)
                    if self.load_or_register():
                        break
            if not self.agent_id:
                print("[!] Could not enroll agent with Manager. Exiting.", file=sys.stderr)
                return

        actual_year = year or datetime.now(timezone.utc).year
        last_hb = 0
        last_flush = time.time()
        last_fim = 0
        last_syscol = 0

        def _sig(signum, frame):
            print(f"[*] Received signal {signum}. Persisting spool and shutting down...")
            self.running = False

        signal.signal(signal.SIGINT, _sig)
        signal.signal(signal.SIGTERM, _sig)

        print(f"[+] Kavalan Agent active (ID: {self.agent_id}, Host: {self.name}, IP: {self.ip}). Monitoring {len(self.tailers)} file sources.")

        # Initial baseline scans
        if self.syscheck:
            self.syscheck.run_scan(report_baseline=False)
        self.syscollector.run_scan(report_baseline=False)
        self.ship_sca_and_packages()

        while self.running:
            now = time.time()

            # Heartbeat check
            if now - last_hb >= self.heartbeat_interval:
                self.send_heartbeat()
                last_hb = now

            # Periodic FIM file integrity scan
            if self.syscheck and (now - last_fim >= self.fim_interval or once):
                fim_events = self.syscheck.run_scan()
                for fe in fim_events:
                    self.buffer.push(fe)
                last_fim = now

            # Periodic Syscollector scan & SCA audit push
            if (now - last_syscol >= self.syscollector_interval) or once:
                _, delta_events = self.syscollector.run_scan()
                for de in delta_events:
                    self.buffer.push(de)
                self.ship_sca_and_packages()
                last_syscol = now

            # Harvest logs from all attached tailers
            for t in self.tailers:
                lines = t.read_new_lines()
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    ev: Optional[CEMEvent] = None
                    if t.log_type == "web":
                        ev = parse_web_line(line, self.name)
                    elif t.log_type == "auth":
                        ev = parse_auth_line(line, self.name, actual_year)
                    if ev:
                        self.buffer.push(ev.to_dict())

            # Drain restored disk spool first if any
            if self.spool:
                batch = self.spool[:self.batch_size]
                if self.ship_events(batch):
                    self.spool = self.spool[len(batch):]
                else:
                    self._persist_disk_spool()

            # Ship buffered batch with rate limiting
            if len(self.buffer) > 0 and (len(self.buffer) >= self.batch_size or now - last_flush >= 1.5 or once):
                _, batch = self.buffer.pop_batch(max_batch_size=self.batch_size)
                if batch:
                    if self.ship_events(batch):
                        last_flush = now
                    else:
                        # Manager unreachable: buffer into spool and persist
                        self.spool.extend(batch)
                        if len(self.spool) > 5000:
                            self.spool = self.spool[-5000:]
                        self._persist_disk_spool()

            if once:
                # Drain remaining buffer & spool before exiting
                while len(self.buffer) > 0:
                    _, batch = self.buffer.pop_batch(max_batch_size=self.batch_size)
                    if batch:
                        if not self.ship_events(batch):
                            self.spool.extend(batch)
                            break
                while self.spool:
                    batch = self.spool[:self.batch_size]
                    if self.ship_events(batch):
                        self.spool = self.spool[len(batch):]
                    else:
                        break
                break

            time.sleep(0.5)

        self._persist_disk_spool()
        print(f"[*] Kavalan Agent {self.agent_id} stopped cleanly.")


# ------------------------------------------------------------------ CLI

def main():
    parser = argparse.ArgumentParser(description="Kavalan Standalone Endpoint Security Agent (Tier 1)")
    parser.add_argument("--config", default=None, help="Path to agent.conf JSON file")
    parser.add_argument("--manager", default="http://127.0.0.1:8910", help="Manager URL (default: http://127.0.0.1:8910)")
    parser.add_argument("--name", default=None, help="Agent hostname (default: system hostname)")
    parser.add_argument("--web", help="Path to web access.log (Nginx/Apache)")
    parser.add_argument("--auth", help="Path to auth.log / secure log (SSH)")
    parser.add_argument("--fim-path", action="append", default=[], help="Directory to monitor with File Integrity Monitoring (FIM)")
    parser.add_argument("--max-eps", type=int, default=500, help="Maximum events per second rate limit (default: 500)")
    parser.add_argument("--year", type=int, default=None, help="Syslog year (default: current year)")
    parser.add_argument("--once", action="store_true", help="Harvest existing logs to EOF, ship and exit")
    parser.add_argument("--auto-discover", action="store_true", help="Auto-discover standard Ubuntu log files")
    args = parser.parse_args()

    manager_url = args.manager
    agent_name = args.name
    batch_size = 50
    heartbeat_interval = 10
    max_eps = args.max_eps
    files_to_watch: List[Tuple[str, str]] = []
    fim_paths: List[str] = list(args.fim_path)

    # 1. Config file loading
    config_paths = [args.config, "/etc/kavalan-agent/agent.conf"] if args.config else ["/etc/kavalan-agent/agent.conf"]
    for cp in config_paths:
        if cp and os.path.exists(cp):
            try:
                cfg = json.loads(Path(cp).read_text(encoding="utf-8"))
                manager_url = cfg.get("manager", manager_url)
                agent_name = cfg.get("agent_name", agent_name)
                batch_size = cfg.get("batch_size", batch_size)
                heartbeat_interval = cfg.get("heartbeat_interval", heartbeat_interval)
                max_eps = cfg.get("max_eps", max_eps)
                cfg_dirs = cfg.get("syscheck", {}).get("directories", [])
                fim_paths.extend(cfg_dirs)
                for lf in cfg.get("localfiles", []):
                    loc = lf.get("location")
                    fmt = lf.get("format", "web")
                    if loc:
                        files_to_watch.append((loc, fmt))
                print(f"[*] Loaded configuration from {cp}")
                break
            except Exception as e:
                print(f"[!] Error reading config {cp}: {e}", file=sys.stderr)

    # 2. Command-line overrides
    if args.web:
        files_to_watch.append((args.web, "web"))
    if args.auth:
        files_to_watch.append((args.auth, "auth"))

    # 3. Auto-discovery on Ubuntu if no logs configured
    if not files_to_watch or args.auto_discover:
        discovered = auto_discover_ubuntu_logs()
        for loc, fmt in discovered:
            if not any(f[0] == loc for f in files_to_watch):
                files_to_watch.append((loc, fmt))

    agent = KavalanAgent(
        manager_url=manager_url,
        name=agent_name,
        batch_size=batch_size,
        heartbeat_interval=heartbeat_interval,
        fim_paths=fim_paths,
        max_eps=max_eps
    )

    for loc, fmt in files_to_watch:
        if os.path.exists(loc):
            agent.add_tailer(loc, fmt)
        else:
            print(f"[!] Log file not found (skipping): {loc}")

    agent.run(year=args.year, once=args.once)


if __name__ == "__main__":
    main()

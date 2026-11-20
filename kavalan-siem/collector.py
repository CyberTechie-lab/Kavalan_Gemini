#!/usr/bin/env python3
"""
collector.py - Kavalan SIEM Log Collector

Tails log files (web access log, auth.log), parses lines into the frozen
Common Event Model (CEM) format, and batches/ships them to Kavalan SIEM Core
via POST /ingest.

Usage:
  python3 collector.py --web /path/access.log --auth /path/auth.log --core http://127.0.0.1:8900 --host web-01
"""

import argparse
import json
import os
import signal
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add kavalan-ml and current dir to path to reuse regexes and CEM model
CURRENT_DIR = Path(__file__).resolve().parent
KAVALAN_ML_DIR = CURRENT_DIR.parent / "kavalan-ml"
if str(KAVALAN_ML_DIR) not in sys.path and KAVALAN_ML_DIR.exists():
    sys.path.insert(0, str(KAVALAN_ML_DIR))
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

import detector
import kavalan_multi
from cem import CEMEvent, validate_event


# ------------------------------------------------------------------ Parsers

def parse_web_line(line: str, host: str) -> Optional[CEMEvent]:
    """Parses a web combined access log line into a CEMEvent."""
    m = detector.LOG_RE.match(line)
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

    # Map status code to outcome enum: ok | fail | denied | error
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
        raw=line.rstrip("\r\n"),
        meta=meta,
    )


def parse_auth_line(line: str, host: str, year: int) -> Optional[CEMEvent]:
    """Parses a syslog sshd line into a CEMEvent."""
    m = kavalan_multi.AUTH_RE.match(line)
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

    try:
        dt = datetime.strptime(f"{year} {m['ts']}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
        ts = int(dt.timestamp())
    except Exception:
        return None

    ip = hit["ip"]
    user = hit["user"]
    action = f"ssh_{outcome}"
    target = "sshd"
    meta = {"service": "sshd"}

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
        meta=meta,
    )


# ------------------------------------------------------------------ File Tailer

class FileTailer:
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
            print(f"[collector] Error reading {self.path}: {e}", file=sys.stderr)
            return []


# ------------------------------------------------------------------ Log Shipping

def ship_batch(core_url: str, events: List[Dict[str, Any]], timeout: float = 5.0) -> bool:
    if not events:
        return True

    url = f"{core_url.rstrip('/')}/ingest"
    data = json.dumps(events).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                res_body = json.loads(resp.read().decode("utf-8"))
                accepted = res_body.get("accepted", 0)
                rejected = res_body.get("rejected", 0)
                print(f"[collector] Shipped {len(events)} events -> Core accepted {accepted}, rejected {rejected}")
                return True
    except urllib.error.URLError as e:
        print(f"[collector] Failed to ship events to {url}: {e}", file=sys.stderr)
    except Exception as e:
        print(f"[collector] Unexpected error shipping to {url}: {e}", file=sys.stderr)

    return False


# ------------------------------------------------------------------ Main Collector Loop

def run_collector(tailers: List[FileTailer], core_url: str, host: str,
                  year: int, batch_size: int = 50, flush_interval: float = 2.0,
                  once: bool = False):
    buffer: List[Dict[str, Any]] = []
    last_flush = time.time()
    running = True

    def _sig_handler(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    print(f"[*] Collector active. Monitoring {[t.path for t in tailers]} for host '{host}'")
    print(f"[*] Shipping to core: {core_url} (batch size: {batch_size}, flush interval: {flush_interval}s)")

    while running:
        new_events_found = False
        for tailer in tailers:
            lines = tailer.read_new_lines()
            if lines:
                new_events_found = True
                for line in lines:
                    if not line.strip():
                        continue
                    ev = None
                    if tailer.log_type == "web":
                        ev = parse_web_line(line, host)
                    elif tailer.log_type == "auth":
                        ev = parse_auth_line(line, host, year)

                    if ev is not None:
                        buffer.append(ev.to_dict())

                        if len(buffer) >= batch_size:
                            if ship_batch(core_url, buffer):
                                buffer.clear()
                                last_flush = time.time()

        # Flush on interval
        now = time.time()
        if buffer and (now - last_flush >= flush_interval):
            if ship_batch(core_url, buffer):
                buffer.clear()
                last_flush = now

        if once:
            # Single pass: flush all remaining and break
            if buffer:
                ship_batch(core_url, buffer)
                buffer.clear()
            break

        time.sleep(0.5)

    # Flush any remaining on shutdown
    if buffer:
        ship_batch(core_url, buffer)
        buffer.clear()
    print("[*] Collector stopped.")


def main():
    parser = argparse.ArgumentParser(description="Kavalan SIEM — Log Collector")
    parser.add_argument("--web", help="Path to nginx/Apache web access.log")
    parser.add_argument("--auth", help="Path to Linux auth.log")
    parser.add_argument("--core", default="http://127.0.0.1:8900", help="SIEM core URL (default: http://127.0.0.1:8900)")
    parser.add_argument("--host", default="web-01", help="Monitored machine host ID (default: web-01)")
    parser.add_argument("--year", type=int, default=None, help="Year for syslog timestamps (default: current year)")
    parser.add_argument("--batch-size", type=int, default=50, help="Batch size for shipping events (default: 50)")
    parser.add_argument("--interval", type=float, default=2.0, help="Flush interval in seconds (default: 2.0)")
    parser.add_argument("--once", action="store_true", help="Read available files to EOF, ship all, and exit")
    args = parser.parse_args()

    if not args.web and not args.auth:
        parser.error("At least one of --web or --auth must be specified.")

    year = args.year or datetime.now(timezone.utc).year
    tailers = []
    if args.web:
        tailers.append(FileTailer(args.web, "web"))
    if args.auth:
        tailers.append(FileTailer(args.auth, "auth"))

    run_collector(
        tailers=tailers,
        core_url=args.core,
        host=args.host,
        year=year,
        batch_size=args.batch_size,
        flush_interval=args.interval,
        once=args.once,
    )


if __name__ == "__main__":
    main()

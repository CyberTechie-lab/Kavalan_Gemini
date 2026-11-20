#!/usr/bin/env python3
"""
siem.py - Kavalan SIEM Core

A single-node, offline mini-SIEM that:
  1. Accepts normalised events over HTTP (POST /ingest)
  2. Stores them in SQLite
  3. Every --interval seconds, runs Kavalan detection over a rolling --window
  4. Serves /api/state, /api/events, /api/stats/timeline and the SOC dashboard at /

Reuses detector.py and kavalan_multi.py directly as libraries.
"""

import argparse
import json
import os
import random
import sqlite3
import sys
import threading
import time
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add kavalan-ml to sys.path so detector and kavalan_multi can be imported
CURRENT_DIR = Path(__file__).resolve().parent
KAVALAN_ML_DIR = CURRENT_DIR.parent / "kavalan-ml"
if str(KAVALAN_ML_DIR) not in sys.path and KAVALAN_ML_DIR.exists():
    sys.path.insert(0, str(KAVALAN_ML_DIR))
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

import detector
import kavalan_multi
from cem import CEMEvent, validate_event
from fastapi import FastAPI, Query, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn


# ------------------------------------------------------------------ Database Helpers

def get_db(db_path: str) -> sqlite3.Connection:
    con = sqlite3.connect(db_path, check_same_thread=False, timeout=10.0)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    return con


def init_db(db_path: str) -> None:
    con = get_db(db_path)
    with con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                host TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                log_type TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                outcome TEXT NOT NULL,
                status INTEGER,
                user TEXT,
                raw TEXT,
                meta_json TEXT
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_events_log_type ON events(log_type)")

        con.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                key TEXT PRIMARY KEY,
                level TEXT NOT NULL,
                type TEXT NOT NULL,
                summary TEXT NOT NULL,
                detail TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                status TEXT DEFAULT 'new'
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_alerts_level ON alerts(level)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
    con.close()


# ------------------------------------------------------------------ Core State & Detection

class SiemCore:
    def __init__(self, db_path: str, window_minutes: int = 15, interval: int = 5,
                 dashboard_path: Optional[str] = None, model_path: Optional[str] = None):
        self.db_path = db_path
        self.window_minutes = window_minutes
        self.interval = interval
        self.model_path = model_path
        self.dashboard_path = dashboard_path or str(CURRENT_DIR / "dashboard.html")
        self.start_time = time.time()
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.worker_thread: Optional[threading.Thread] = None

        # Tracking for Events Per Second (EPS)
        self.recent_ingests = deque(maxlen=2000)

        self.state: Dict[str, Any] = {
            "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0},
            "sources": [],
            "alerts": [],
            "web_campaigns": [],
            "events_in_window": 0,
            "sources_in_window": 0,
            "total_events": 0,
            "eps": 0.0,
            "window_minutes": self.window_minutes,
            "window_start": None,
            "window_end": None,
            "last_scan": None,
            "uptime_seconds": 0,
        }

    def compute_eps(self) -> float:
        now = time.time()
        with self.lock:
            # Drop entries older than 5 seconds
            while self.recent_ingests and now - self.recent_ingests[0][0] > 5.0:
                self.recent_ingests.popleft()
            if not self.recent_ingests:
                return 0.0
            total_events = sum(count for _, count in self.recent_ingests)
            elapsed = max(1.0, now - self.recent_ingests[0][0])
            return round(total_events / elapsed, 1)

    def ingest_events(self, items: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Validates CEM events and inserts valid ones into SQLite."""
        valid_rows = []
        errors = []
        rejected = 0

        for idx, item in enumerate(items):
            try:
                ev = validate_event(item)
                valid_rows.append((
                    ev.ts,
                    ev.host,
                    ev.source_ip,
                    ev.log_type,
                    ev.action,
                    ev.target,
                    ev.outcome,
                    ev.status,
                    ev.user,
                    ev.raw,
                    json.dumps(ev.meta),
                ))
            except Exception as e:
                rejected += 1
                if len(errors) < 10:
                    errors.append(f"Item #{idx}: {str(e)}")

        accepted = len(valid_rows)
        if valid_rows:
            con = get_db(self.db_path)
            with con:
                con.executemany("""
                    INSERT INTO events (ts, host, source_ip, log_type, action, target, outcome, status, user, raw, meta_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, valid_rows)
            con.close()

            # Track EPS
            now = time.time()
            with self.lock:
                self.recent_ingests.append((now, accepted))

        return {"accepted": accepted, "rejected": rejected, "errors": errors}

    def run_detection_pass(self) -> Dict[str, Any]:
        """
        Runs Kavalan detection over the rolling time window.
        Adapts CEM events in SQLite to the tuple shapes expected by:
          - detector.analyse (web)
          - kavalan_multi.score_ssh (auth)
          - kavalan_multi.correlate (both)
        """
        con = get_db(self.db_path)
        try:
            row = con.execute("SELECT MAX(ts) FROM events").fetchone()
            max_ts = row[0] if row and row[0] is not None else None

            total_row = con.execute("SELECT COUNT(*) FROM events").fetchone()
            total_events = total_row[0] if total_row else 0

            eps = self.compute_eps()

            if max_ts is None:
                # No events in database yet
                now_iso = datetime.now(timezone.utc).isoformat()
                with self.lock:
                    self.state.update({
                        "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0},
                        "sources": [],
                        "alerts": [],
                        "web_campaigns": [],
                        "events_in_window": 0,
                        "sources_in_window": 0,
                        "total_events": total_events,
                        "eps": eps,
                        "last_scan": now_iso,
                        "uptime_seconds": int(time.time() - self.start_time),
                    })
                    return self.state

            window_seconds = self.window_minutes * 60
            cutoff = max_ts - window_seconds

            cursor = con.execute("""
                SELECT ts, host, source_ip, log_type, action, target, outcome, status, user, meta_json
                FROM events
                WHERE ts >= ? AND ts <= ?
                ORDER BY ts ASC
            """, (cutoff, max_ts))
            rows = cursor.fetchall()
            events_in_window = len(rows)

            web_by_ip = {}
            auth_by_ip = {}
            all_ips = set()

            for r in rows:
                ip = r["source_ip"]
                all_ips.add(ip)
                ltype = r["log_type"]
                ts = r["ts"]

                if ltype == "web":
                    meta = {}
                    if r["meta_json"]:
                        try:
                            meta = json.loads(r["meta_json"])
                        except Exception:
                            pass
                    method = meta.get("method")
                    path = meta.get("path")
                    if not method or not path:
                        action = r["action"]
                        if " " in action:
                            parts = action.split(" ", 1)
                            method = method or parts[0]
                            path = path or parts[1]
                        else:
                            method = method or "GET"
                            path = path or r["target"]
                    status_code = r["status"] if r["status"] is not None else 200
                    web_by_ip.setdefault(ip, []).append((ts, method, path, status_code))

                elif ltype == "auth":
                    outcome = "fail" if r["outcome"] in ("fail", "denied", "error") else "ok"
                    user = r["user"] or ""
                    auth_by_ip.setdefault(ip, []).append((ts, outcome, user))

            # 1. Web analysis
            web_sources = []
            if web_by_ip:
                if self.model_path and os.path.exists(self.model_path):
                    detector.label_with_model(web_by_ip, self.model_path)
                web_sources = [s for s in (detector.analyse(ip, evs) for ip, evs in web_by_ip.items()) if s]
            web_campaigns = detector.find_campaigns(web_sources) if web_sources else []

            # 2. Auth analysis
            ssh_sources = []
            if auth_by_ip:
                ssh_sources = [s for s in (kavalan_multi.score_ssh(ip, evs) for ip, evs in auth_by_ip.items()) if s]

            # 3. Correlation
            correlated_rows = kavalan_multi.correlate(web_sources, ssh_sources)

            # Map correlated rows by ip for quick lookup
            corr_by_ip = {r["ip"]: r for r in correlated_rows}

            # Build full source table for SIEM: includes correlated threats + benign sources (level OK)
            web_score_map = {s["ip"]: s["score"] for s in web_sources}
            ssh_score_map = {s["ip"]: s["score"] for s in ssh_sources}

            sources_table = []
            for r in correlated_rows:
                r["log_types"] = list(r.get("channels", []))
                sources_table.append(r)

            # Benign / unflagged sources
            for ip in sorted(all_ips - set(corr_by_ip.keys())):
                channels = []
                if ip in web_by_ip:
                    channels.append("web")
                if ip in auth_by_ip:
                    channels.append("ssh")
                sources_table.append({
                    "ip": ip,
                    "level": "OK",
                    "cross_source": False,
                    "channels": channels,
                    "log_types": channels,
                    "web_score": web_score_map.get(ip, 0),
                    "ssh_score": ssh_score_map.get(ip, 0),
                    "tactics": {},
                    "reasons": [],
                })

            # Calculate severity counts
            crit_count = sum(1 for r in correlated_rows if r["level"] == "CRITICAL") + len(web_campaigns)
            high_count = sum(1 for r in correlated_rows if r["level"] == "HIGH")
            med_count = sum(1 for r in correlated_rows if r["level"] == "MEDIUM")
            counts = {"CRITICAL": crit_count, "HIGH": high_count, "MEDIUM": med_count}

            # Build alerts list and persist to alerts table
            alerts = []
            now_iso = datetime.now(timezone.utc).isoformat()

            # Campaign alerts
            for c in web_campaigns:
                camp_key = f"campaign:{c['sources'][0]}:{c['first']}"
                summary = (f"Agent campaign: {len(c['sources'])} short-lived sources, "
                           f"{c['requests']:,} requests")
                camp_alert = {
                    "key": camp_key,
                    "level": "CRITICAL",
                    "type": "agent_campaign",
                    "summary": summary,
                    "sources": c["sources"],
                    "requests": c["requests"],
                    "tactics": c.get("tactics", {}),
                    "first": c["first"],
                    "last": c["last"],
                    "status": self._get_alert_status(con, camp_key),
                    "reasons": [summary],
                }
                alerts.append(camp_alert)
                self._upsert_alert(con, camp_key, "CRITICAL", "agent_campaign", summary, camp_alert, now_iso)

            # Correlated source alerts
            for r in correlated_rows:
                src_key = f"source:{r['ip']}"
                if r["cross_source"]:
                    alert_type = "cross_source_agent"
                    summary = f"Cross-source agent: {r['ip']} attacked {' + '.join(r['channels'])}"
                else:
                    ch = r["channels"][0] if r.get("channels") else "unknown"
                    alert_type = f"{ch}_attack"
                    summary = f"Suspicious activity on {ch} by {r['ip']}"

                alert_status = self._get_alert_status(con, src_key)
                alert_obj = {
                    "key": src_key,
                    "level": r["level"],
                    "type": alert_type,
                    "ip": r["ip"],
                    "summary": summary,
                    "cross_source": r["cross_source"],
                    "channels": r["channels"],
                    "web_score": r["web_score"],
                    "ssh_score": r["ssh_score"],
                    "tactics": r.get("tactics", {}),
                    "status": alert_status,
                    "reasons": r.get("reasons", []),
                }
                alerts.append(alert_obj)
                self._upsert_alert(con, src_key, r["level"], alert_type, summary, alert_obj, now_iso)

            with self.lock:
                self.state.update({
                    "counts": counts,
                    "sources": sources_table,
                    "alerts": alerts,
                    "web_campaigns": [
                        {"sources": c["sources"], "requests": c["requests"], "first": c["first"], "last": c["last"]}
                        for c in web_campaigns
                    ],
                    "events_in_window": events_in_window,
                    "sources_in_window": len(all_ips),
                    "total_events": total_events,
                    "eps": eps,
                    "window_start": cutoff,
                    "window_end": max_ts,
                    "last_scan": now_iso,
                    "uptime_seconds": int(time.time() - self.start_time),
                })
                return self.state

        finally:
            con.close()

    def _get_alert_status(self, con: sqlite3.Connection, key: str) -> str:
        row = con.execute("SELECT status FROM alerts WHERE key=?", (key,)).fetchone()
        return row[0] if row and row[0] else "new"

    def _upsert_alert(self, con: sqlite3.Connection, key: str, level: str,
                      atype: str, summary: str, detail_obj: dict, now_iso: str) -> None:
        detail_json = json.dumps(detail_obj)
        with con:
            existing = con.execute("SELECT status FROM alerts WHERE key=?", (key,)).fetchone()
            if existing:
                con.execute("""
                    UPDATE alerts
                    SET level=?, type=?, summary=?, detail=?, last_seen=?
                    WHERE key=?
                """, (level, atype, summary, detail_json, now_iso, key))
            else:
                con.execute("""
                    INSERT INTO alerts (key, level, type, summary, detail, first_seen, last_seen, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'new')
                """, (key, level, atype, summary, detail_json, now_iso, now_iso))

    def update_alert_status(self, key: str, new_status: str) -> bool:
        if new_status not in ("new", "acknowledged", "resolved"):
            return False
        con = get_db(self.db_path)
        with con:
            cur = con.execute("UPDATE alerts SET status=? WHERE key=?", (new_status, key))
            updated = cur.rowcount > 0
        con.close()
        if updated:
            with self.lock:
                for a in self.state.get("alerts", []):
                    if a.get("key") == key:
                        a["status"] = new_status
        return updated

    def get_events(self, limit: int = 50, offset: int = 0, ip: Optional[str] = None,
                   log_type: Optional[str] = None, outcome: Optional[str] = None,
                   q: Optional[str] = None, since_ts: Optional[int] = None) -> Dict[str, Any]:
        """Queries events with filters for the SIEM Log Explorer."""
        con = get_db(self.db_path)
        conditions = []
        params = []

        if ip:
            conditions.append("source_ip = ?")
            params.append(ip)
        if log_type:
            conditions.append("log_type = ?")
            params.append(log_type)
        if outcome:
            conditions.append("outcome = ?")
            params.append(outcome)
        if since_ts:
            conditions.append("ts >= ?")
            params.append(since_ts)
        if q:
            conditions.append("(action LIKE ? OR target LIKE ? OR user LIKE ? OR raw LIKE ?)")
            pattern = f"%{q}%"
            params.extend([pattern, pattern, pattern, pattern])

        where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""
        count_query = f"SELECT COUNT(*) FROM events{where_clause}"
        total = con.execute(count_query, params).fetchone()[0]

        data_query = f"""
            SELECT id, ts, host, source_ip, log_type, action, target, outcome, status, user, raw, meta_json
            FROM events{where_clause}
            ORDER BY ts DESC, id DESC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])
        rows = con.execute(data_query, params).fetchall()

        events = []
        for r in rows:
            meta = {}
            if r["meta_json"]:
                try:
                    meta = json.loads(r["meta_json"])
                except Exception:
                    pass
            events.append({
                "id": r["id"],
                "ts": r["ts"],
                "host": r["host"],
                "source_ip": r["source_ip"],
                "log_type": r["log_type"],
                "action": r["action"],
                "target": r["target"],
                "outcome": r["outcome"],
                "status": r["status"],
                "user": r["user"],
                "raw": r["raw"],
                "meta": meta,
            })
        con.close()
        return {"events": events, "total": total, "limit": limit, "offset": offset}

    def get_source_timeline(self, ip: str) -> Dict[str, Any]:
        """Deep dive investigation data for an IP."""
        con = get_db(self.db_path)
        cursor = con.execute("""
            SELECT id, ts, log_type, action, target, outcome, status, user, raw, meta_json
            FROM events
            WHERE source_ip = ?
            ORDER BY ts ASC
            LIMIT 500
        """, (ip,))
        rows = cursor.fetchall()
        con.close()

        events = []
        for r in rows:
            events.append({
                "id": r["id"],
                "ts": r["ts"],
                "log_type": r["log_type"],
                "action": r["action"],
                "target": r["target"],
                "outcome": r["outcome"],
                "status": r["status"],
                "user": r["user"],
                "raw": r["raw"],
            })

        # Match against current source row
        with self.lock:
            src_info = next((s for s in self.state["sources"] if s["ip"] == ip), None)
            alerts = [a for a in self.state["alerts"] if a.get("ip") == ip]

        return {
            "ip": ip,
            "info": src_info,
            "alerts": alerts,
            "events_count": len(events),
            "events": events,
        }

    def get_timeline_stats(self) -> Dict[str, Any]:
        """Returns bucketed event activity across the window for histogram chart."""
        con = get_db(self.db_path)
        row = con.execute("SELECT MAX(ts) FROM events").fetchone()
        if not row or not row[0]:
            con.close()
            return {"buckets": []}

        max_ts = row[0]
        min_ts = max_ts - (self.window_minutes * 60)
        # Bucket every 60 seconds
        cursor = con.execute("""
            SELECT (ts / 60) * 60 AS bucket, log_type, outcome, COUNT(*) as cnt
            FROM events
            WHERE ts >= ? AND ts <= ?
            GROUP BY bucket, log_type, outcome
            ORDER BY bucket ASC
        """, (min_ts, max_ts))
        rows = cursor.fetchall()
        con.close()

        buckets_map: Dict[int, Dict[str, int]] = {}
        # Pre-fill every minute
        cur = (min_ts // 60) * 60
        while cur <= max_ts:
            buckets_map[cur] = {"ts": cur, "web": 0, "auth": 0, "errors": 0, "total": 0}
            cur += 60

        for r in rows:
            b = r["bucket"]
            if b in buckets_map:
                cnt = r["cnt"]
                ltype = r["log_type"]
                out = r["outcome"]
                buckets_map[b]["total"] += cnt
                if ltype == "web":
                    buckets_map[b]["web"] += cnt
                elif ltype == "auth":
                    buckets_map[b]["auth"] += cnt
                if out in ("fail", "denied", "error"):
                    buckets_map[b]["errors"] += cnt

        return {"buckets": sorted(buckets_map.values(), key=lambda x: x["ts"])}

    def simulate_traffic(self, scenario: str) -> Dict[str, Any]:
        """Generates realistic real-time traffic bursts with current timestamps."""
        now = int(time.time())
        events = []
        host = "web-01"

        if scenario == "cross_source":
            actor_ip = f"203.0.113.{random.randint(150, 199)}"
            # 1. Rapid web attack
            web_attacks = [
                ("GET", "/admin", 401, "denied"),
                ("GET", "/api/v1/admin/tokens", 403, "denied"),
                ("GET", "/page?file=../../../../etc/passwd", 404, "fail"),
                ("POST", "/rest/products/search?q=1' OR '1'='1", 500, "error"),
                ("GET", "/.env", 404, "fail"),
                ("GET", "/.git/config", 404, "fail"),
                ("GET", "/redirect?url=http://169.254.169.254/", 403, "denied"),
                ("POST", "/cmd?x=;id", 403, "denied"),
            ]
            t = now - 50
            for _ in range(60):
                method, path, status_code, outcome = random.choice(web_attacks)
                events.append({
                    "ts": t,
                    "host": host,
                    "source_ip": actor_ip,
                    "log_type": "web",
                    "action": f"{method} {path}",
                    "target": path.split("?", 1)[0],
                    "outcome": outcome,
                    "status": status_code,
                    "user": None,
                    "raw": f'{actor_ip} - - [{datetime.fromtimestamp(t, timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {path} HTTP/1.1" {status_code} 512',
                    "meta": {"method": method, "path": path},
                })
                t += 1

            # 2. SSH Brute force & Breach
            users = ["root", "admin", "ubuntu", "msfadmin", "deploy"]
            t = now - 45
            for _ in range(25):
                u = random.choice(users)
                events.append({
                    "ts": t,
                    "host": host,
                    "source_ip": actor_ip,
                    "log_type": "auth",
                    "action": "ssh_fail",
                    "target": "sshd",
                    "outcome": "fail",
                    "status": 1,
                    "user": u,
                    "raw": f'{datetime.fromtimestamp(t, timezone.utc).strftime("%b %d %H:%M:%S")} {host} sshd[1234]: Failed password for {u} from {actor_ip} port 54321 ssh2',
                    "meta": {"service": "sshd"},
                })
                t += 1
            # Breach event
            events.append({
                "ts": now - 5,
                "host": host,
                "source_ip": actor_ip,
                "log_type": "auth",
                "action": "ssh_ok",
                "target": "sshd",
                "outcome": "ok",
                "status": 0,
                "user": "msfadmin",
                "raw": f'{datetime.fromtimestamp(now - 5, timezone.utc).strftime("%b %d %H:%M:%S")} {host} sshd[1235]: Accepted password for msfadmin from {actor_ip} port 54400 ssh2',
                "meta": {"service": "sshd"},
            })

        elif scenario == "web_scan":
            actor_ip = f"198.51.100.{random.randint(150, 199)}"
            scan_paths = ["/.env", "/.git/config", "/admin", "/backup.zip", "/config.json", "/phpinfo.php", "/api/v1/admin/users"]
            t = now - 40
            for _ in range(75):
                p = random.choice(scan_paths) + f"/{random.randint(1, 99)}"
                events.append({
                    "ts": t,
                    "host": host,
                    "source_ip": actor_ip,
                    "log_type": "web",
                    "action": f"GET {p}",
                    "target": p,
                    "outcome": "fail",
                    "status": 404,
                    "user": None,
                    "raw": f'{actor_ip} - - [{datetime.fromtimestamp(t, timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {p} HTTP/1.1" 404 512',
                    "meta": {"method": "GET", "path": p},
                })
                t += 1

        elif scenario == "ssh_brute":
            actor_ip = f"198.51.100.{random.randint(200, 250)}"
            users = ["root", "admin", "oracle", "postgres", "test", "git"]
            t = now - 35
            for _ in range(40):
                u = random.choice(users)
                events.append({
                    "ts": t,
                    "host": host,
                    "source_ip": actor_ip,
                    "log_type": "auth",
                    "action": "ssh_fail",
                    "target": "sshd",
                    "outcome": "fail",
                    "status": 1,
                    "user": u,
                    "raw": f'{datetime.fromtimestamp(t, timezone.utc).strftime("%b %d %H:%M:%S")} {host} sshd[1236]: Failed password for invalid user {u} from {actor_ip} port 43210 ssh2',
                    "meta": {"service": "sshd"},
                })
                t += 1

        else:  # benign_burst
            user_ip = f"192.0.2.{random.randint(50, 80)}"
            pages = ["/", "/products", "/about", "/cart", "/rest/products/search?q=shoes"]
            t = now - 20
            for _ in range(15):
                p = random.choice(pages)
                events.append({
                    "ts": t,
                    "host": host,
                    "source_ip": user_ip,
                    "log_type": "web",
                    "action": f"GET {p}",
                    "target": p.split("?", 1)[0],
                    "outcome": "ok",
                    "status": 200,
                    "user": None,
                    "raw": f'{user_ip} - - [{datetime.fromtimestamp(t, timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {p} HTTP/1.1" 200 512',
                    "meta": {"method": "GET", "path": p},
                })
                t += 1

        res = self.ingest_events(events)
        self.run_detection_pass()
        return {
            "scenario": scenario,
            "generated_events": len(events),
            "ingest_result": res,
            "actor_ip": events[0]["source_ip"] if events else None,
        }

    def start_worker(self) -> None:
        if self.worker_thread is not None and self.worker_thread.is_alive():
            return
        self.stop_event.clear()
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()

    def stop_worker(self) -> None:
        self.stop_event.set()
        if self.worker_thread is not None:
            self.worker_thread.join(timeout=2.0)

    def _worker_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.run_detection_pass()
            except Exception as e:
                print(f"[siem] Error during detection pass: {e}", file=sys.stderr)
            self.stop_event.wait(self.interval)


# ------------------------------------------------------------------ FastAPI App

def create_app(core: SiemCore) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        init_db(core.db_path)
        core.start_worker()
        yield
        core.stop_worker()

    app = FastAPI(title="Kavalan SIEM", lifespan=lifespan)

    @app.post("/ingest")
    async def ingest_endpoint(request: Request):
        try:
            body = await request.json()
        except Exception as e:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": f"Invalid JSON body: {str(e)}"},
            )

        if not isinstance(body, list):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "Body must be a JSON array of CEM events"},
            )

        res = core.ingest_events(body)
        return JSONResponse(content=res, status_code=status.HTTP_200_OK)

    @app.get("/api/state")
    async def state_endpoint():
        with core.lock:
            core.state["uptime_seconds"] = int(time.time() - core.start_time)
            core.state["eps"] = core.compute_eps()
            return JSONResponse(content=core.state)

    @app.post("/api/scan")
    async def scan_endpoint():
        """Manually triggers detection pass and returns state immediately."""
        st = core.run_detection_pass()
        return JSONResponse(content=st)

    @app.get("/api/events")
    async def events_endpoint(
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
        ip: Optional[str] = None,
        log_type: Optional[str] = None,
        outcome: Optional[str] = None,
        q: Optional[str] = None,
        since_ts: Optional[int] = None,
    ):
        """SIEM Log Explorer: paginated & filtered event stream."""
        data = core.get_events(limit=limit, offset=offset, ip=ip, log_type=log_type,
                               outcome=outcome, q=q, since_ts=since_ts)
        return JSONResponse(content=data)

    @app.get("/api/sources/{ip}/timeline")
    async def source_timeline_endpoint(ip: str):
        """Deep dive investigation data for an IP."""
        data = core.get_source_timeline(ip)
        return JSONResponse(content=data)

    @app.post("/api/alerts/{key:path}/status")
    async def alert_status_endpoint(key: str, request: Request):
        """Update alert status (new, acknowledged, resolved)."""
        body = await request.json()
        new_status = body.get("status")
        if not new_status or new_status not in ("new", "acknowledged", "resolved"):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "Status must be 'new', 'acknowledged', or 'resolved'"},
            )
        updated = core.update_alert_status(key, new_status)
        if not updated:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"error": f"Alert with key '{key}' not found"},
            )
        return JSONResponse(content={"ok": True, "key": key, "status": new_status})

    @app.get("/api/stats/timeline")
    async def timeline_stats_endpoint():
        """Histogram activity across the window."""
        data = core.get_timeline_stats()
        return JSONResponse(content=data)

    @app.post("/api/simulate")
    async def simulate_endpoint(request: Request):
        """Simulate live traffic and attacks."""
        body = {}
        try:
            body = await request.json()
        except Exception:
            pass
        scenario = body.get("scenario", "cross_source")
        res = core.simulate_traffic(scenario)
        return JSONResponse(content=res)

    @app.get("/")
    async def dashboard_endpoint():
        path = Path(core.dashboard_path)
        if not path.exists():
            return HTMLResponse(
                content=f"<h1>Kavalan SIEM</h1><p>Dashboard file not found at {path}</p>",
                status_code=404,
            )
        html = path.read_text(encoding="utf-8")
        resp = HTMLResponse(content=html)
        resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    return app


# ------------------------------------------------------------------ CLI

def main():
    parser = argparse.ArgumentParser(description="Kavalan SIEM — Core & Ingest Server")
    parser.add_argument("--db", default="kavalan_siem.db", help="SQLite database path")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8900, help="Bind port (default: 8900)")
    parser.add_argument("--window", type=int, default=15, help="Rolling detection window in minutes (default: 15)")
    parser.add_argument("--interval", type=int, default=5, help="Detection pass interval in seconds (default: 5)")
    parser.add_argument("--dashboard", default=None, help="Path to dashboard.html")
    parser.add_argument("--model", default=None, help="Optional scikit-learn model for web classifier")
    args = parser.parse_args()

    init_db(args.db)
    core = SiemCore(
        db_path=args.db,
        window_minutes=args.window,
        interval=args.interval,
        dashboard_path=args.dashboard,
        model_path=args.model,
    )
    app = create_app(core)

    print(f"[*] Kavalan SIEM Core starting on http://{args.host}:{args.port}")
    print(f"[*] Database: {args.db} | Window: {args.window} min | Interval: {args.interval}s")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()

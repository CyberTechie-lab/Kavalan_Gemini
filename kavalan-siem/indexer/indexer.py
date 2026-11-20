#!/usr/bin/env python3
"""
indexer.py - Kavalan Lightweight Indexer Service (Tier 3)

A high-performance, embedded document and time-series search engine (<25MB RAM),
100% offline, powered by SQLite in WAL mode with composite indices.

Endpoints:
  POST /api/index/events     - Ingests & indexes event documents
  POST /api/index/alerts     - Ingests & indexes security alerts
  POST /api/search/events    - Filter & query events with pagination
  POST /api/search/alerts    - Filter & query alerts
  POST /api/aggregate        - Date histograms & term aggregations
  GET  /api/stats            - Storage and index metrics
  GET  /health               - Health check
"""

import argparse
import json
import os
import re
import sqlite3
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
import uvicorn


import threading

_local_storage = threading.local()


def get_db(db_path: str) -> sqlite3.Connection:
    con = getattr(_local_storage, "con", None)
    current_path = getattr(_local_storage, "db_path", None)
    is_closed = False
    if con is not None:
        try:
            con.execute("SELECT 1")
        except Exception:
            is_closed = True
    if con is None or is_closed or current_path != db_path:
        con = sqlite3.connect(db_path, check_same_thread=False, timeout=30.0)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode = WAL")
        con.execute("PRAGMA synchronous = NORMAL")
        con.execute("PRAGMA cache_size = -64000")  # 64MB cache
        con.execute("PRAGMA temp_store = MEMORY")
        _local_storage.con = con
        _local_storage.db_path = db_path
    return con


def init_db(db_path: str) -> None:
    con = get_db(db_path)
    with con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS events_index (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                agent_id TEXT NOT NULL,
                host TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                log_type TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                outcome TEXT NOT NULL,
                status INTEGER,
                user TEXT,
                tactics_json TEXT,
                raw TEXT,
                meta_json TEXT
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_ei_ts ON events_index(timestamp)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_ei_ts_desc ON events_index(timestamp DESC, id DESC)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_ei_agent ON events_index(agent_id)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_ei_src ON events_index(source_ip)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_ei_type ON events_index(log_type)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_ei_outcome ON events_index(outcome)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_ei_target ON events_index(target)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_ei_action ON events_index(action)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_ei_user ON events_index(user)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_ei_composite ON events_index(agent_id, source_ip, timestamp)")

        con.execute("""
            CREATE TABLE IF NOT EXISTS alerts_index (
                id TEXT PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                level TEXT NOT NULL,
                type TEXT NOT NULL,
                agent_id TEXT,
                source_ip TEXT,
                summary TEXT NOT NULL,
                mitre_tactics TEXT,
                detail_json TEXT NOT NULL,
                status TEXT DEFAULT 'new'
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_ai_ts ON alerts_index(timestamp)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_ai_ts_desc ON alerts_index(timestamp DESC)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_ai_level ON alerts_index(level)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_ai_agent ON alerts_index(agent_id)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_ai_status ON alerts_index(status)")


class IndexerService:
    def __init__(self, db_path: str):
        self.db_path = db_path
        try:
            from threat_intel import ThreatIntelEngine
            self.threat_intel = ThreatIntelEngine(db_path=self.db_path)
        except Exception:
            self.threat_intel = None

    def index_events(self, docs: List[Dict[str, Any]]) -> int:
        rows = []
        for d in docs:
            tactics = d.get("tactics") or {}
            meta = d.get("meta") or {}
            rows.append((
                d.get("ts") or d.get("timestamp") or int(time.time()),
                d.get("agent_id", "000"),
                d.get("host", "unknown"),
                d.get("source_ip", "0.0.0.0"),
                d.get("log_type", "unknown"),
                d.get("action", ""),
                d.get("target", ""),
                d.get("outcome", "ok"),
                d.get("status"),
                d.get("user"),
                json.dumps(tactics),
                d.get("raw"),
                json.dumps(meta),
            ))
        if rows:
            con = get_db(self.db_path)
            with con:
                con.executemany("""
                    INSERT INTO events_index (timestamp, agent_id, host, source_ip, log_type, action, target, outcome, status, user, tactics_json, raw, meta_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, rows)
        return len(rows)

    def index_alerts(self, alerts: List[Dict[str, Any]]) -> int:
        con = get_db(self.db_path)
        with con:
            for a in alerts:
                aid = a.get("key") or a.get("id") or f"alert:{int(time.time())}:{a.get('source_ip')}"
                ts = a.get("timestamp") or a.get("ts") or int(time.time())
                tactics = json.dumps(a.get("tactics") or a.get("mitre_tactics") or {})
                detail = json.dumps(a)
                con.execute("""
                    INSERT INTO alerts_index (id, timestamp, level, type, agent_id, source_ip, summary, mitre_tactics, detail_json, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        level = excluded.level,
                        type = excluded.type,
                        summary = excluded.summary,
                        mitre_tactics = excluded.mitre_tactics,
                        detail_json = excluded.detail_json,
                        timestamp = excluded.timestamp
                """, (
                    aid,
                    ts,
                    a.get("level", "MEDIUM"),
                    a.get("type", "security_alert"),
                    a.get("agent_id", "000"),
                    a.get("ip") or a.get("source_ip", ""),
                    a.get("summary", ""),
                    tactics,
                    detail,
                    a.get("status", "new"),
                ))
        return len(alerts)

    def _build_event_filter_clause(self, query: Dict[str, Any]) -> Tuple[str, List[Any]]:
        filters = []
        params = []

        if query.get("agent_id"):
            filters.append("agent_id = ?")
            params.append(str(query["agent_id"]))
        if query.get("host"):
            filters.append("host = ?")
            params.append(str(query["host"]))
        if query.get("source_ip"):
            filters.append("source_ip = ?")
            params.append(str(query["source_ip"]))
        if query.get("log_type"):
            filters.append("log_type = ?")
            params.append(str(query["log_type"]))
        if query.get("outcome"):
            filters.append("outcome = ?")
            params.append(str(query["outcome"]))
        if query.get("start_ts"):
            filters.append("timestamp >= ?")
            params.append(int(query["start_ts"]))
        if query.get("end_ts"):
            filters.append("timestamp <= ?")
            params.append(int(query["end_ts"]))

        if query.get("q"):
            raw_q = str(query["q"]).strip()
            # Tokenize: supports quoted phrases, negation, and multi-word terms
            tokens = re.findall(r'(NOT\s+"[^"]+"|\bNOT\s+\S+|"[^"]+"|\S+)', raw_q)
            for token in tokens:
                token = token.strip()
                if not token:
                    continue
                is_neg = False
                val = token
                if val.upper().startswith("NOT "):
                    is_neg = True
                    val = val[4:].strip()
                if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                    val = val[1:-1].strip()
                if not val:
                    continue
                
                p = f"%{val}%"
                if is_neg:
                    filters.append("""(
                        target NOT LIKE ? AND action NOT LIKE ? AND user NOT LIKE ? 
                        AND host NOT LIKE ? AND source_ip NOT LIKE ? AND raw NOT LIKE ? AND meta_json NOT LIKE ?
                    )""")
                    params.extend([p, p, p, p, p, p, p])
                else:
                    filters.append("""(
                        target LIKE ? OR action LIKE ? OR user LIKE ? 
                        OR host LIKE ? OR source_ip LIKE ? OR raw LIKE ? OR meta_json LIKE ?
                    )""")
                    params.extend([p, p, p, p, p, p, p])

        where_clause = " WHERE " + " AND ".join(filters) if filters else ""
        return where_clause, params

    def search_events(self, query: Dict[str, Any]) -> Dict[str, Any]:
        limit = min(500, max(1, int(query.get("limit", 50))))
        offset = max(0, int(query.get("offset", 0)))
        where_clause, params = self._build_event_filter_clause(query)

        con = get_db(self.db_path)
        total = con.execute(f"SELECT COUNT(*) FROM events_index{where_clause}", params).fetchone()[0]

        sql = f"""
            SELECT id, timestamp, agent_id, host, source_ip, log_type, action, target, outcome, status, user, tactics_json, raw, meta_json
            FROM events_index{where_clause}
            ORDER BY timestamp DESC, id DESC
            LIMIT ? OFFSET ?
        """
        rows = con.execute(sql, params + [limit, offset]).fetchall()

        events = []
        for r in rows:
            events.append({
                "id": r["id"],
                "timestamp": r["timestamp"],
                "agent_id": r["agent_id"],
                "host": r["host"],
                "source_ip": r["source_ip"],
                "log_type": r["log_type"],
                "action": r["action"],
                "target": r["target"],
                "outcome": r["outcome"],
                "status": r["status"],
                "user": r["user"],
                "tactics": json.loads(r["tactics_json"]) if r["tactics_json"] else {},
                "raw": r["raw"],
                "meta": json.loads(r["meta_json"]) if r["meta_json"] else {},
            })
        return {"total": total, "limit": limit, "offset": offset, "hits": events}

    def search_alerts(self, query: Dict[str, Any]) -> Dict[str, Any]:
        filters = []
        params = []
        if query.get("level"):
            filters.append("level = ?")
            params.append(query["level"])
        if query.get("agent_id"):
            filters.append("agent_id = ?")
            params.append(query["agent_id"])
        if query.get("source_ip"):
            filters.append("source_ip = ?")
            params.append(query["source_ip"])
        if query.get("status"):
            filters.append("status = ?")
            params.append(query["status"])

        where = " WHERE " + " AND ".join(filters) if filters else ""
        con = get_db(self.db_path)
        sql = f"SELECT id, timestamp, level, type, agent_id, source_ip, summary, mitre_tactics, detail_json, status FROM alerts_index{where} ORDER BY timestamp DESC"
        rows = con.execute(sql, params).fetchall()

        alerts = []
        for r in rows:
            alerts.append({
                "id": r["id"],
                "timestamp": r["timestamp"],
                "level": r["level"],
                "type": r["type"],
                "agent_id": r["agent_id"],
                "source_ip": r["source_ip"],
                "summary": r["summary"],
                "mitre_tactics": json.loads(r["mitre_tactics"]) if r["mitre_tactics"] else {},
                "detail": json.loads(r["detail_json"]) if r["detail_json"] else {},
                "status": r["status"],
            })
        return {"total": len(alerts), "hits": alerts}

    def aggregate(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """Date histograms and term aggregations."""
        con = get_db(self.db_path)
        res: Dict[str, Any] = {}

        # 1. Date histogram
        if "date_histogram" in req:
            dh = req["date_histogram"]
            bucket_sec = max(10, int(dh.get("interval_seconds", 60)))
            start_ts = int(dh.get("start_ts", 0))
            end_ts = int(dh.get("end_ts", int(time.time())))

            cursor = con.execute("""
                SELECT (timestamp / ?) * ? as b_ts, log_type, outcome, COUNT(*) as cnt
                FROM events_index
                WHERE timestamp >= ? AND timestamp <= ?
                GROUP BY b_ts, log_type, outcome
                ORDER BY b_ts ASC
            """, (bucket_sec, bucket_sec, start_ts, end_ts))
            rows = cursor.fetchall()

            buckets_map = {}
            cur = (start_ts // bucket_sec) * bucket_sec
            while cur <= end_ts:
                buckets_map[cur] = {"timestamp": cur, "total": 0, "web": 0, "auth": 0, "errors": 0}
                cur += bucket_sec

            for r in rows:
                b = r["b_ts"]
                if b in buckets_map:
                    cnt = r["cnt"]
                    buckets_map[b]["total"] += cnt
                    if r["log_type"] == "web":
                        buckets_map[b]["web"] += cnt
                    elif r["log_type"] == "auth":
                        buckets_map[b]["auth"] += cnt
                    if r["outcome"] in ("fail", "denied", "error"):
                        buckets_map[b]["errors"] += cnt

            res["date_histogram"] = sorted(buckets_map.values(), key=lambda x: x["timestamp"])

        # 2. Terms aggregations
        if "terms" in req:
            for field in req["terms"]:
                if field in ("source_ip", "agent_id", "log_type", "outcome", "status"):
                    cursor = con.execute(f"""
                        SELECT {field} as term, COUNT(*) as count
                        FROM events_index
                        GROUP BY {field}
                        ORDER BY count DESC
                        LIMIT 10
                    """)
                    res[f"terms_{field}"] = [{"term": r["term"], "count": r["count"]} for r in cursor.fetchall()]

        return res

    def get_surrounding_events(self, event_id: int, window: int = 5) -> Dict[str, Any]:
        con = get_db(self.db_path)
        target = con.execute("""
            SELECT id, timestamp, agent_id, host, source_ip, log_type, action, target, outcome, status, user, tactics_json, raw, meta_json
            FROM events_index WHERE id = ?
        """, (event_id,)).fetchone()
        if not target:
            return {"error": f"Event {event_id} not found", "events": []}

        t_ts = target["timestamp"]
        t_host = target["host"]

        before_rows = con.execute("""
            SELECT id, timestamp, agent_id, host, source_ip, log_type, action, target, outcome, status, user, tactics_json, raw, meta_json
            FROM events_index
            WHERE host = ? AND (timestamp < ? OR (timestamp = ? AND id < ?))
            ORDER BY timestamp DESC, id DESC
            LIMIT ?
        """, (t_host, t_ts, t_ts, event_id, window)).fetchall()

        after_rows = con.execute("""
            SELECT id, timestamp, agent_id, host, source_ip, log_type, action, target, outcome, status, user, tactics_json, raw, meta_json
            FROM events_index
            WHERE host = ? AND (timestamp > ? OR (timestamp = ? AND id > ?))
            ORDER BY timestamp ASC, id ASC
            LIMIT ?
        """, (t_host, t_ts, t_ts, event_id, window)).fetchall()

        def _row_to_dict(r, is_target=False):
            return {
                "id": r["id"],
                "timestamp": r["timestamp"],
                "agent_id": r["agent_id"],
                "host": r["host"],
                "source_ip": r["source_ip"],
                "log_type": r["log_type"],
                "action": r["action"],
                "target": r["target"],
                "outcome": r["outcome"],
                "status": r["status"],
                "user": r["user"],
                "tactics": json.loads(r["tactics_json"]) if r["tactics_json"] else {},
                "raw": r["raw"],
                "meta": json.loads(r["meta_json"]) if r["meta_json"] else {},
                "is_target": is_target
            }

        result = [_row_to_dict(r) for r in reversed(before_rows)]
        result.append(_row_to_dict(target, is_target=True))
        result.extend([_row_to_dict(r) for r in after_rows])

        return {
            "target_id": event_id,
            "host": t_host,
            "timestamp": t_ts,
            "events": result
        }

    def get_field_stats(self, query: Dict[str, Any]) -> Dict[str, Any]:
        """Calculates top term distributions and counts for Kibana Discover field explorer sidebar."""
        con = get_db(self.db_path)
        where, params = self._build_event_filter_clause(query)
        total = con.execute(f"SELECT COUNT(*) FROM events_index{where}", params).fetchone()[0]

        target_fields = ["host", "source_ip", "log_type", "action", "status", "user", "outcome"]
        stats: Dict[str, Any] = {"total_events": total, "fields": {}}

        for fld in target_fields:
            sql = f"""
                SELECT COALESCE({fld}, '(empty)') as term, COUNT(*) as cnt
                FROM events_index{where}
                GROUP BY {fld}
                ORDER BY cnt DESC
                LIMIT 5
            """
            rows = con.execute(sql, params).fetchall()
            items = []
            for r in rows:
                cnt = r["cnt"]
                pct = round((cnt / total * 100), 1) if total > 0 else 0
                items.append({
                    "term": str(r["term"]),
                    "count": cnt,
                    "percent": pct
                })
            stats["fields"][fld] = items

        return stats

    def get_ip_dossier(self, ip: str) -> Dict[str, Any]:
        """Compiles a complete 360-degree security investigation dossier for an IP address."""
        con = get_db(self.db_path)

        is_loopback = ip in ("127.0.0.1", "::1", "localhost")
        parts = ip.split(".")
        is_private = (
            ip.startswith("10.") or
            ip.startswith("192.168.") or
            (ip.startswith("172.") and len(parts) == 4 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31)
        )
        if is_loopback:
            classification = "LOCALHOST / LOOPBACK"
        elif is_private:
            classification = "INTERNAL LAN (RFC 1918)"
        else:
            classification = "EXTERNAL INTERNET (PUBLIC WAN)"

        row = con.execute("""
            SELECT COUNT(*) as total, MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
            FROM events_index WHERE source_ip = ?
        """, (ip,)).fetchone()

        total_events = row["total"] if row else 0
        first_seen = row["first_seen"] if row and row["first_seen"] else None
        last_seen = row["last_seen"] if row and row["last_seen"] else None

        hosts = [r["host"] for r in con.execute("""
            SELECT DISTINCT host FROM events_index WHERE source_ip = ? ORDER BY host ASC
        """, (ip,)).fetchall()]

        log_types = [{"type": r["log_type"], "count": r["cnt"]} for r in con.execute("""
            SELECT log_type, COUNT(*) as cnt FROM events_index WHERE source_ip = ? GROUP BY log_type ORDER BY cnt DESC
        """, (ip,)).fetchall()]

        top_actions = [{"action": r["action"], "target": r["target"], "count": r["cnt"]} for r in con.execute("""
            SELECT action, target, COUNT(*) as cnt FROM events_index
            WHERE source_ip = ? GROUP BY action, target ORDER BY cnt DESC LIMIT 8
        """, (ip,)).fetchall()]

        ssh_attempts = [{"user": r["user"] or "unknown", "outcome": r["outcome"], "count": r["cnt"]} for r in con.execute("""
            SELECT user, outcome, COUNT(*) as cnt FROM events_index
            WHERE source_ip = ? AND log_type = 'auth' GROUP BY user, outcome ORDER BY cnt DESC LIMIT 8
        """, (ip,)).fetchall()]

        status_codes = [{"status": r["status"], "count": r["cnt"]} for r in con.execute("""
            SELECT status, COUNT(*) as cnt FROM events_index
            WHERE source_ip = ? AND status IS NOT NULL GROUP BY status ORDER BY cnt DESC LIMIT 5
        """, (ip,)).fetchall()]

        alerts = []
        for r in con.execute("""
            SELECT id, timestamp, level, type, summary, mitre_tactics FROM alerts_index
            WHERE source_ip = ? ORDER BY timestamp DESC LIMIT 10
        """, (ip,)).fetchall():
            alerts.append({
                "id": r["id"],
                "timestamp": r["timestamp"],
                "level": r["level"],
                "type": r["type"],
                "summary": r["summary"],
                "tactics": json.loads(r["mitre_tactics"]) if r["mitre_tactics"] else {}
            })

        has_crit = any(a["level"] == "CRITICAL" for a in alerts)
        has_high = any(a["level"] == "HIGH" for a in alerts)
        ssh_fails = sum(a["count"] for a in ssh_attempts if a["outcome"] == "fail")

        if has_crit:
            threat_level = "CRITICAL"
            threat_score = 98
        elif has_high or ssh_fails >= 10:
            threat_level = "HIGH"
            threat_score = 75
        elif ssh_fails > 0 or any(s["status"] in (401, 403, 500) for s in status_codes):
            threat_level = "MEDIUM"
            threat_score = 45
        else:
            threat_level = "LOW / BENIGN"
            threat_score = 10

        ti_data = self.threat_intel.lookup(ip) if self.threat_intel else {}
        if ti_data.get("found") and ti_data.get("threat_score", 0) > threat_score:
            threat_score = max(threat_score, ti_data["threat_score"])
            if ti_data.get("threat_level") in ("CRITICAL", "HIGH"):
                threat_level = ti_data["threat_level"]

        return {
            "ip": ip,
            "classification": classification,
            "is_private": is_private,
            "threat_level": threat_level,
            "threat_score": threat_score,
            "threat_intel": ti_data,
            "total_events": total_events,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "hosts_targeted": hosts,
            "log_types": log_types,
            "top_actions": top_actions,
            "ssh_attempts": ssh_attempts,
            "status_codes": status_codes,
            "alerts": alerts
        }

    def get_stats(self) -> Dict[str, Any]:
        con = get_db(self.db_path)
        events_count = con.execute("SELECT COUNT(*) FROM events_index").fetchone()[0]
        alerts_count = con.execute("SELECT COUNT(*) FROM alerts_index").fetchone()[0]

        db_size_bytes = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0
        return {
            "total_events": events_count,
            "total_alerts": alerts_count,
            "db_size_bytes": db_size_bytes,
            "db_size_mb": round(db_size_bytes / (1024 * 1024), 2),
        }

    def get_attack_graph(self, window_seconds: int = 3600, ip: Optional[str] = None) -> Dict[str, Any]:
        """Builds directed multi-entity attack topology graph, blast-radius metrics, and killchain steps."""
        con = get_db(self.db_path)
        now = int(time.time())
        cutoff = now - window_seconds

        alert_params = [cutoff]
        alert_where = "WHERE timestamp >= ?"
        if ip:
            alert_where += " AND source_ip = ?"
            alert_params.append(ip)

        alert_rows = con.execute(f"""
            SELECT id, timestamp, level, type, agent_id, source_ip, summary, mitre_tactics, detail_json
            FROM alerts_index {alert_where}
            ORDER BY timestamp DESC LIMIT 60
        """, alert_params).fetchall()

        if not alert_rows:
            fallback_params = [ip] if ip else []
            where_fb = "WHERE source_ip = ?" if ip else ""
            alert_rows = con.execute(f"""
                SELECT id, timestamp, level, type, agent_id, source_ip, summary, mitre_tactics, detail_json
                FROM alerts_index {where_fb}
                ORDER BY timestamp DESC LIMIT 30
            """, fallback_params).fetchall()

        actor_ips = set()
        for r in alert_rows:
            if r["source_ip"]:
                actor_ips.add(r["source_ip"])
        if ip:
            actor_ips.add(ip)

        nodes = {}
        links = []
        link_keys = set()
        timeline_steps = []

        def _add_node(n_id, label, n_type, **kwargs):
            if n_id not in nodes:
                nodes[n_id] = {
                    "id": n_id,
                    "label": label,
                    "type": n_type,
                    **kwargs
                }

        def _add_link(source_id, target_id, link_type, count=1, **kwargs):
            key = f"{source_id}->{target_id}:{link_type}"
            if key not in link_keys:
                link_keys.add(key)
                links.append({
                    "source": source_id,
                    "target": target_id,
                    "type": link_type,
                    "count": count,
                    **kwargs
                })

        for ar in alert_rows:
            src_ip = ar["source_ip"]
            lvl = ar["level"]
            agent_id = ar["agent_id"]
            tactics = json.loads(ar["mitre_tactics"]) if ar["mitre_tactics"] else {}
            details = json.loads(ar["detail_json"]) if ar["detail_json"] else {}
            ts = ar["timestamp"]
            host = details.get("host")
            if not host and details.get("hosts") and isinstance(details["hosts"], list) and len(details["hosts"]) > 0:
                host = details["hosts"][0]
            if not host or host in ("agent-000", "agent-none", ""):
                h_row = con.execute("SELECT host FROM events_index WHERE source_ip = ? ORDER BY timestamp DESC LIMIT 1", (src_ip,)).fetchone()
                if h_row and h_row[0]:
                    host = h_row[0]
                elif agent_id and str(agent_id) not in ("000", "0", ""):
                    host = f"agent-{agent_id}"
                else:
                    host = "server"

            actor_node_id = f"ip_{src_ip}"
            is_priv = src_ip.startswith("10.") or src_ip.startswith("192.168.") or (src_ip.startswith("172.") and "172.16." in src_ip)
            ti_data = self.threat_intel.lookup(src_ip) if self.threat_intel else {}
            calc_score = max(95 if lvl == "CRITICAL" else 75 if lvl == "HIGH" else 40, ti_data.get("threat_score", 0))
            calc_lvl = "CRITICAL" if (lvl == "CRITICAL" or ti_data.get("threat_level") == "CRITICAL") else lvl
            _add_node(actor_node_id, src_ip, "actor",
                      threat_score=calc_score,
                      threat_level=calc_lvl,
                      is_private=is_priv,
                      threat_intel=ti_data)

            host_node_id = f"host_{host}"
            _add_node(host_node_id, host, "host", os="Linux (Monitored)")
            _add_link(actor_node_id, host_node_id, "attacks", count=details.get("event_count", 1), level=lvl)

            tgt = details.get("target") or ("sshd" if "ssh" in ar["summary"].lower() else "web-service")
            target_node_id = f"target_{tgt}"
            _add_node(target_node_id, tgt, "target", category="service")
            _add_link(actor_node_id, target_node_id, "probes", count=1)
            _add_link(host_node_id, target_node_id, "hosts", count=1)

            for t_code, t_val in tactics.items():
                t_node_id = f"tactic_{t_code}"
                _add_node(t_node_id, t_code, "tactic")
                _add_link(actor_node_id, t_node_id, "uses_tactic", count=1)

            timeline_steps.append({
                "timestamp": ts,
                "actor": src_ip,
                "host": host,
                "summary": ar["summary"],
                "level": lvl,
                "active_node_ids": [actor_node_id, host_node_id, target_node_id]
            })

        if actor_ips:
            placeholders = ",".join("?" for _ in actor_ips)
            ev_rows = con.execute(f"""
                SELECT id, timestamp, host, source_ip, log_type, action, target, outcome, status, user
                FROM events_index
                WHERE source_ip IN ({placeholders}) AND (outcome != 'ok' OR action = 'ssh_ok' OR log_type = 'fim')
                ORDER BY timestamp DESC LIMIT 80
            """, list(actor_ips)).fetchall()

            for er in ev_rows:
                src_ip = er["source_ip"]
                host = er["host"]
                u = er["user"]
                tgt = er["target"]
                act = er["action"]
                out = er["outcome"]
                ts = er["timestamp"]

                actor_id = f"ip_{src_ip}"
                host_id = f"host_{host}"

                if u:
                    user_node_id = f"user_{u}"
                    is_breach = (act == "ssh_ok" or out == "ok")
                    _add_node(user_node_id, u, "user",
                              is_compromised=is_breach,
                              status="COMPROMISED" if is_breach else "TARGETED")
                    _add_link(actor_id, user_node_id, "compromised" if is_breach else "brute_forces", count=1)
                    _add_link(host_id, user_node_id, "authorizes", count=1)

                    if is_breach:
                        timeline_steps.append({
                            "timestamp": ts,
                            "actor": src_ip,
                            "host": host,
                            "summary": f"BREACH: Valid credentials used for '{u}' on {host}",
                            "level": "CRITICAL",
                            "active_node_ids": [actor_id, host_id, user_node_id]
                        })

                if er["log_type"] == "fim":
                    fim_target_id = f"fim_{tgt}"
                    _add_node(fim_target_id, tgt, "fim_file", action=act)
                    _add_link(host_id, fim_target_id, "file_tampered", count=1)
                    timeline_steps.append({
                        "timestamp": ts,
                        "actor": src_ip,
                        "host": host,
                        "summary": f"FIM INTEGRITY TAMPERING: {tgt} {act}",
                        "level": "CRITICAL",
                        "active_node_ids": [host_id, fim_target_id]
                    })

        timeline_steps.sort(key=lambda s: s["timestamp"])

        hosts_targeted = len([n for n in nodes.values() if n["type"] == "host"])
        users_targeted = len([n for n in nodes.values() if n["type"] == "user"])
        compromised_users = len([n for n in nodes.values() if n["type"] == "user" and n.get("is_compromised")])
        actors_count = len([n for n in nodes.values() if n["type"] == "actor"])

        if compromised_users > 0:
            blast_radius_status = "CRITICAL / ACTIVE BREACH"
            blast_score = 95
        elif hosts_targeted > 1:
            blast_radius_status = "HIGH / LATERAL RECON"
            blast_score = 75
        elif actors_count > 0:
            blast_radius_status = "ELEVATED / PERIMETER PROBE"
            blast_score = 45
        else:
            blast_radius_status = "BENIGN / NORMAL"
            blast_score = 10

        return {
            "window_seconds": window_seconds,
            "filter_ip": ip,
            "metrics": {
                "blast_radius_status": blast_radius_status,
                "blast_score": blast_score,
                "total_actors": actors_count,
                "hosts_targeted": hosts_targeted,
                "users_targeted": users_targeted,
                "compromised_users": compromised_users,
                "total_nodes": len(nodes),
                "total_links": len(links),
            },
            "nodes": list(nodes.values()),
            "links": links,
            "timeline_steps": timeline_steps
        }


def create_indexer_app(indexer: IndexerService) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        init_db(indexer.db_path)
        yield

    app = FastAPI(title="Kavalan Indexer (Tier 3)", lifespan=lifespan)

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "kavalan-indexer"}

    @app.post("/api/index/events")
    async def index_events_api(request: Request):
        body = await request.json()
        if not isinstance(body, list):
            return JSONResponse(status_code=400, content={"error": "Expected array of events"})
        count = indexer.index_events(body)
        return {"indexed": count}

    @app.post("/api/index/alerts")
    async def index_alerts_api(request: Request):
        body = await request.json()
        if not isinstance(body, list):
            return JSONResponse(status_code=400, content={"error": "Expected array of alerts"})
        count = indexer.index_alerts(body)
        return {"indexed": count}

    @app.post("/api/search/events")
    async def search_events_api(request: Request):
        query = await request.json()
        return indexer.search_events(query)

    @app.post("/api/search/alerts")
    async def search_alerts_api(request: Request):
        query = await request.json()
        return indexer.search_alerts(query)

    @app.post("/api/aggregate")
    async def aggregate_api(request: Request):
        query = await request.json()
        return indexer.aggregate(query)

    @app.get("/api/events/{event_id}/context")
    async def get_surrounding_events_api(event_id: int, window: int = 5):
        return indexer.get_surrounding_events(event_id, window=window)

    @app.post("/api/fields/stats")
    async def get_field_stats_api(request: Request):
        query = await request.json()
        return indexer.get_field_stats(query)

    @app.get("/api/entity/ip/{ip}")
    async def get_ip_dossier_api(ip: str):
        return indexer.get_ip_dossier(ip)

    @app.get("/api/stats")
    async def stats_api():
        return indexer.get_stats()

    @app.get("/api/graph/attack-topology")
    async def get_attack_graph_api(window: int = 3600, ip: Optional[str] = None):
        return indexer.get_attack_graph(window_seconds=window, ip=ip)

    @app.get("/api/threat-intel/lookup/{ioc}")
    async def threat_intel_lookup_api(ioc: str):
        if indexer.threat_intel:
            return indexer.threat_intel.lookup(ioc)
        return {"found": False, "ioc": ioc}

    @app.get("/api/threat-intel/summary")
    async def threat_intel_summary_api():
        if indexer.threat_intel:
            return indexer.threat_intel.get_summary()
        return {"total_iocs": 0}

    @app.post("/api/threat-intel/iocs")
    async def threat_intel_add_ioc_api(request: Request):
        if not indexer.threat_intel:
            return {"error": "Threat intel not initialized"}
        data = await request.json()
        return indexer.threat_intel.add_ioc(
            ioc=data.get("ioc", ""),
            ioc_type=data.get("ioc_type", "ip"),
            threat_score=data.get("threat_score", 80),
            threat_level=data.get("threat_level", "HIGH"),
            reputation=data.get("reputation", "MALICIOUS"),
            feed=data.get("feed", "SOC Custom"),
            categories=data.get("categories"),
            country=data.get("country", "XX"),
            country_name=data.get("country_name", "Unknown"),
            asn=data.get("asn", "Unknown"),
            is_tor=data.get("is_tor", False),
            description=data.get("description", "")
        )

    return app


def main():
    parser = argparse.ArgumentParser(description="Kavalan Lightweight Indexer (Tier 3)")
    parser.add_argument("--db", default="indexer.db", help="Path to index database")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8920, help="Bind port (default: 8920)")
    args = parser.parse_args()

    db_path = str(BASE_DIR / args.db) if not os.path.isabs(args.db) else args.db
    init_db(db_path)
    indexer = IndexerService(db_path)
    app = create_indexer_app(indexer)
    print(f"[*] Kavalan Indexer (Tier 3) running on http://{args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()

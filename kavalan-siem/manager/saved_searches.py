"""
saved_searches.py - Saved Searches & Scheduled Search Alerting Engine for Kavalan SIEM

Allows SOC teams to:
  1. Bookmark and share investigative queries
  2. Schedule periodic query executions (e.g., every 5, 15, or 60 minutes)
  3. Automatically raise Alerts & create Incident Cases when thresholds are exceeded
"""

import json
import sqlite3
import threading
import time
import urllib.request
import uuid
from typing import Any, Callable, Dict, List, Optional


class SavedSearchManager:
    """Manages saved searches and background scheduled alert evaluation."""

    def __init__(
        self,
        db_factory: Callable[[], sqlite3.Connection],
        indexer_url: str = "http://127.0.0.1:8920",
        alert_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ):
        self.get_db = db_factory
        self.indexer_url = indexer_url.rstrip("/")
        self.alert_callback = alert_callback
        self.stop_event = threading.Event()
        self.worker_thread: Optional[threading.Thread] = None
        self.init_db()

    def init_db(self) -> None:
        conn = self.get_db()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS saved_searches (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                query TEXT NOT NULL,
                description TEXT,
                created_by TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                is_scheduled INTEGER DEFAULT 0,
                schedule_interval_mins INTEGER DEFAULT 15,
                alert_threshold INTEGER DEFAULT 1,
                alert_severity TEXT DEFAULT 'HIGH',
                last_run_at INTEGER,
                last_result_count INTEGER
            )
        """)
        conn.commit()

        # Seed standard SOC investigation searches if empty
        cursor.execute("SELECT COUNT(*) FROM saved_searches")
        if cursor.fetchone()[0] == 0:
            now = int(time.time())
            seeds = [
                ("src_ip_burst", "High-Frequency Probe IPs", "status>=400 | stats count by source_ip | where count > 10 | sort count desc", "Detects aggressive fuzzing/probing", "admin", 1, 15, 10, "HIGH"),
                ("failed_logons_by_user", "SSH/Auth Brute Force by User", "outcome=fail | stats count by user | where count > 5 | sort count desc", "Flags dictionary attack targets", "admin", 1, 15, 5, "HIGH"),
                ("error_status_spike", "5xx Server Error Bursts", "status>=500 | stats count by target | where count > 3", "Detects application crash induction and command injection", "admin", 1, 10, 3, "CRITICAL"),
            ]
            for s_id, s_name, s_q, s_desc, s_user, is_sched, interval, thresh, sev in seeds:
                cursor.execute("""
                    INSERT INTO saved_searches (id, name, query, description, created_by, created_at, is_scheduled, schedule_interval_mins, alert_threshold, alert_severity)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (s_id, s_name, s_q, s_desc, s_user, now, is_sched, interval, thresh, sev))
            conn.commit()

    def start(self) -> None:
        if self.worker_thread is None or not self.worker_thread.is_alive():
            self.stop_event.clear()
            self.worker_thread = threading.Thread(target=self._run_scheduler_loop, daemon=True, name="ScheduledSearchRunner")
            self.worker_thread.start()

    def stop(self) -> None:
        self.stop_event.set()

    def create_saved_search(
        self,
        name: str,
        query: str,
        description: str = "",
        created_by: str = "analyst",
        is_scheduled: bool = False,
        interval_mins: int = 15,
        alert_threshold: int = 1,
        alert_severity: str = "HIGH"
    ) -> Dict[str, Any]:
        s_id = str(uuid.uuid4())[:8]
        now = int(time.time())
        conn = self.get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO saved_searches (id, name, query, description, created_by, created_at, is_scheduled, schedule_interval_mins, alert_threshold, alert_severity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (s_id, name, query, description, created_by, now, 1 if is_scheduled else 0, interval_mins, alert_threshold, alert_severity))
        conn.commit()
        return self.get_saved_search(s_id)  # type: ignore

    def list_saved_searches(self) -> List[Dict[str, Any]]:
        conn = self.get_db()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, name, query, description, created_by, created_at, is_scheduled, schedule_interval_mins, alert_threshold, alert_severity, last_run_at, last_result_count
            FROM saved_searches ORDER BY created_at DESC
        """)
        rows = cursor.fetchall()
        return [
            {
                "id": r[0],
                "name": r[1],
                "query": r[2],
                "description": r[3],
                "created_by": r[4],
                "created_at": r[5],
                "is_scheduled": bool(r[6]),
                "schedule_interval_mins": r[7],
                "alert_threshold": r[8],
                "alert_severity": r[9],
                "last_run_at": r[10],
                "last_result_count": r[11]
            }
            for r in rows
        ]

    def get_saved_search(self, search_id: str) -> Optional[Dict[str, Any]]:
        conn = self.get_db()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, name, query, description, created_by, created_at, is_scheduled, schedule_interval_mins, alert_threshold, alert_severity, last_run_at, last_result_count
            FROM saved_searches WHERE id = ?
        """, (search_id,))
        r = cursor.fetchone()
        if not r:
            return None
        return {
            "id": r[0],
            "name": r[1],
            "query": r[2],
            "description": r[3],
            "created_by": r[4],
            "created_at": r[5],
            "is_scheduled": bool(r[6]),
            "schedule_interval_mins": r[7],
            "alert_threshold": r[8],
            "alert_severity": r[9],
            "last_run_at": r[10],
            "last_result_count": r[11]
        }

    def delete_saved_search(self, search_id: str) -> bool:
        conn = self.get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM saved_searches WHERE id = ?", (search_id,))
        conn.commit()
        return cursor.rowcount > 0

    def execute_search_now(self, query: str) -> Dict[str, Any]:
        """Runs query against the Indexer piped search endpoint."""
        url = f"{self.indexer_url}/api/search/piped"
        body = json.dumps({"query": query}).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            return {"error": str(e), "total_count": 0, "rows": []}

    def _run_scheduler_loop(self) -> None:
        """Background thread running scheduled searches at their configured interval."""
        while not self.stop_event.is_set():
            time.sleep(30.0)  # Check scheduler every 30s
            now = int(time.time())
            searches = self.list_saved_searches()
            for s in searches:
                if not s["is_scheduled"]:
                    continue
                last_run = s["last_run_at"] or 0
                interval_sec = s["schedule_interval_mins"] * 60
                if now - last_run >= interval_sec:
                    # Run search
                    res = self.execute_search_now(s["query"])
                    count = res.get("total_count", 0)
                    
                    conn = self.get_db()
                    cursor = conn.cursor()
                    cursor.execute("UPDATE saved_searches SET last_run_at = ?, last_result_count = ? WHERE id = ?", (now, count, s["id"]))
                    conn.commit()

                    # Trigger alert if threshold exceeded
                    threshold = s["alert_threshold"]
                    if count >= threshold and self.alert_callback:
                        alert = {
                            "rule_id": 100750,
                            "level": 12 if s["alert_severity"] == "CRITICAL" else (9 if s["alert_severity"] == "HIGH" else 6),
                            "name": f"Scheduled Search Triggered: {s['name']}",
                            "description": f"Query '{s['query']}' matched {count} events (threshold: {threshold}).",
                            "source_ip": "127.0.0.1",
                            "timestamp": now,
                            "channels": ["scheduled_search"],
                            "reasons": [f"Scheduled rule '{s['name']}' fired with {count} hits"],
                            "query": s["query"],
                            "hits": count
                        }
                        try:
                            self.alert_callback(alert)
                        except Exception:
                            pass

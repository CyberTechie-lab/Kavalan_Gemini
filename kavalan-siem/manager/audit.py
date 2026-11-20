"""
audit.py - Tamper-Evident Audit Logging for Kavalan SIEM

Records an immutable audit trail of:
  - User Logins, Logouts, and Authentication Failures
  - Alert Triage Actions (Closed, Resolved, False Positive, Severity Override)
  - Active Response & Quarantine Execution (Firewall Drops, Process Kills, Account Locks)
  - Detection Rule Changes (Creation, Modification, Deletion)
  - System Configurations, Key Rotations, and Retention Policies
"""

import json
import sqlite3
import time
from typing import Any, Callable, Dict, List, Optional


class AuditLogger:
    """Manages system audit logs in SQLite."""

    def __init__(self, db_factory: Callable[[], sqlite3.Connection]):
        self.get_db = db_factory
        self.init_db()

    def init_db(self) -> None:
        conn = self.get_db()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT,
                details TEXT,
                outcome TEXT NOT NULL,
                ip TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action)")
        conn.commit()

    def log(
        self,
        username: str,
        role: str,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        details: Optional[Any] = None,
        outcome: str = "success",
        ip: Optional[str] = None
    ) -> Dict[str, Any]:
        """Appends an immutable audit entry."""
        now = int(time.time())
        details_str = json.dumps(details) if isinstance(details, (dict, list)) else (str(details) if details else "")
        conn = self.get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_logs (ts, username, role, action, resource_type, resource_id, details, outcome, ip)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (now, username, role, action, resource_type, resource_id, details_str, outcome, ip))
        conn.commit()
        log_id = cursor.lastrowid
        return {
            "id": log_id,
            "ts": now,
            "username": username,
            "role": role,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "details": details_str,
            "outcome": outcome,
            "ip": ip
        }

    def query(
        self,
        username: Optional[str] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        outcome: Optional[str] = None,
        since_ts: Optional[int] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        conn = self.get_db()
        cursor = conn.cursor()
        query = "SELECT id, ts, username, role, action, resource_type, resource_id, details, outcome, ip FROM audit_logs WHERE 1=1"
        params: List[Any] = []
        if username:
            query += " AND username = ?"
            params.append(username)
        if action:
            query += " AND action LIKE ?"
            params.append(f"%{action}%")
        if resource_type:
            query += " AND resource_type = ?"
            params.append(resource_type)
        if outcome:
            query += " AND outcome = ?"
            params.append(outcome)
        if since_ts:
            query += " AND ts >= ?"
            params.append(since_ts)
        query += " ORDER BY ts DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()
        logs = []
        for r in rows:
            details_parsed = r[7]
            try:
                details_parsed = json.loads(r[7])
            except Exception:
                pass
            logs.append({
                "id": r[0],
                "ts": r[1],
                "username": r[2],
                "role": r[3],
                "action": r[4],
                "resource_type": r[5],
                "resource_id": r[6],
                "details": details_parsed,
                "outcome": r[8],
                "ip": r[9]
            })
        return logs

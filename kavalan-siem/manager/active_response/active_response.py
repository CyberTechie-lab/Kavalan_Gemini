"""
active_response.py - Active Response Engine for Kavalan SIEM

Triggers automated containment actions when threat levels exceed critical thresholds (Rule Level >= 10).
Supports operator-directed manual containment from SOC dashboard (Firewall Drop, Lock Account, Kill Process).
Dispatches orders to endpoint agents on heartbeat responses for local execution.
"""

import json
import sqlite3
import time
from typing import Any, Dict, List, Optional


class ActiveResponseEngine:
    def __init__(self, db_conn_factory):
        self.get_db = db_conn_factory
        self.init_ar_table()

    def init_ar_table(self):
        con = self.get_db()
        with con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS active_responses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    command TEXT NOT NULL,
                    actor_ip TEXT NOT NULL,
                    rule_id INTEGER NOT NULL,
                    rule_level INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    target_agent TEXT DEFAULT 'all',
                    delivered INTEGER DEFAULT 0,
                    details TEXT DEFAULT ''
                )
            """)
            cols = [r[1] for r in con.execute("PRAGMA table_info(active_responses)").fetchall()]
            if "target_agent" not in cols:
                con.execute("ALTER TABLE active_responses ADD COLUMN target_agent TEXT DEFAULT 'all'")
            if "delivered" not in cols:
                con.execute("ALTER TABLE active_responses ADD COLUMN delivered INTEGER DEFAULT 0")
            if "details" not in cols:
                con.execute("ALTER TABLE active_responses ADD COLUMN details TEXT DEFAULT ''")

            con.execute("CREATE INDEX IF NOT EXISTS idx_ar_ip ON active_responses(actor_ip)")
            con.execute("CREATE INDEX IF NOT EXISTS idx_ar_status ON active_responses(status, delivered)")

    def evaluate_and_respond(self, actor_ip: str, rule_matches: List[Any], agent_id: str = "all") -> Optional[Dict[str, Any]]:
        """If highest fired rule has level >= 10, trigger automated containment."""
        if not rule_matches:
            return None

        # Sort by level descending
        sorted_rules = sorted(rule_matches, key=lambda r: getattr(r, "level", 0), reverse=True)
        top_rule = sorted_rules[0]
        level = getattr(top_rule, "level", 0)
        rule_id = getattr(top_rule, "rule_id", 0)
        description = getattr(top_rule, "description", "")

        if level < 10:
            return None

        command = "firewall-drop" if level >= 12 else "rate-limit-actor"

        con = self.get_db()
        now = int(time.time())
        with con:
            recent = con.execute("""
                SELECT id FROM active_responses
                WHERE actor_ip = ? AND command = ? AND timestamp > ?
            """, (actor_ip, command, now - 300)).fetchone()
            if recent:
                return None

            con.execute("""
                INSERT INTO active_responses (timestamp, command, actor_ip, rule_id, rule_level, reason, status, target_agent, delivered)
                VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, 0)
            """, (now, command, actor_ip, rule_id, level, description, agent_id))

        print(f"[active-response] QUEUED {command} on {actor_ip} [Rule {rule_id} Level {level}]")
        return {
            "command": command,
            "actor_ip": actor_ip,
            "rule_id": rule_id,
            "level": level,
            "action": f"Automated perimeter containment queued for actor {actor_ip}",
        }

    def trigger_manual_response(self, action: str, actor_ip: str, target: str = "",
                                target_agent: str = "all", timeout: int = 600,
                                reason: str = "Manual containment order by SOC Analyst") -> Dict[str, Any]:
        """Manually dispatches an Active Response order from SOC dashboard."""
        con = self.get_db()
        now = int(time.time())
        with con:
            cur = con.execute("""
                INSERT INTO active_responses (timestamp, command, actor_ip, rule_id, rule_level, reason, status, target_agent, delivered)
                VALUES (?, ?, ?, 0, 15, ?, 'pending', ?, 0)
            """, (now, action, actor_ip or target, reason, target_agent))
            row_id = cur.lastrowid

        print(f"[active-response] MANUAL TRIGGER: {action} on {actor_ip or target} for agent {target_agent}")
        return {
            "status": "queued",
            "command_id": f"ar_{row_id}",
            "action": action,
            "target": actor_ip or target,
            "target_agent": target_agent,
            "timestamp": now
        }

    def get_pending_commands(self, agent_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves pending active response commands targeted to an agent or broadcast to all."""
        con = self.get_db()
        now = int(time.time())
        rows = con.execute("""
            SELECT id, command, actor_ip, rule_id, rule_level, reason, timestamp
            FROM active_responses
            WHERE timestamp > ? AND status = 'pending' AND (target_agent = 'all' OR target_agent = ?)
            ORDER BY id ASC
            LIMIT 10
        """, (now - 300, agent_id or "")).fetchall()

        cmds = []
        for r in rows:
            cmds.append({
                "command_id": f"ar_{r['id']}",
                "action": r["command"],
                "actor_ip": r["actor_ip"],
                "target": r["actor_ip"],
                "rule_id": r["rule_id"],
                "level": r["rule_level"],
                "reason": r["reason"],
                "timeout": 600,
            })
        return cmds

    def acknowledge_command(self, command_id: str, status: str, details: str = "") -> bool:
        """Updates containment command status following agent execution feedback."""
        con = self.get_db()
        try:
            cid = int(command_id.replace("ar_", "")) if command_id.startswith("ar_") else int(command_id)
        except ValueError:
            return False

        with con:
            cur = con.execute("""
                UPDATE active_responses
                SET status = ?, delivered = 1, details = ?
                WHERE id = ?
            """, (status, details, cid))
            return cur.rowcount > 0

    def unblock_response(self, ar_id: int) -> bool:
        """Manually releases containment for a given active response ID."""
        con = self.get_db()
        with con:
            row = con.execute("SELECT id, actor_ip, command, target_agent FROM active_responses WHERE id=?", (ar_id,)).fetchone()
            if not row:
                return False
            actor_ip = row["actor_ip"]
            target_agent = row["target_agent"]
            now = int(time.time())

            # Mark old response as unblocked
            con.execute("UPDATE active_responses SET status='unblocked' WHERE id=?", (ar_id,))

            # Queue unblock order to agent
            con.execute("""
                INSERT INTO active_responses (timestamp, command, actor_ip, rule_id, rule_level, reason, status, target_agent, delivered)
                VALUES (?, 'firewall-unblock', ?, 0, 0, 'Manual unblock by SOC Analyst', 'pending', ?, 0)
            """, (now, actor_ip, target_agent))
            return True

    def list_responses(self, limit: int = 50) -> List[Dict[str, Any]]:
        con = self.get_db()
        rows = con.execute("""
            SELECT id, timestamp, command, actor_ip, rule_id, rule_level, reason, status, target_agent, details
            FROM active_responses
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,)).fetchall()

        res = []
        for r in rows:
            res.append({
                "id": r["id"],
                "timestamp": r["timestamp"],
                "command": r["command"],
                "actor_ip": r["actor_ip"],
                "rule_id": r["rule_id"],
                "rule_level": r["rule_level"],
                "reason": r["reason"],
                "status": r["status"],
                "target_agent": r["target_agent"] if "target_agent" in r.keys() else "all",
                "details": r["details"] if "details" in r.keys() else "",
            })
        return res

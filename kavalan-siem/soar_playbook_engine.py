#!/usr/bin/env python3
"""
Kavalan SIEM · Autonomous SOAR Playbook Engine (Tier 2/4)
Event-Condition-Action (ECA) workflow orchestrator for zero-touch incident remediation.
Executes autonomous multi-step containment, automated case creation, and webhooks.
"""

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

_local_soar = threading.local()


class AutonomousSoarPlaybookEngine:
    def __init__(self, db_path: str = "manager.db"):
        p = Path(db_path)
        if not p.is_absolute():
            cur_dir = Path(__file__).resolve().parent
            if (cur_dir / p.name).exists() or not p.exists():
                p = cur_dir / p.name
        self.db_path = str(p.resolve())
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._seed_default_playbooks()

    def _get_con(self) -> sqlite3.Connection:
        attr_name = f"con_{self.db_path}"
        con = getattr(_local_soar, attr_name, None)
        if con is not None:
            try:
                con.execute("SELECT 1")
                return con
            except Exception:
                pass
        con = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        setattr(_local_soar, attr_name, con)
        return con

    def _init_db(self):
        with self._get_con() as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS soar_playbooks (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    trigger_type TEXT NOT NULL DEFAULT 'alert',
                    condition_json TEXT NOT NULL,
                    actions_json TEXT NOT NULL,
                    is_enabled INTEGER NOT NULL DEFAULT 1,
                    execution_count INTEGER NOT NULL DEFAULT 0,
                    last_triggered_at INTEGER,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                )
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS soar_playbook_runs (
                    id TEXT PRIMARY KEY,
                    playbook_id TEXT NOT NULL,
                    playbook_name TEXT NOT NULL,
                    trigger_source TEXT NOT NULL,
                    trigger_entity TEXT,
                    status TEXT NOT NULL,
                    actions_taken_json TEXT NOT NULL,
                    output_log TEXT,
                    executed_at INTEGER NOT NULL
                )
            """)
            con.execute("CREATE INDEX IF NOT EXISTS idx_pb_enabled ON soar_playbooks(is_enabled)")
            con.execute("CREATE INDEX IF NOT EXISTS idx_pb_runs_ts ON soar_playbook_runs(executed_at)")

    def _seed_default_playbooks(self):
        now = int(time.time())
        default_playbooks = [
            {
                "id": "PB-AUTO-001",
                "name": "Auto-Quarantine High-Risk Malicious IOCs",
                "description": "Zero-touch perimeter firewall drop across the fleet when inbound traffic matches verified Threat Intel with Abuse Score >= 80% or Tor Exit Node.",
                "trigger_type": "alert",
                "condition": {
                    "min_threat_score": 80,
                    "or_tor_exit": True
                },
                "actions": [
                    {"action": "active_response", "cmd": "firewall-drop", "target": "source_ip", "target_agent": "all", "timeout": 3600},
                    {"action": "create_case", "severity": "CRITICAL", "title_prefix": "AUTONOMOUS CONTAINMENT: Threat Intel IOC Blocked"},
                    {"action": "dispatch_webhook", "event_type": "threat_intel_auto_quarantine"}
                ]
            },
            {
                "id": "PB-AUTO-002",
                "name": "Rapid Ransomware & Critical FIM Containment",
                "description": "Automatically quarantines compromised files and locks user accounts when critical FIM system tampering is detected (Level >= 12, Impact T1565).",
                "trigger_type": "alert",
                "condition": {
                    "min_level": 12,
                    "tactics_contain": ["Impact", "T1565"]
                },
                "actions": [
                    {"action": "active_response", "cmd": "quarantine-file", "target": "target_file"},
                    {"action": "active_response", "cmd": "account-lock", "target": "user"},
                    {"action": "create_case", "severity": "CRITICAL", "title_prefix": "RANSOMWARE ALERT: File Quarantine Executed"},
                    {"action": "dispatch_webhook", "event_type": "ransomware_fim_quarantine"}
                ]
            },
            {
                "id": "PB-AUTO-003",
                "name": "Distributed SSH Brute Force Suppressor",
                "description": "Throttles high-rate credential dictionary attacks by issuing temporary 1800s firewall drops across auth gateways on Level >= 8 credential guessing bursts.",
                "trigger_type": "alert",
                "condition": {
                    "min_level": 8,
                    "tactics_contain": ["Credential Access", "T1110.001"]
                },
                "actions": [
                    {"action": "active_response", "cmd": "firewall-drop", "target": "source_ip", "timeout": 1800},
                    {"action": "dispatch_webhook", "event_type": "ssh_brute_suppression"}
                ]
            }
        ]

        with self._get_con() as con:
            for pb in default_playbooks:
                con.execute("""
                    INSERT OR IGNORE INTO soar_playbooks (
                        id, name, description, trigger_type, condition_json, actions_json,
                        is_enabled, execution_count, last_triggered_at, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 1, 0, NULL, ?, ?)
                """, (
                    pb["id"], pb["name"], pb["description"], pb["trigger_type"],
                    json.dumps(pb["condition"]), json.dumps(pb["actions"]), now, now
                ))

    def get_playbooks(self) -> List[Dict[str, Any]]:
        with self._get_con() as con:
            rows = con.execute("SELECT * FROM soar_playbooks ORDER BY created_at ASC").fetchall()
            playbooks = []
            for r in rows:
                playbooks.append({
                    "id": r["id"],
                    "name": r["name"],
                    "description": r["description"],
                    "trigger_type": r["trigger_type"],
                    "condition": json.loads(r["condition_json"]) if r["condition_json"] else {},
                    "actions": json.loads(r["actions_json"]) if r["actions_json"] else [],
                    "is_enabled": bool(r["is_enabled"]),
                    "execution_count": r["execution_count"],
                    "last_triggered_at": r["last_triggered_at"],
                    "created_at": r["created_at"],
                    "updated_at": r["updated_at"]
                })
            return playbooks

    def toggle_playbook(self, playbook_id: str, is_enabled: bool) -> Dict[str, Any]:
        now = int(time.time())
        with self._get_con() as con:
            con.execute("UPDATE soar_playbooks SET is_enabled = ?, updated_at = ? WHERE id = ?",
                        (1 if is_enabled else 0, now, playbook_id))
        return {"status": "ok", "playbook_id": playbook_id, "is_enabled": is_enabled}

    def evaluate_alert(self, alert_payload: Dict[str, Any], manager_core) -> List[Dict[str, Any]]:
        """
        Evaluates active SOAR playbooks against an incoming alert and executes matching actions.
        """
        playbooks = self.get_playbooks()
        executed_runs = []
        now = int(time.time())

        lvl_raw = alert_payload.get("level", 0)
        level_map = {"CRITICAL": 12, "HIGH": 8, "MEDIUM": 5, "LOW": 2}
        if isinstance(lvl_raw, str):
            lvl = level_map.get(lvl_raw.upper(), 0)
            if lvl == 0:
                try:
                    lvl = int(lvl_raw)
                except Exception:
                    lvl = 0
        else:
            try:
                lvl = int(lvl_raw)
            except Exception:
                lvl = 0

        rule_lvl_raw = alert_payload.get("rule_level", lvl)
        if isinstance(rule_lvl_raw, str):
            rule_lvl = level_map.get(rule_lvl_raw.upper(), lvl)
            if rule_lvl == lvl:
                try:
                    rule_lvl = int(rule_lvl_raw)
                except Exception:
                    rule_lvl = lvl
        else:
            try:
                rule_lvl = int(rule_lvl_raw)
            except Exception:
                rule_lvl = lvl

        eff_lvl = max(lvl, rule_lvl)
        src_ip = alert_payload.get("source_ip", "")
        summary = alert_payload.get("summary", "")
        tactics = alert_payload.get("tactics", {})
        threat_intel = alert_payload.get("threat_intel") or {}
        ti_score = int(threat_intel.get("threat_score", 0))
        is_tor = bool(threat_intel.get("is_tor_exit", False))

        for pb in playbooks:
            if not pb["is_enabled"]:
                continue

            cond = pb["condition"]
            matched = False

            # Condition 1: Threat Intel threshold
            if "min_threat_score" in cond:
                if ti_score >= cond["min_threat_score"]:
                    matched = True
            if cond.get("or_tor_exit") and is_tor:
                matched = True

            # Condition 2: Min Alert Level
            if "min_level" in cond:
                level_match = eff_lvl >= cond["min_level"]
                if "tactics_contain" in cond:
                    # check tactics match
                    t_str = " ".join(str(k) for k in tactics.keys()).lower() + " " + summary.lower()
                    t_match = any(tc.lower() in t_str for tc in cond["tactics_contain"])
                    if level_match and t_match:
                        matched = True
                elif level_match:
                    matched = True

            if matched:
                # Deduplication cooldown: do not re-run same playbook on same entity within 300 seconds
                cooldown_sec = 300
                entity = src_ip or alert_payload.get("target") or "fleet"
                with self._get_con() as con:
                    recent = con.execute("""
                        SELECT id FROM soar_playbook_runs
                        WHERE playbook_id = ? AND trigger_entity = ? AND executed_at > ?
                    """, (pb["id"], entity, now - cooldown_sec)).fetchone()
                if recent:
                    continue

                run_res = self._execute_playbook_actions(pb, alert_payload, manager_core, trigger_source="alert_correlation")
                executed_runs.append(run_res)

        return executed_runs

    def run_manual(self, playbook_id: str, target: str, manager_core) -> Dict[str, Any]:
        with self._get_con() as con:
            row = con.execute("SELECT * FROM soar_playbooks WHERE id = ?", (playbook_id,)).fetchone()
            if not row:
                return {"error": f"Playbook {playbook_id} not found"}
            pb = {
                "id": row["id"],
                "name": row["name"],
                "description": row["description"],
                "actions": json.loads(row["actions_json"]) if row["actions_json"] else []
            }

        mock_alert = {
            "source_ip": target,
            "target": target,
            "level": 12,
            "summary": f"Manual SOAR Execution of [{pb['name']}] against {target}",
            "tactics": {"Manual": 1}
        }
        return self._execute_playbook_actions(pb, mock_alert, manager_core, trigger_source="manual_simulation")

    def _execute_playbook_actions(self, pb: Dict[str, Any], alert_payload: Dict[str, Any],
                                  manager_core, trigger_source: str) -> Dict[str, Any]:
        now = int(time.time())
        actions_taken = []
        src_ip = alert_payload.get("source_ip", "")
        tgt = alert_payload.get("target", src_ip)
        user = alert_payload.get("user") or alert_payload.get("account") or "root"
        actions = pb.get("actions", [])

        for act in actions:
            act_type = act.get("action")
            cmd = act.get("cmd", "")

            if act_type == "active_response":
                timeout = act.get("timeout", 600)
                ar_target = src_ip if act.get("target") == "source_ip" else (user if act.get("target") == "user" else tgt)
                if ar_target and manager_core:
                    try:
                        if hasattr(manager_core, "queue_active_response"):
                            res = manager_core.queue_active_response(
                                command=cmd,
                                target=ar_target,
                                target_agent=act.get("target_agent", "all"),
                                timeout=timeout,
                                reason=f"Autonomous SOAR Playbook [{pb['name']}]"
                            )
                        elif hasattr(manager_core, "ar_engine"):
                            res = manager_core.ar_engine.trigger_manual_response(
                                action=cmd,
                                actor_ip=ar_target,
                                target=ar_target,
                                target_agent=act.get("target_agent", "all"),
                                timeout=timeout,
                                reason=f"Autonomous SOAR Playbook [{pb['name']}]"
                            )
                        else:
                            res = {"status": "ok", "id": "local"}
                        actions_taken.append(f"Active Response executed: {cmd} on {ar_target} (ID: {res.get('id', 'N/A')})")
                    except Exception as e:
                        actions_taken.append(f"Active Response {cmd} error: {str(e)}")

            elif act_type == "create_case":
                title_prefix = act.get("title_prefix", "Autonomous Incident")
                sev = act.get("severity", "HIGH")
                if manager_core:
                    try:
                        case_res = manager_core.create_case(
                            title=f"{title_prefix} - {src_ip or tgt}",
                            description=f"Auto-generated by SOAR Playbook '{pb['name']}'. Summary: {alert_payload.get('summary', 'Threat detected')}",
                            severity=sev,
                            entities={"ips": [src_ip] if src_ip else [], "hosts": [], "users": [user] if user else []},
                            assignee="Autonomous SOAR Orchestrator"
                        )
                        actions_taken.append(f"Incident Case opened: {case_res.get('id')} ({sev})")
                    except Exception as e:
                        actions_taken.append(f"Case creation error: {str(e)}")

            elif act_type == "dispatch_webhook":
                if manager_core:
                    try:
                        ev_type = act.get("event_type", "soar_playbook_action")
                        if hasattr(manager_core, "dispatch_webhook"):
                            manager_core.dispatch_webhook(ev_type, {
                                "title": f"SOAR Playbook [{pb['name']}] Executed",
                                "target": ar_target or src_ip,
                                "playbook_id": pb.get("id"),
                                "alert": alert_payload
                            })
                            actions_taken.append(f"Webhook notification dispatched ({ev_type})")
                    except Exception as e:
                        actions_taken.append(f"Webhook error: {str(e)}")

        run_id = f"RUN-{int(time.time() * 1000) % 1000000:06d}"
        with self._get_con() as con:
            con.execute("""
                INSERT INTO soar_playbook_runs (
                    id, playbook_id, playbook_name, trigger_source, trigger_entity,
                    status, actions_taken_json, output_log, executed_at
                ) VALUES (?, ?, ?, ?, ?, 'SUCCESS', ?, ?, ?)
            """, (
                run_id, pb["id"], pb["name"], trigger_source, src_ip or tgt,
                json.dumps(actions_taken), "; ".join(actions_taken), now
            ))
            con.execute("""
                UPDATE soar_playbooks
                SET execution_count = execution_count + 1, last_triggered_at = ?
                WHERE id = ?
            """, (now, pb["id"]))

        return {
            "run_id": run_id,
            "playbook_id": pb["id"],
            "playbook_name": pb["name"],
            "trigger_source": trigger_source,
            "trigger_entity": src_ip or tgt,
            "status": "SUCCESS",
            "actions_taken": actions_taken,
            "executed_at": now
        }

    def get_recent_runs(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._get_con() as con:
            rows = con.execute("""
                SELECT * FROM soar_playbook_runs ORDER BY executed_at DESC LIMIT ?
            """, (limit,)).fetchall()
            runs = []
            for r in rows:
                runs.append({
                    "id": r["id"],
                    "playbook_id": r["playbook_id"],
                    "playbook_name": r["playbook_name"],
                    "trigger_source": r["trigger_source"],
                    "trigger_entity": r["trigger_entity"],
                    "status": r["status"],
                    "actions_taken": json.loads(r["actions_taken_json"]) if r["actions_taken_json"] else [],
                    "output_log": r["output_log"],
                    "executed_at": r["executed_at"]
                })
            return runs

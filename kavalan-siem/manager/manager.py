#!/usr/bin/env python3
"""
manager.py - Kavalan SIEM Central Manager (Tier 2)

The brain of the distributed SIEM architecture.
High-performance, ultra-lightweight SIEM Manager (<35MB RAM).

Responsibilities:
  1. Agent Enrollment & Fleet Keepalive tracking (active vs disconnected)
  2. Multi-agent event ingestion & CEM decoding
  3. Kavalan deterministic behavioral detection & cross-source correlation
  4. MITRE ATT&CK tactic enrichment
  5. Alert dispatch to Indexer (Tier 3)
"""

import argparse
import json
import os
import sqlite3
import sys
import threading
import time
import urllib.request
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add paths to detector and kavalan_multi
CURRENT_DIR = Path(__file__).resolve().parent
SIEM_ROOT = CURRENT_DIR.parent
KAVALAN_ML_DIR = SIEM_ROOT.parent / "kavalan-ml"
for p in (str(CURRENT_DIR), str(SIEM_ROOT), str(KAVALAN_ML_DIR)):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

import detector
import kavalan_multi
from cem import CEMEvent, validate_event
from decoders.decoders import DecoderPipeline
from rules.ai_agent_rules import AIAgentRuleEngine
from rules.kavalan_rules import KavalanRuleEngine
from rules.sigma_converter import SigmaRuleConverter
from active_response.active_response import ActiveResponseEngine
from ai.ai_analyst import AIAttackAnalyst
from gemini.service import GeminiAIService
from sec_llm.service import SecLLMService
from vuln_scanner import VulnerabilityEngine
from auth import AuthManager
from audit import AuditLogger
from security import AgentSecurityManager
from quiet_source_monitor import QuietSourceMonitor
from saved_searches import SavedSearchManager
from cert_in_compliance import generate_cert_in_report
from schema_mapper import cem_to_ocsf, cem_to_ecs
from fastapi import FastAPI, Request, status, Header, Depends
from fastapi.responses import JSONResponse, PlainTextResponse
import uvicorn


MITRE_MAPPING = {
    "recon_files": {"id": "T1595.002", "name": "Vulnerability Scanning", "tactic": "Reconnaissance"},
    "path_guessing": {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"},
    "protected_resource_probing": {"id": "T1069", "name": "Permission Groups Discovery", "tactic": "Discovery"},
    "sql_injection": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "command_injection": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "path_traversal": {"id": "T1006", "name": "Direct Volume Access", "tactic": "Defense Evasion"},
    "ssrf": {"id": "T1090", "name": "Proxy/Connection Proxy", "tactic": "Command and Control"},
    "credential_guessing": {"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"},
    "ssh_credential_guessing": {"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"},
    "ssh_login_success": {"id": "T1078", "name": "Valid Accounts", "tactic": "Persistence"},
}


try:
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(10240, hard), hard))
except Exception:
    pass

_local_mgr = threading.local()


def get_db(db_path: str) -> sqlite3.Connection:
    con = getattr(_local_mgr, "con", None)
    current_path = getattr(_local_mgr, "db_path", None)
    is_closed = False
    if con is not None:
        try:
            con.execute("SELECT 1")
        except Exception:
            is_closed = True
    if con is None or is_closed or current_path != db_path:
        if con is not None:
            try:
                con.close()
            except Exception:
                pass
        con = sqlite3.connect(db_path, check_same_thread=False, timeout=30.0)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode = WAL")
        con.execute("PRAGMA synchronous = NORMAL")
        con.execute("PRAGMA cache_size = -64000")  # 64MB cache
        con.execute("PRAGMA temp_store = MEMORY")
        _local_mgr.con = con
        _local_mgr.db_path = db_path
    return con


def init_db(db_path: str) -> None:
    con = get_db(db_path)
    with con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                ip TEXT NOT NULL,
                os TEXT,
                registered_at INTEGER NOT NULL,
                last_keepalive INTEGER NOT NULL,
                status TEXT DEFAULT 'active',
                metrics_json TEXT
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS local_events (
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
                raw TEXT,
                meta_json TEXT
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS agent_configs (
                agent_id TEXT PRIMARY KEY,
                config_json TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                updated_at INTEGER NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS incident_cases (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL DEFAULT 'HIGH',
                status TEXT NOT NULL DEFAULT 'NEW',
                assignee TEXT DEFAULT 'Unassigned',
                entities_json TEXT DEFAULT '{}',
                playbooks_run_json TEXT DEFAULT '[]',
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS case_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                author TEXT NOT NULL DEFAULT 'SOC Analyst',
                note TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS webhook_configs (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                type TEXT NOT NULL DEFAULT 'generic',
                min_level TEXT NOT NULL DEFAULT 'HIGH',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS custom_rules (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                level INTEGER NOT NULL DEFAULT 7,
                log_type TEXT NOT NULL DEFAULT '*',
                rule_json TEXT NOT NULL,
                raw_sigma TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_mgr_ev_ts ON local_events(timestamp)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_mgr_ev_src ON local_events(source_ip)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_cases_status ON incident_cases(status)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_case_notes_id ON case_notes(case_id)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_custom_rules_level ON custom_rules(level)")

        # Seed initial production Sigma templates if custom_rules table is empty
        try:
            cnt_row = con.execute("SELECT COUNT(*) as cnt FROM custom_rules").fetchone()
            if cnt_row and cnt_row["cnt"] == 0:
                now_ts = int(time.time())
                start_id = 200001
                for tmpl in SigmaRuleConverter.get_templates():
                    try:
                        converted = SigmaRuleConverter.convert(tmpl["yaml"], rule_id=start_id)
                        con.execute("""
                            INSERT INTO custom_rules (id, name, title, description, level, log_type, rule_json, raw_sigma, enabled, created_at, updated_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                        """, (
                            converted["id"],
                            converted["name"],
                            converted["title"],
                            converted.get("description", ""),
                            converted.get("level", 7),
                            converted.get("log_type", "*"),
                            json.dumps(converted),
                            tmpl["yaml"],
                            now_ts,
                            now_ts,
                        ))
                        start_id += 1
                    except Exception:
                        pass
        except Exception:
            pass


class ManagerCore:
    def __init__(self, db_path: str, indexer_url: str = "http://127.0.0.1:8920",
                 window_minutes: int = 15, interval: int = 5):
        self.db_path = db_path
        self.indexer_url = indexer_url.rstrip("/")
        self.window_minutes = window_minutes
        self.interval = interval
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.worker_thread: Optional[threading.Thread] = None
        self.decoder_pipeline = DecoderPipeline()
        self.rule_engine = AIAgentRuleEngine()
        self.kavalan_rules = KavalanRuleEngine()
        self.agent_tx: Dict[str, int] = {}
        self.ar_engine = ActiveResponseEngine(lambda: get_db(self.db_path))
        self.gemini = GeminiAIService()
        self.sec_llm = self.gemini
        self.ai_analyst = AIAttackAnalyst(gemini_service=self.gemini)
        self.vuln_engine = VulnerabilityEngine(lambda: get_db(self.db_path))
        self.auth = AuthManager(lambda: get_db(self.db_path))
        self.audit = AuditLogger(lambda: get_db(self.db_path))
        self.agent_sec = AgentSecurityManager(lambda: get_db(self.db_path))
        self.quiet_monitor = QuietSourceMonitor(
            alert_callback=self._handle_background_alert,
            quiet_threshold_sec=300
        )
        self.saved_searches = SavedSearchManager(
            db_factory=lambda: get_db(self.db_path),
            indexer_url=self.indexer_url,
            alert_callback=self._handle_background_alert
        )
        try:
            from threat_intel import ThreatIntelEngine
            indexer_db_path = str(SIEM_ROOT / "indexer.db")
            self.threat_intel = ThreatIntelEngine(indexer_db_path)
        except Exception:
            self.threat_intel = None
        try:
            from soar_playbook_engine import AutonomousSoarPlaybookEngine
            self.soar_engine = AutonomousSoarPlaybookEngine(self.db_path)
        except Exception:
            self.soar_engine = None
        self.state: Dict[str, Any] = {
            "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0},
            "sources": [],
            "alerts": [],
            "active_agents": 0,
            "total_agents": 0,
            "last_scan": None,
        }
        self.load_custom_rules()

    # --- Custom Detection Rule Studio & Sigma Management ---

    def load_custom_rules(self) -> List[Dict[str, Any]]:
        try:
            con = get_db(self.db_path)
            rows = con.execute("""
                SELECT id, name, title, description, level, log_type, rule_json, raw_sigma, enabled, created_at, updated_at
                FROM custom_rules ORDER BY id ASC
            """).fetchall()
            loaded: List[Dict[str, Any]] = []
            for r in rows:
                try:
                    rule = json.loads(r["rule_json"]) if r["rule_json"] else {}
                    rule["id"] = r["id"]
                    rule["name"] = r["name"]
                    rule["title"] = r["title"]
                    rule["description"] = r["description"]
                    rule["level"] = r["level"]
                    rule["log_type"] = r["log_type"]
                    rule["raw_sigma"] = r["raw_sigma"]
                    rule["enabled"] = bool(r["enabled"])
                    rule["created_at"] = r["created_at"]
                    rule["updated_at"] = r["updated_at"]
                    loaded.append(rule)
                except Exception:
                    continue
            self.kavalan_rules.set_custom_rules(loaded)
            return loaded
        except Exception:
            return []

    def get_custom_rules(self) -> List[Dict[str, Any]]:
        return self.load_custom_rules()

    def save_custom_rule(self, rule_data: Dict[str, Any], raw_sigma: Optional[str] = None) -> Dict[str, Any]:
        valid, err_msg = SigmaRuleConverter.validate_kavalan_rule(rule_data)
        if not valid:
            raise ValueError(f"Invalid rule schema: {err_msg}")

        con = get_db(self.db_path)
        now_ts = int(time.time())
        rule_id = rule_data.get("id")
        with con:
            if not rule_id:
                max_row = con.execute("SELECT MAX(id) as max_id FROM custom_rules").fetchone()
                max_id = max_row["max_id"] if (max_row and max_row["max_id"]) else 200000
                rule_id = max(200001, max_id + 1)
                rule_data["id"] = rule_id

            name = rule_data.get("name") or f"custom_rule_{rule_id}"
            title = rule_data.get("title", f"Custom Rule {rule_id}")
            desc = rule_data.get("description", "")
            level = int(rule_data.get("level", 7))
            log_type = rule_data.get("log_type", "*")
            enabled = 1 if rule_data.get("enabled", True) else 0

            con.execute("""
                INSERT INTO custom_rules (id, name, title, description, level, log_type, rule_json, raw_sigma, enabled, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    title=excluded.title,
                    description=excluded.description,
                    level=excluded.level,
                    log_type=excluded.log_type,
                    rule_json=excluded.rule_json,
                    raw_sigma=COALESCE(excluded.raw_sigma, custom_rules.raw_sigma),
                    enabled=excluded.enabled,
                    updated_at=excluded.updated_at
            """, (
                rule_id,
                name,
                title,
                desc,
                level,
                log_type,
                json.dumps(rule_data),
                raw_sigma or rule_data.get("raw_sigma", ""),
                enabled,
                now_ts,
                now_ts,
            ))
        self.load_custom_rules()
        return rule_data

    def delete_custom_rule(self, rule_id: int) -> bool:
        con = get_db(self.db_path)
        with con:
            cur = con.execute("DELETE FROM custom_rules WHERE id=?", (rule_id,))
            deleted = cur.rowcount > 0
        self.load_custom_rules()
        return deleted

    def toggle_custom_rule(self, rule_id: int) -> Dict[str, Any]:
        con = get_db(self.db_path)
        now_ts = int(time.time())
        with con:
            cur = con.execute("""
                UPDATE custom_rules
                SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END,
                    updated_at = ?
                WHERE id = ?
            """, (now_ts, rule_id))
            if cur.rowcount == 0:
                raise ValueError(f"Rule {rule_id} not found")
            row = con.execute("SELECT enabled FROM custom_rules WHERE id=?", (rule_id,)).fetchone()
            new_enabled = bool(row["enabled"])
        self.load_custom_rules()
        return {"id": rule_id, "enabled": new_enabled}

    def test_custom_rule(self, rule_candidate: Dict[str, Any], log_line: str, host: str = "logtest-host") -> Dict[str, Any]:
        ev = self.decoder_pipeline.decode_line(log_line, host=host)
        if not ev:
            return {
                "decoded": False,
                "raw": log_line,
                "matched": False,
                "message": "No decoder recognized this log format. Try auth, web, fim, or syslog formats.",
            }

        ev_dict = ev.to_dict()
        event_log_type = ev_dict.get("log_type", "")
        expected_type = rule_candidate.get("log_type", "*")

        type_match = True
        if expected_type and expected_type != "*" and expected_type != event_log_type:
            type_match = False

        conditions = rule_candidate.get("match") or {}
        details = []
        all_matched = type_match

        for k, expected in conditions.items():
            matched = self.kavalan_rules._check_field_match(ev_dict, k, expected)
            field_name = k.split("|")[0]
            actual_val = ev_dict.get(field_name)
            if actual_val is None and "meta" in ev_dict and isinstance(ev_dict["meta"], dict):
                actual_val = ev_dict["meta"].get(field_name)
            details.append({
                "condition": k,
                "expected": expected,
                "actual": actual_val,
                "matched": matched,
            })
            if not matched:
                all_matched = False

        return {
            "decoded": True,
            "decoder": ev_dict.get("meta", {}).get("decoder", "unknown"),
            "event": ev_dict,
            "matched": all_matched,
            "type_matched": type_match,
            "condition_details": details,
            "rule_id": rule_candidate.get("id", 200001),
            "level": rule_candidate.get("level", 7),
            "mitre_id": rule_candidate.get("mitre_id"),
            "mitre_tactic": rule_candidate.get("mitre_tactic"),
            "active_response_triggered": all_matched and (int(rule_candidate.get("level", 7)) >= 10),
        }

    def queue_active_response(self, command: str, target: str, actor_ip: str = "",
                              target_agent: str = "all", timeout: int = 600, reason: str = "") -> Dict[str, Any]:
        ip = actor_ip or target
        return self.ar_engine.trigger_manual_response(
            action=command, actor_ip=ip, target=target,
            target_agent=target_agent, timeout=timeout, reason=reason
        )

    # --- Agent Fleet Lifecycle ---

    def register_agent(self, name: str, ip: str, os_name: str) -> Dict[str, Any]:
        con = get_db(self.db_path)
        with con:
            # Check if existing by name
            existing = con.execute("SELECT id FROM agents WHERE name=?", (name,)).fetchone()
            now = int(time.time())
            if existing:
                agent_id = existing[0]
                con.execute("UPDATE agents SET ip=?, os=?, last_keepalive=?, status='active' WHERE id=?",
                            (ip, os_name, now, agent_id))
            else:
                count = con.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
                agent_id = f"{count + 1:03d}"
                con.execute("""
                    INSERT INTO agents (id, name, ip, os, registered_at, last_keepalive, status, metrics_json)
                    VALUES (?, ?, ?, ?, ?, ?, 'active', '{}')
                """, (agent_id, name, ip, os_name, now, now))
        auth_key = self.agent_sec.get_or_create_agent_key(agent_id)
        try:
            self.quiet_monitor.record_heartbeat(agent_id, name, ip)
        except Exception:
            pass
        return {"agent_id": agent_id, "name": name, "status": "active", "auth_key": auth_key}

    def heartbeat_agent(self, agent_id: str, metrics: Optional[Dict] = None) -> bool:
        con = get_db(self.db_path)
        now = int(time.time())
        m = metrics or {}
        new_ip = m.get("ip")
        with con:
            if new_ip and new_ip != "127.0.0.1":
                cur = con.execute("UPDATE agents SET last_keepalive=?, status='active', ip=?, metrics_json=? WHERE id=?",
                                  (now, new_ip, json.dumps(m), agent_id))
            else:
                cur = con.execute("UPDATE agents SET last_keepalive=?, status='active', metrics_json=? WHERE id=?",
                                  (now, json.dumps(m), agent_id))
            updated = cur.rowcount > 0
        try:
            row = con.execute("SELECT name, ip FROM agents WHERE id=?", (agent_id,)).fetchone()
            if row:
                self.quiet_monitor.record_heartbeat(agent_id, row[0], row[1])
        except Exception:
            pass
        return updated

    def check_agent_keepalives(self) -> None:
        con = get_db(self.db_path)
        now = int(time.time())
        # Disconnect after 60 seconds of missing keepalive
        cutoff = now - 60
        with con:
            con.execute("UPDATE agents SET status='disconnected' WHERE last_keepalive < ? AND status='active'", (cutoff,))

    def list_agents(self) -> List[Dict[str, Any]]:
        self.check_agent_keepalives()
        con = get_db(self.db_path)
        rows = con.execute("SELECT id, name, ip, os, registered_at, last_keepalive, status, metrics_json FROM agents ORDER BY id ASC").fetchall()

        agents = []
        for r in rows:
            m = json.loads(r["metrics_json"]) if r["metrics_json"] else {}
            display_ip = m.get("ip") if (m.get("ip") and m.get("ip") != "127.0.0.1") else r["ip"]
            agents.append({
                "id": r["id"],
                "name": r["name"],
                "ip": display_ip,
                "os": r["os"],
                "registered_at": r["registered_at"],
                "last_keepalive": r["last_keepalive"],
                "status": r["status"],
                "metrics": m,
            })
        return agents

    def delete_agent(self, agent_id: str) -> bool:
        con = get_db(self.db_path)
        with con:
            cur = con.execute("DELETE FROM agents WHERE id=?", (agent_id,))
            con.execute("DELETE FROM agent_configs WHERE agent_id=?", (agent_id,))
            con.execute("DELETE FROM agent_sca_reports WHERE agent_id=?", (agent_id,))
            con.execute("DELETE FROM agent_vulnerabilities WHERE agent_id=?", (agent_id,))
            deleted = cur.rowcount > 0
            if agent_id in self.agent_tx:
                del self.agent_tx[agent_id]
        return deleted

    # --- Agent Configuration Management ---

    def get_default_config(self) -> Dict[str, Any]:
        return {
            "localfiles": [
                {"location": "/var/log/auth.log", "format": "auth"},
                {"location": "/var/log/nginx/access.log", "format": "web"}
            ],
            "syscheck": {
                "directories": ["/etc", "/bin", "/sbin", "/usr/bin"],
                "interval": 60
            },
            "syscollector": {
                "interval": 300,
                "scan_on_start": True
            },
            "active_response": {
                "enabled": True
            }
        }

    def get_agent_config(self, agent_id: str) -> Dict[str, Any]:
        con = get_db(self.db_path)
        row = con.execute("SELECT config_json, version, updated_at FROM agent_configs WHERE agent_id=?", (agent_id,)).fetchone()
        if row:
            return {
                "agent_id": agent_id,
                "version": row["version"],
                "updated_at": row["updated_at"],
                "config": json.loads(row["config_json"])
            }
        def_cfg = self.get_default_config()
        now = int(time.time())
        with con:
            con.execute("""
                INSERT INTO agent_configs (agent_id, config_json, version, updated_at)
                VALUES (?, ?, 1, ?)
                ON CONFLICT(agent_id) DO NOTHING
            """, (agent_id, json.dumps(def_cfg), now))
        return {
            "agent_id": agent_id,
            "version": 1,
            "updated_at": now,
            "config": def_cfg
        }

    def set_agent_config(self, agent_id: str, new_config: Dict[str, Any]) -> Dict[str, Any]:
        con = get_db(self.db_path)
        now = int(time.time())
        with con:
            row = con.execute("SELECT version FROM agent_configs WHERE agent_id=?", (agent_id,)).fetchone()
            next_ver = (row["version"] + 1) if row else 1
            con.execute("""
                INSERT INTO agent_configs (agent_id, config_json, version, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    config_json=excluded.config_json,
                    version=excluded.version,
                    updated_at=excluded.updated_at
            """, (agent_id, json.dumps(new_config), next_ver, now))
        return {
            "status": "ok",
            "agent_id": agent_id,
            "version": next_ver,
            "updated_at": now,
            "config": new_config
        }

    # --- SOAR Incident Cases & Playbooks ---

    def create_case(self, title: str, description: str = "", severity: str = "HIGH",
                    entities: Optional[Dict[str, Any]] = None, assignee: str = "Unassigned") -> Dict[str, Any]:
        con = get_db(self.db_path)
        now = int(time.time())
        entities_data = entities or {"ips": [], "hosts": [], "users": []}
        with con:
            count = con.execute("SELECT COUNT(*) FROM incident_cases").fetchone()[0]
            case_id = f"CASE-{count + 1:04d}"
            con.execute("""
                INSERT INTO incident_cases (id, title, description, severity, status, assignee, entities_json, playbooks_run_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'NEW', ?, ?, '[]', ?, ?)
            """, (case_id, title, description, severity.upper(), assignee, json.dumps(entities_data), now, now))

            initial_note = f"Case opened with severity {severity.upper()}. Assigned to {assignee}."
            if entities_data.get("ips"):
                initial_note += f" Impacted IPs: {', '.join(entities_data['ips'])}."
            con.execute("""
                INSERT INTO case_notes (case_id, author, note, created_at)
                VALUES (?, 'System SOAR', ?, ?)
            """, (case_id, initial_note, now))

        case_obj = {
            "id": case_id,
            "title": title,
            "description": description,
            "severity": severity.upper(),
            "status": "NEW",
            "assignee": assignee,
            "entities": entities_data,
            "playbooks_run": [],
            "notes_count": 1,
            "created_at": now,
            "updated_at": now,
        }
        self.dispatch_webhook("case_created", case_obj)
        return case_obj

    def list_cases(self, status: Optional[str] = None, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        con = get_db(self.db_path)
        filters = []
        params = []
        if status:
            filters.append("c.status = ?")
            params.append(status.upper())
        if severity:
            filters.append("c.severity = ?")
            params.append(severity.upper())
        where = " WHERE " + " AND ".join(filters) if filters else ""
        sql = f"""
            SELECT c.id, c.title, c.description, c.severity, c.status, c.assignee,
                   c.entities_json, c.playbooks_run_json, c.created_at, c.updated_at,
                   COUNT(n.id) as notes_count
            FROM incident_cases c
            LEFT JOIN case_notes n ON c.id = n.case_id
            {where}
            GROUP BY c.id
            ORDER BY c.updated_at DESC
        """
        rows = con.execute(sql, params).fetchall()
        cases = []
        for r in rows:
            cases.append({
                "id": r["id"],
                "title": r["title"],
                "description": r["description"],
                "severity": r["severity"],
                "status": r["status"],
                "assignee": r["assignee"],
                "entities": json.loads(r["entities_json"]) if r["entities_json"] else {},
                "playbooks_run": json.loads(r["playbooks_run_json"]) if r["playbooks_run_json"] else [],
                "notes_count": r["notes_count"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            })
        return cases

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        con = get_db(self.db_path)
        row = con.execute("""
            SELECT id, title, description, severity, status, assignee, entities_json, playbooks_run_json, created_at, updated_at
            FROM incident_cases WHERE id = ?
        """, (case_id,)).fetchone()
        if not row:
            return None
        notes_rows = con.execute("""
            SELECT id, author, note, created_at FROM case_notes WHERE case_id = ? ORDER BY created_at ASC
        """, (case_id,)).fetchall()
        notes = [{
            "id": nr["id"],
            "author": nr["author"],
            "note": nr["note"],
            "created_at": nr["created_at"]
        } for nr in notes_rows]
        return {
            "id": row["id"],
            "title": row["title"],
            "description": row["description"],
            "severity": row["severity"],
            "status": row["status"],
            "assignee": row["assignee"],
            "entities": json.loads(row["entities_json"]) if row["entities_json"] else {},
            "playbooks_run": json.loads(row["playbooks_run_json"]) if row["playbooks_run_json"] else [],
            "notes": notes,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def update_case_status(self, case_id: str, new_status: str, assignee: Optional[str] = None,
                           note: Optional[str] = None) -> Optional[Dict[str, Any]]:
        con = get_db(self.db_path)
        now = int(time.time())
        new_status = new_status.upper()
        with con:
            cur = con.execute("SELECT status, assignee FROM incident_cases WHERE id = ?", (case_id,)).fetchone()
            if not cur:
                return None
            old_status = cur["status"]
            final_assignee = assignee if assignee is not None else cur["assignee"]
            con.execute("""
                UPDATE incident_cases SET status = ?, assignee = ?, updated_at = ? WHERE id = ?
            """, (new_status, final_assignee, now, case_id))

            note_text = f"Status updated: {old_status} ➔ {new_status}."
            if assignee and assignee != cur["assignee"]:
                note_text += f" Assignee changed to {assignee}."
            if note:
                note_text += f" Note: {note}"
            con.execute("""
                INSERT INTO case_notes (case_id, author, note, created_at)
                VALUES (?, 'SOC Operator', ?, ?)
            """, (case_id, note_text, now))

        updated_case = self.get_case(case_id)
        if updated_case:
            self.dispatch_webhook("case_status_changed", updated_case)
        return updated_case

    def add_case_note(self, case_id: str, note: str, author: str = "SOC Analyst") -> Dict[str, Any]:
        con = get_db(self.db_path)
        now = int(time.time())
        with con:
            con.execute("""
                INSERT INTO case_notes (case_id, author, note, created_at)
                VALUES (?, ?, ?, ?)
            """, (case_id, author, note, now))
            con.execute("UPDATE incident_cases SET updated_at = ? WHERE id = ?", (now, case_id))
        return {"status": "ok", "case_id": case_id, "author": author, "created_at": now}

    def run_case_playbook(self, case_id: str, playbook: str, target: Optional[str] = None) -> Dict[str, Any]:
        case = self.get_case(case_id)
        if not case:
            return {"error": f"Case {case_id} not found"}
        entities = case.get("entities", {})
        ips = entities.get("ips", [])
        users = entities.get("users", [])
        now = int(time.time())
        actions_taken = []

        if playbook == "perimeter-drop":
            target_ips = [target] if target else ips
            if not target_ips:
                return {"error": "No IP addresses specified in case entities for perimeter drop"}
            for ip in target_ips:
                res = self.ar_engine.trigger_manual_response(
                    "firewall-drop", actor_ip=ip, target_agent="all",
                    reason=f"SOAR Playbook [Perimeter Drop] for {case_id}"
                )
                actions_taken.append(f"Blocked IP {ip} across fleet")

        elif playbook == "account-lock":
            target_users = [target] if target else users
            if not target_users:
                return {"error": "No usernames specified in case entities for account lock"}
            for user in target_users:
                res = self.ar_engine.trigger_manual_response(
                    "account-lock", actor_ip="127.0.0.1", target=user, target_agent="all",
                    reason=f"SOAR Playbook [Account Lock] for {case_id}"
                )
                actions_taken.append(f"Locked user account '{user}' across fleet")

        elif playbook == "full-containment":
            for ip in ips:
                self.ar_engine.trigger_manual_response(
                    "firewall-drop", actor_ip=ip, target_agent="all",
                    reason=f"SOAR Playbook [Full Containment] for {case_id}"
                )
                actions_taken.append(f"Blocked IP {ip}")
            for user in users:
                self.ar_engine.trigger_manual_response(
                    "account-lock", actor_ip="127.0.0.1", target=user, target_agent="all",
                    reason=f"SOAR Playbook [Full Containment] for {case_id}"
                )
                actions_taken.append(f"Locked user account '{user}'")
            # Update status to CONTAINED
            self.update_case_status(case_id, "CONTAINED", note="Automated Full Containment Playbook successfully applied.")
            actions_taken.append("Updated case status to CONTAINED")
        else:
            return {"error": f"Unknown playbook: {playbook}"}

        con = get_db(self.db_path)
        playbook_record = {
            "playbook": playbook,
            "executed_at": now,
            "actions": actions_taken
        }
        with con:
            cur = con.execute("SELECT playbooks_run_json FROM incident_cases WHERE id=?", (case_id,)).fetchone()
            existing_p = json.loads(cur[0]) if cur and cur[0] else []
            existing_p.append(playbook_record)
            con.execute("UPDATE incident_cases SET playbooks_run_json = ?, updated_at = ? WHERE id = ?",
                        (json.dumps(existing_p), now, case_id))
            con.execute("""
                INSERT INTO case_notes (case_id, author, note, created_at)
                VALUES (?, 'SOAR Orchestrator', ?, ?)
            """, (case_id, f"Executed playbook [{playbook}]: " + "; ".join(actions_taken), now))

        res_data = {"status": "ok", "case_id": case_id, "playbook": playbook, "actions": actions_taken, "timestamp": now}
        self.dispatch_webhook("playbook_executed", res_data)
        return res_data

    # --- Outbound SOAR Webhooks ---

    def save_webhook(self, name: str, url: str, hook_type: str = "generic", min_level: str = "HIGH", enabled: bool = True) -> Dict[str, Any]:
        con = get_db(self.db_path)
        now = int(time.time())
        import hashlib
        hook_id = hashlib.sha256(url.encode()).hexdigest()[:10]
        with con:
            con.execute("""
                INSERT INTO webhook_configs (id, name, url, type, min_level, enabled, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    url=excluded.url,
                    type=excluded.type,
                    min_level=excluded.min_level,
                    enabled=excluded.enabled
            """, (hook_id, name, url, hook_type.lower(), min_level.upper(), 1 if enabled else 0, now))
        return {"id": hook_id, "name": name, "url": url, "type": hook_type, "min_level": min_level, "enabled": enabled}

    def list_webhooks(self) -> List[Dict[str, Any]]:
        con = get_db(self.db_path)
        rows = con.execute("SELECT id, name, url, type, min_level, enabled, created_at FROM webhook_configs ORDER BY created_at DESC").fetchall()
        return [{
            "id": r["id"],
            "name": r["name"],
            "url": r["url"],
            "type": r["type"],
            "min_level": r["min_level"],
            "enabled": bool(r["enabled"]),
            "created_at": r["created_at"]
        } for r in rows]

    def delete_webhook(self, webhook_id: str) -> bool:
        con = get_db(self.db_path)
        with con:
            cur = con.execute("DELETE FROM webhook_configs WHERE id = ?", (webhook_id,))
            return cur.rowcount > 0

    def dispatch_webhook(self, event_type: str, payload: Dict[str, Any]) -> None:
        def _send():
            try:
                con = get_db(self.db_path)
                hooks = con.execute("SELECT id, name, url, type, min_level FROM webhook_configs WHERE enabled = 1").fetchall()
                if not hooks:
                    return
                for h in hooks:
                    url = h["url"]
                    htype = h["type"]
                    data_to_send = None
                    if htype == "discord":
                        desc = f"**Event Type:** {event_type.upper()}\n"
                        if "title" in payload:
                            desc += f"**Title:** {payload['title']}\n"
                        if "severity" in payload:
                            desc += f"**Severity:** {payload['severity']}\n"
                        if "reason" in payload:
                            desc += f"**Reason:** {payload['reason']}\n"
                        color = 0xFF0000 if payload.get("severity") == "CRITICAL" else 0xFFA500
                        data_to_send = {
                            "embeds": [{
                                "title": f"🛡️ Kavalan SIEM/SOAR Notification: {event_type}",
                                "description": desc,
                                "color": color,
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            }]
                        }
                    elif htype == "slack":
                        text = f":shield: *Kavalan SIEM/SOAR Notification: {event_type}*\n"
                        text += f"• *Details*: {payload.get('title') or payload.get('description') or event_type}\n"
                        if "severity" in payload:
                            text += f"• *Severity*: `{payload['severity']}`\n"
                        data_to_send = {"text": text}
                    else:
                        data_to_send = {
                            "source": "kavalan_siem_soar",
                            "event_type": event_type,
                            "timestamp": int(time.time()),
                            "payload": payload
                        }

                    req = urllib.request.Request(
                        url,
                        data=json.dumps(data_to_send).encode("utf-8"),
                        headers={"Content-Type": "application/json", "User-Agent": "Kavalan-SOAR/1.0"},
                        method="POST"
                    )
                    urllib.request.urlopen(req, timeout=3.0)
            except Exception:
                pass

        threading.Thread(target=_send, daemon=True).start()

    # --- Event Ingest & Forwarding ---

    def ingest_agent_events(self, agent_id: str, events: List[Dict[str, Any]], tx_id: Optional[int] = None) -> Dict[str, Any]:
        # Replay protection check
        if tx_id is not None:
            last_tx = self.agent_tx.get(agent_id, -1)
            if tx_id <= last_tx:
                print(f"[!] [ReplayProtection] Dropped stale batch tx_id={tx_id} <= {last_tx} from agent {agent_id}")
                return {"accepted": 0, "agent_id": agent_id, "status": "dropped_replay"}
            self.agent_tx[agent_id] = tx_id

        valid_rows = []
        docs_to_index = []
        fired_alerts = []
        now = int(time.time())

        # Lookup host name
        con = get_db(self.db_path)
        agent_row = con.execute("SELECT name FROM agents WHERE id=?", (agent_id,)).fetchone()
        host = agent_row[0] if agent_row else f"agent-{agent_id}"

        for item in events:
            try:
                ev = validate_event(item)
                ev_dict = ev.to_dict()
                valid_rows.append((
                    ev.ts,
                    agent_id,
                    host,
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
                docs_to_index.append(ev_dict)

                # Evaluate against Kavalan ruleset
                rule_matches = self.kavalan_rules.evaluate_event(ev_dict)
                for rm in rule_matches:
                    alert_doc = {
                        "timestamp": ev.ts,
                        "agent_id": agent_id,
                        "host": host,
                        "rule_id": rm.rule_id,
                        "level": rm.level,
                        "rule_name": rm.name,
                        "description": rm.description,
                        "groups": rm.groups,
                        "mitre_id": rm.mitre_id,
                        "mitre_tactic": rm.mitre_tactic,
                        "source_ip": rm.actor_ip,
                        "target": rm.target,
                        "reason": rm.fired_reason,
                    }
                    ti_info = self.threat_intel.lookup(rm.actor_ip) if self.threat_intel else {}
                    alert_doc["threat_intel"] = ti_info
                    fired_alerts.append(alert_doc)

                    # Trigger Autonomous SOAR Playbook Engine
                    if self.soar_engine:
                        self.soar_engine.evaluate_alert(alert_doc, manager_core=self)

                    # Trigger Active Response if level >= 10
                    if rm.level >= 10:
                        self.ar_engine.evaluate_and_respond(rm.actor_ip, [rm], agent_id=agent_id)
                        self.dispatch_webhook("alert", alert_doc)

                    # Auto-create Incident Case on Critical Alert (level >= 12)
                    if rm.level >= 12:
                        con_cases = get_db(self.db_path)
                        existing_case = con_cases.execute("""
                            SELECT id FROM incident_cases
                            WHERE entities_json LIKE ? AND status IN ('NEW', 'INVESTIGATING') AND created_at > ?
                        """, (f'%"{rm.actor_ip}"%', now - 3600)).fetchone()
                        if not existing_case:
                            self.create_case(
                                title=f"CRITICAL: {rm.name} detected on {host}",
                                description=f"Rule {rm.rule_id} fired with severity Level {rm.level}. Reason: {rm.fired_reason}",
                                severity="CRITICAL",
                                entities={"ips": [rm.actor_ip], "hosts": [host], "users": [ev.user] if ev.user else []},
                                assignee="Automated SOAR"
                            )
            except Exception:
                pass

        if valid_rows:
            con = get_db(self.db_path)
            with con:
                con.executemany("""
                    INSERT INTO local_events (timestamp, agent_id, host, source_ip, log_type, action, target, outcome, status, user, raw, meta_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, valid_rows)

            # Forward events and alerts to Indexer Tier
            self._forward_to_indexer(docs_to_index)
            if fired_alerts:
                self._dispatch_alerts_to_indexer(fired_alerts)

        try:
            self.quiet_monitor.record_event_batch(agent_id, events)
        except Exception:
            pass

        return {"accepted": len(valid_rows), "agent_id": agent_id, "alerts_fired": len(fired_alerts)}

    def ingest_generic_log(self, raw_line: str, host: str = "syslog-source", agent_id: str = "syslog-receiver") -> Dict[str, Any]:
        """Parses an arbitrary log line using hierarchical decoders and ingests it."""
        ev = self.decoder_pipeline.decode_line(raw_line, host=host)
        if not ev:
            ev = CEMEvent(
                ts=int(time.time()),
                host=host,
                source_ip="127.0.0.1",
                log_type="syslog",
                action="raw_event",
                target=host,
                outcome="unknown",
                status="200",
                user=None,
                raw=raw_line.strip(),
                meta={"source": "generic_ingest"}
            )
        return self.ingest_agent_events(agent_id, [ev.to_dict()])

    def _forward_to_indexer(self, docs: List[Dict[str, Any]]) -> None:
        try:
            req = urllib.request.Request(
                f"{self.indexer_url}/api/index/events",
                data=json.dumps(docs).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            urllib.request.urlopen(req, timeout=3.0)
        except Exception:
            pass  # Indexer may be offline; manager buffers locally

    def _dispatch_alerts_to_indexer(self, alerts: List[Dict[str, Any]]) -> None:
        try:
            req = urllib.request.Request(
                f"{self.indexer_url}/api/index/alerts",
                data=json.dumps(alerts).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            urllib.request.urlopen(req, timeout=3.0)
        except Exception:
            pass

    # --- Detection & Multi-Host Correlation ---

    def run_detection_pass(self) -> Dict[str, Any]:
        self.check_agent_keepalives()
        con = get_db(self.db_path)
        max_row = con.execute("SELECT MAX(timestamp) FROM local_events").fetchone()
        max_ts = max_row[0] if max_row and max_row[0] else None

        agents = self.list_agents()
        active_count = sum(1 for a in agents if a["status"] == "active")

        if not max_ts:
            with self.lock:
                self.state.update({
                    "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0},
                    "sources": [],
                    "alerts": [],
                    "active_agents": active_count,
                    "total_agents": len(agents),
                    "last_scan": datetime.now(timezone.utc).isoformat(),
                })
                return self.state

        window_sec = self.window_minutes * 60
        cutoff = max_ts - window_sec

        rows = con.execute("""
            SELECT timestamp, agent_id, host, source_ip, log_type, action, target, outcome, status, user, meta_json
            FROM local_events
            WHERE timestamp >= ? AND timestamp <= ?
            ORDER BY timestamp ASC
        """, (cutoff, max_ts)).fetchall()

        web_by_ip = {}
        auth_by_ip = {}
        agent_hosts_by_ip = {}
        all_ips = set()

        for r in rows:
            ip = r["source_ip"]
            all_ips.add(ip)
            agent_hosts_by_ip.setdefault(ip, set()).add(r["host"])
            ltype = r["log_type"]
            ts = r["timestamp"]

            if ltype == "web":
                meta = json.loads(r["meta_json"]) if r["meta_json"] else {}
                method = meta.get("method")
                path = meta.get("path")
                if not method or not path:
                    act = r["action"]
                    if " " in act:
                        m_p = act.split(" ", 1)
                        method, path = m_p[0], m_p[1]
                    else:
                        method, path = "GET", r["target"]
                st_code = r["status"] if r["status"] is not None else 200
                web_by_ip.setdefault(ip, []).append((ts, method, path, st_code))

            elif ltype == "auth":
                outcome = "fail" if r["outcome"] in ("fail", "denied", "error") else "ok"
                user = r["user"] or ""
                auth_by_ip.setdefault(ip, []).append((ts, outcome, user))

        # 1. Run Kavalan Single-Channel Scores
        web_sources = [s for s in (detector.analyse(ip, ev) for ip, ev in web_by_ip.items()) if s]
        ssh_sources = [s for s in (kavalan_multi.score_ssh(ip, ev) for ip, ev in auth_by_ip.items()) if s]

        # 2. Correlate Channels
        correlated = kavalan_multi.correlate(web_sources, ssh_sources)
        corr_by_ip = {r["ip"]: r for r in correlated}

        # Build full source table for SOC: correlated threats + unflagged/benign sources (level OK)
        sources_table = list(correlated)
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
                "hosts": list(agent_hosts_by_ip.get(ip, [])),
                "multi_host": len(agent_hosts_by_ip.get(ip, [])) > 1,
                "web_score": 0,
                "ssh_score": 0,
                "tactics": {},
                "mitre_tactics": {},
                "reasons": [],
            })

        # 3. Multi-Host Enrichment: Tag actors who hit multiple hosts
        alerts_to_dispatch = []
        for r in correlated:
            ip = r["ip"]
            hosts = list(agent_hosts_by_ip.get(ip, []))
            r["hosts"] = hosts
            multi_host = len(hosts) > 1
            r["multi_host"] = multi_host

            # Map MITRE ATT&CK tactics
            tactics = r.get("tactics", {})
            mitre_tags = {}
            for t_name in tactics:
                if t_name in MITRE_MAPPING:
                    mitre_tags[t_name] = MITRE_MAPPING[t_name]
            r["mitre_tactics"] = mitre_tags

            # AI Agent Rule Evaluation
            rule_matches = self.rule_engine.evaluate_source(r, cross=r["cross_source"], campaign=False)
            top_rule = rule_matches[0] if rule_matches else None
            r["top_rule"] = {
                "id": top_rule.rule_id if top_rule else 100000,
                "level": top_rule.level if top_rule else 0,
                "description": top_rule.description if top_rule else "Normal activity",
            }
            r["rule_matches"] = [
                {"id": m.rule_id, "level": m.level, "name": m.name, "desc": m.description, "reason": m.fired_reason, "mitre": m.mitre_id}
                for m in rule_matches
            ]

            # Automated Active Response (Level >= 10)
            ar_action = self.ar_engine.evaluate_and_respond(ip, rule_matches)
            r["active_response"] = ar_action

            # Alert dispatch
            summary = f"Threat from {ip} on {', '.join(r['channels'])}"
            if r["cross_source"] and multi_host:
                summary = f"CRITICAL: Distributed cross-host intrusion by {ip} across {', '.join(hosts)}"
            elif r["cross_source"]:
                summary = f"CRITICAL: Cross-source agent {ip} attacked web and breached SSH"

            alert_doc = {
                "key": f"alert:{ip}",
                "level": r["level"],
                "rule_id": top_rule.rule_id if top_rule else 100000,
                "rule_level": top_rule.level if top_rule else 0,
                "type": "cross_source_agent" if r["cross_source"] else f"{r['channels'][0]}_attack",
                "source_ip": ip,
                "hosts": hosts,
                "channels": r["channels"],
                "web_score": r["web_score"],
                "ssh_score": r["ssh_score"],
                "summary": summary,
                "reasons": r.get("reasons", []),
                "tactics": tactics,
                "mitre_tactics": mitre_tags,
                "rule_matches": r["rule_matches"],
                "active_response": ar_action,
                "timestamp": max_ts,
            }
            ti_info = self.threat_intel.lookup(ip) if self.threat_intel else {}
            alert_doc["threat_intel"] = ti_info
            if self.soar_engine and alert_doc.get("level") in ("CRITICAL", "HIGH"):
                self.soar_engine.evaluate_alert(alert_doc, manager_core=self)
            alerts_to_dispatch.append(alert_doc)

        # Dispatch alerts to Indexer
        if alerts_to_dispatch:
            self._dispatch_alerts_to_indexer(alerts_to_dispatch)

        counts = {
            "CRITICAL": sum(1 for r in correlated if r["level"] == "CRITICAL"),
            "HIGH": sum(1 for r in correlated if r["level"] == "HIGH"),
            "MEDIUM": sum(1 for r in correlated if r["level"] == "MEDIUM"),
        }

        with self.lock:
            self.state.update({
                "counts": counts,
                "sources": sources_table,
                "alerts": alerts_to_dispatch,
                "active_agents": active_count,
                "total_agents": len(agents),
                "agents": agents,
                "last_scan": datetime.now(timezone.utc).isoformat(),
            })
            return self.state

    def _handle_background_alert(self, alert: Dict[str, Any]) -> None:
        """Processes background alerts raised by Quiet Source Monitor or Scheduled Searches."""
        with self.lock:
            self.state["alerts"].append(alert)
            lvl = alert.get("level", 5)
            sev = "CRITICAL" if lvl >= 12 else ("HIGH" if lvl >= 8 else "MEDIUM")
            self.state["counts"][sev] = self.state["counts"].get(sev, 0) + 1
        
        # Log to audit trail
        try:
            self.audit.log(
                username="system:monitor",
                role="admin",
                action="alert_generated",
                resource_type="alert",
                resource_id=str(alert.get("rule_id")),
                details=alert.get("description", ""),
                outcome="alert"
            )
        except Exception:
            pass

        # Forward to indexer if available
        try:
            req = urllib.request.Request(
                f"{self.indexer_url}/api/index/alerts",
                data=json.dumps([alert]).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                pass
        except Exception:
            pass

        # Auto-create case for High/Critical alerts
        if lvl >= 8:
            try:
                self.create_case(
                    title=alert.get("name", "Automated Security Alert"),
                    description=alert.get("description", ""),
                    severity=sev,
                    entities={"source_ip": alert.get("source_ip"), "host": alert.get("host")},
                    assignee="Unassigned"
                )
            except Exception:
                pass

    def start_worker(self) -> None:
        if self.worker_thread is not None and self.worker_thread.is_alive():
            return
        self.stop_event.clear()
        self.quiet_monitor.start()
        self.saved_searches.start()
        self.worker_thread = threading.Thread(target=self._loop, daemon=True)
        self.worker_thread.start()

    def stop_worker(self) -> None:
        self.stop_event.set()
        try:
            self.quiet_monitor.stop()
            self.saved_searches.stop()
        except Exception:
            pass
        if self.worker_thread is not None:
            self.worker_thread.join(timeout=2.0)

    def _loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.run_detection_pass()
            except Exception as e:
                import traceback
                print(f"[manager] Error in detection loop: {e}", file=sys.stderr)
                traceback.print_exc(file=sys.stderr)
            self.stop_event.wait(self.interval)


def create_manager_app(mgr: ManagerCore) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        init_db(mgr.db_path)
        mgr.start_worker()
        yield
        mgr.stop_worker()

    app = FastAPI(title="Kavalan Manager (Tier 2)", lifespan=lifespan)

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "kavalan-manager"}

    @app.post("/api/agent/register")
    async def register_agent_api(request: Request):
        body = await request.json()
        name = body.get("name", "unknown-host")
        ip = body.get("ip", "127.0.0.1")
        os_name = body.get("os", "Linux")
        res = mgr.register_agent(name, ip, os_name)
        return res

    def get_current_user(request: Request) -> Optional[Dict[str, Any]]:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            return mgr.auth.verify_token(token)
        return None

    @app.post("/api/agent/heartbeat")
    async def heartbeat_agent_api(request: Request):
        raw_body = await request.body()
        try:
            body = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        except Exception:
            return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})
        agent_id = body.get("agent_id")
        metrics = body.get("metrics", {})
        acks = body.get("acks", [])
        if not agent_id:
            return JSONResponse(status_code=400, content={"error": "Missing agent_id"})

        # Check cryptographic signature if present
        sig = request.headers.get("X-Agent-Signature")
        ts = request.headers.get("X-Agent-Timestamp")
        if sig or ts:
            valid, err = mgr.agent_sec.verify_request_signature(agent_id, ts, sig, raw_body)
            if not valid:
                mgr.audit.log(
                    username=f"agent:{agent_id}",
                    role="agent",
                    action="tamper_attempt",
                    resource_type="agent_signature",
                    resource_id=agent_id,
                    details=f"Heartbeat signature verification failed: {err}",
                    outcome="failure",
                    ip=request.client.host if request.client else "unknown"
                )
                return JSONResponse(status_code=401, content={"error": f"Agent signature invalid: {err}"})

        # Process active response execution acknowledgements
        for ack in acks:
            cid = ack.get("command_id")
            cstat = ack.get("status", "executed")
            cdet = ack.get("details", "")
            if cid:
                mgr.ar_engine.acknowledge_command(cid, cstat, cdet)

        ok = mgr.heartbeat_agent(agent_id, metrics)
        commands = mgr.ar_engine.get_pending_commands(agent_id)

        # Centralized Config synchronization
        agent_cfg_ver = int(metrics.get("config_version", 0))
        current_cfg = mgr.get_agent_config(agent_id)
        resp: Dict[str, Any] = {"ok": ok, "commands": commands}

        if current_cfg["version"] > agent_cfg_ver:
            resp["config"] = current_cfg["config"]
            resp["config_version"] = current_cfg["version"]

        return resp

    @app.get("/api/agent/{agent_id}/config")
    async def get_agent_config_api(agent_id: str):
        return mgr.get_agent_config(agent_id)

    @app.post("/api/agent/{agent_id}/config")
    async def set_agent_config_api(agent_id: str, request: Request):
        body = await request.json()
        cfg = body.get("config", body)
        res = mgr.set_agent_config(agent_id, cfg)
        return res

    @app.post("/api/active_response/trigger")
    async def trigger_active_response_api(request: Request):
        body = await request.json()
        action = body.get("action", "firewall-drop")
        actor_ip = body.get("actor_ip", "")
        target = body.get("target", "")
        target_agent = body.get("target_agent", "all")
        timeout = int(body.get("timeout", 600))
        reason = body.get("reason", "Manual containment ordered via SOC Console")
        res = mgr.ar_engine.trigger_manual_response(action, actor_ip, target, target_agent, timeout, reason)
        
        curr = get_current_user(request)
        user_name = curr["username"] if curr else "admin"
        user_role = curr["role"] if curr else "admin"
        mgr.audit.log(
            username=user_name,
            role=user_role,
            action="active_response_triggered",
            resource_type="firewall",
            resource_id=actor_ip or target,
            details={"action": action, "timeout": timeout, "reason": reason},
            outcome="success",
            ip=request.client.host if request.client else "127.0.0.1"
        )
        return res

    @app.post("/api/active_response/unblock")
    async def unblock_active_response_api(request: Request):
        body = await request.json()
        ar_id = int(body.get("id", 0))
        ok = mgr.ar_engine.unblock_response(ar_id)
        if not ok:
            return JSONResponse(status_code=404, content={"error": f"Response {ar_id} not found"})
        
        curr = get_current_user(request)
        user_name = curr["username"] if curr else "admin"
        user_role = curr["role"] if curr else "admin"
        mgr.audit.log(
            username=user_name,
            role=user_role,
            action="active_response_unblocked",
            resource_type="firewall",
            resource_id=str(ar_id),
            outcome="success",
            ip=request.client.host if request.client else "127.0.0.1"
        )
        return {"status": "ok", "unblocked_id": ar_id}

    @app.post("/api/agent/sca")
    async def agent_sca_api(request: Request):
        body = await request.json()
        agent_id = body.get("agent_id")
        sca_data = body.get("sca", {})
        packages = body.get("packages", [])
        if not agent_id:
            return JSONResponse(status_code=400, content={"error": "Missing agent_id"})

        con = get_db(mgr.db_path)
        agent_row = con.execute("SELECT name FROM agents WHERE id=?", (agent_id,)).fetchone()
        host = agent_row[0] if agent_row else f"agent-{agent_id}"

        sca_res = mgr.vuln_engine.save_sca_report(agent_id, sca_data) if sca_data else {}
        vuln_res = mgr.vuln_engine.correlate_packages(agent_id, host, packages) if packages else []
        return {
            "status": "ok",
            "agent_id": agent_id,
            "sca_score": sca_res.get("score"),
            "vulnerabilities_found": len(vuln_res)
        }

    @app.get("/api/sca/summary")
    async def sca_summary_api():
        return mgr.vuln_engine.get_fleet_summary()

    @app.get("/api/sca/agent/{agent_id}")
    async def sca_agent_api(agent_id: str):
        sca = mgr.vuln_engine.get_agent_sca(agent_id)
        vulns = mgr.vuln_engine.get_agent_vulnerabilities(agent_id)
        return {"sca": sca, "vulnerabilities": vulns}

    @app.get("/api/vuln/all")
    async def vuln_all_api():
        return {"vulnerabilities": mgr.vuln_engine.get_agent_vulnerabilities(None)}

    @app.post("/api/agent/events")
    async def agent_events_api(request: Request):
        raw_body = await request.body()
        try:
            body = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        except Exception:
            return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})
        agent_id = body.get("agent_id")
        events = body.get("events", [])
        tx_id = body.get("tx_id")
        if not agent_id or not isinstance(events, list):
            return JSONResponse(status_code=400, content={"error": "Expected agent_id and events array"})

        # Check cryptographic signature if present
        sig = request.headers.get("X-Agent-Signature")
        ts = request.headers.get("X-Agent-Timestamp")
        if sig or ts:
            valid, err = mgr.agent_sec.verify_request_signature(agent_id, ts, sig, raw_body)
            if not valid:
                mgr.audit.log(
                    username=f"agent:{agent_id}",
                    role="agent",
                    action="tamper_attempt",
                    resource_type="agent_signature",
                    resource_id=agent_id,
                    details=f"Signature verification failed: {err}",
                    outcome="failure",
                    ip=request.client.host if request.client else "unknown"
                )
                mgr._handle_background_alert({
                    "rule_id": 100801,
                    "level": 12,
                    "name": "Agent Telemetry Tampering Detected",
                    "description": f"HMAC cryptographic signature verification failed for agent '{agent_id}': {err}",
                    "source_ip": request.client.host if request.client else "unknown",
                    "agent_id": agent_id,
                    "host": agent_id,
                    "timestamp": int(time.time()),
                    "mitre_id": "T1562.001",
                    "mitre_tactic": "Defense Evasion"
                })
                return JSONResponse(status_code=401, content={"error": f"Agent signature invalid: {err}"})

        res = mgr.ingest_agent_events(agent_id, events, tx_id=tx_id)
        return res

    @app.get("/api/agents")
    async def list_agents_api():
        return {"agents": mgr.list_agents()}

    @app.delete("/api/agents/{agent_id}")
    async def delete_agent_api(agent_id: str):
        ok = mgr.delete_agent(agent_id)
        if not ok:
            return JSONResponse(status_code=404, content={"error": f"Agent {agent_id} not found"})
        return {"status": "ok", "deleted_id": agent_id}

    @app.post("/api/agents/{agent_id}/delete")
    async def delete_agent_api_post(agent_id: str):
        ok = mgr.delete_agent(agent_id)
        if not ok:
            return JSONResponse(status_code=404, content={"error": f"Agent {agent_id} not found"})
        return {"status": "ok", "deleted_id": agent_id}

    @app.get("/api/state")
    async def state_api():
        with mgr.lock:
            return JSONResponse(content=mgr.state)

    @app.post("/api/scan")
    async def scan_api():
        st = mgr.run_detection_pass()
        return JSONResponse(content=st)

    @app.get("/api/active_response/actions")
    async def active_response_api():
        return {"actions": mgr.ar_engine.list_responses()}

    @app.post("/api/logtest")
    async def logtest_api(request: Request):
        body = await request.json()
        log_line = body.get("log", "").strip()
        host = body.get("host", "logtest-host")
        if not log_line:
            return JSONResponse(status_code=400, content={"error": "Missing 'log' line to test"})

        ev = mgr.decoder_pipeline.decode_line(log_line, host=host)
        if not ev:
            return {
                "decoded": False,
                "raw": log_line,
                "message": "No decoder matched this log format"
            }

        ev_dict = ev.to_dict()
        rule_matches = mgr.kavalan_rules.evaluate_event(ev_dict)
        return {
            "decoded": True,
            "decoder": ev_dict.get("meta", {}).get("decoder", "unknown"),
            "event": ev_dict,
            "rules_fired": [rm.to_dict() for rm in rule_matches]
        }

    @app.get("/install.sh")
    async def serve_installer_api():
        sh_path = SIEM_ROOT / "agent" / "install.sh"
        if not sh_path.exists():
            return PlainTextResponse("#!/bin/bash\necho 'Installer not found'\nexit 1", status_code=404)
        return PlainTextResponse(sh_path.read_text(encoding="utf-8"), media_type="text/x-shellscript")

    @app.get("/agent/agent.py")
    async def serve_agent_script_api():
        py_path = SIEM_ROOT / "agent" / "agent.py"
        if not py_path.exists():
            return PlainTextResponse("# Agent script not found", status_code=404)
        return PlainTextResponse(py_path.read_text(encoding="utf-8"), media_type="text/x-python")

    @app.get("/agent/sample.conf")
    async def serve_agent_conf_api():
        conf_path = SIEM_ROOT / "agent" / "agent.conf"
        if not conf_path.exists():
            return PlainTextResponse("{}", status_code=404)
        return PlainTextResponse(conf_path.read_text(encoding="utf-8"), media_type="application/json")

    @app.get("/agent/{filename}")
    async def serve_agent_module_api(filename: str):
        safe_file = Path(filename).name
        target = SIEM_ROOT / "agent" / safe_file
        if not target.exists() or not target.is_file():
            return PlainTextResponse(f"# File not found: {safe_file}", status_code=404)
        media_type = "text/x-python" if safe_file.endswith(".py") else "application/json"
        return PlainTextResponse(target.read_text(encoding="utf-8"), media_type=media_type)

    @app.post("/api/ai/analyze")
    async def ai_analyze_api(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        ip = body.get("ip")
        with mgr.lock:
            sources = list(mgr.state.get("sources", []))
            alerts = list(mgr.state.get("alerts", []))

        target_source = None
        if ip:
            target_source = next((s for s in sources if s.get("ip") == ip), None)
        if not target_source and sources:
            target_source = sources[0]
            ip = target_source.get("ip")

        if not target_source:
            return JSONResponse(
                content={"error": "No threat actors found in detection window", "ip": ip or "unknown"},
                status_code=404
            )

        analysis = mgr.ai_analyst.analyze_actor(ip, target_source, alerts)
        return JSONResponse(content=analysis)

    @app.post("/api/ai/chat")
    async def ai_chat_api(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        msg = body.get("message", "")
        with mgr.lock:
            st = dict(mgr.state)
        res = mgr.ai_analyst.chat(msg, st)
        return JSONResponse(content=res)

    @app.get("/api/gemini/model-info")
    @app.get("/api/sec-llm/model-info")
    async def gemini_model_info_api():
        return JSONResponse(content=mgr.gemini.get_model_info())

    @app.get("/api/gemini/config")
    async def gemini_get_config_api():
        return JSONResponse(content={
            "model": mgr.gemini.client.model,
            "configured": mgr.gemini.client.is_configured(),
            "has_key": bool(mgr.gemini.client.api_key),
            "key_preview": (mgr.gemini.client.api_key[:6] + "..." + mgr.gemini.client.api_key[-4:]) if mgr.gemini.client.api_key and len(mgr.gemini.client.api_key) > 10 else ("Configured" if mgr.gemini.client.api_key else "")
        })

    @app.post("/api/gemini/config")
    async def gemini_set_config_api(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        api_key = body.get("api_key")
        model = body.get("model")
        mgr.gemini.set_config(api_key=api_key, model=model)
        return JSONResponse(content={
            "success": True,
            "model": mgr.gemini.client.model,
            "configured": mgr.gemini.client.is_configured()
        })

    @app.post("/api/gemini/generate")
    @app.post("/api/sec-llm/generate")
    async def gemini_generate_api(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        prompt = body.get("prompt", "")
        max_tokens = min(body.get("max_tokens", 250), 1024)
        temp = body.get("temperature", 0.3)
        res = mgr.gemini.infer(prompt, max_tokens=max_tokens, temperature=temp)
        return JSONResponse(content=res)

    @app.post("/api/gemini/explain")
    @app.post("/api/sec-llm/explain")
    async def gemini_explain_api(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        ip = body.get("ip")
        with mgr.lock:
            sources = list(mgr.state.get("sources", []))
        target_source = None
        if ip:
            target_source = next((s for s in sources if s.get("ip") == ip), None)
        if not target_source and sources:
            target_source = sources[0]
        if not target_source:
            target_source = {"ip": ip or "203.0.113.66", "tactics": {}, "reasons": []}
        res = mgr.gemini.explain_threat(target_source)
        return JSONResponse(content=res)

    # --- SOAR Incident Cases REST Endpoints ---

    @app.get("/api/cases")
    async def list_cases_api(status: Optional[str] = None, severity: Optional[str] = None):
        return JSONResponse(content={"cases": mgr.list_cases(status=status, severity=severity)})

    @app.post("/api/cases")
    async def create_case_api(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        title = body.get("title") or "Security Incident"
        desc = body.get("description", "")
        sev = body.get("severity", "HIGH")
        entities = body.get("entities", {})
        assignee = body.get("assignee", "Unassigned")
        new_case = mgr.create_case(title, description=desc, severity=sev, entities=entities, assignee=assignee)
        return JSONResponse(content=new_case)

    @app.get("/api/cases/{case_id}")
    async def get_case_api(case_id: str):
        c = mgr.get_case(case_id)
        if not c:
            return JSONResponse(content={"error": f"Case {case_id} not found"}, status_code=404)
        return JSONResponse(content=c)

    @app.patch("/api/cases/{case_id}/status")
    async def update_case_status_api(case_id: str, request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        st = body.get("status", "INVESTIGATING")
        assignee = body.get("assignee")
        note = body.get("note")
        res = mgr.update_case_status(case_id, st, assignee=assignee, note=note)
        if not res:
            return JSONResponse(content={"error": f"Case {case_id} not found"}, status_code=404)
        
        curr = get_current_user(request)
        user_name = curr["username"] if curr else "analyst"
        user_role = curr["role"] if curr else "analyst"
        mgr.audit.log(
            username=user_name,
            role=user_role,
            action="case_status_updated",
            resource_type="case",
            resource_id=case_id,
            details={"status": st, "assignee": assignee, "note": note},
            outcome="success",
            ip=request.client.host if request.client else "127.0.0.1"
        )
        return JSONResponse(content=res)

    @app.post("/api/cases/{case_id}/notes")
    async def add_case_note_api(case_id: str, request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        note = body.get("note", "")
        author = body.get("author", "SOC Analyst")
        res = mgr.add_case_note(case_id, note=note, author=author)
        return JSONResponse(content=res)

    @app.post("/api/cases/{case_id}/playbook")
    async def run_case_playbook_api(case_id: str, request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        playbook = body.get("playbook", "")
        target = body.get("target")
        res = mgr.run_case_playbook(case_id, playbook, target=target)
        if "error" in res:
            return JSONResponse(content=res, status_code=400)
        return JSONResponse(content=res)

    # --- Outbound Webhooks REST Endpoints ---

    @app.get("/api/webhooks")
    async def list_webhooks_api():
        return JSONResponse(content={"webhooks": mgr.list_webhooks()})

    @app.post("/api/webhooks")
    async def save_webhook_api(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        name = body.get("name") or "SOC Webhook"
        url = body.get("url") or ""
        htype = body.get("type", "generic")
        min_level = body.get("min_level", "HIGH")
        enabled = body.get("enabled", True)
        if not url:
            return JSONResponse(content={"error": "URL is required"}, status_code=400)
        res = mgr.save_webhook(name, url, hook_type=htype, min_level=min_level, enabled=enabled)
        return JSONResponse(content=res)

    @app.delete("/api/webhooks/{webhook_id}")
    async def delete_webhook_api(webhook_id: str):
        ok = mgr.delete_webhook(webhook_id)
        return JSONResponse(content={"deleted": ok, "id": webhook_id})

    @app.post("/api/webhooks/test")
    async def test_webhook_api(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        mgr.dispatch_webhook("test_notification", {
            "title": "Kavalan SOAR Webhook Test",
            "description": "Integration connectivity verified from Kavalan SOC Manager.",
            "severity": "INFO",
            "reason": "Operator initiated diagnostic probe."
        })
        return JSONResponse(content={"status": "dispatched", "message": "Test notification sent to configured webhooks."})

    @app.get("/api/soar/playbooks")
    async def list_soar_playbooks_api():
        try:
            if mgr.soar_engine:
                return JSONResponse(content={"playbooks": mgr.soar_engine.get_playbooks()})
            return JSONResponse(content={"playbooks": []})
        except Exception as e:
            import traceback
            return JSONResponse(content={"error": str(e), "traceback": traceback.format_exc()}, status_code=500)

    @app.post("/api/soar/playbooks/{playbook_id}/toggle")
    async def toggle_soar_playbook_api(playbook_id: str, request: Request):
        try:
            try:
                body = await request.json()
            except Exception:
                body = {}
            enabled = body.get("enabled", True)
            if mgr.soar_engine:
                res = mgr.soar_engine.toggle_playbook(playbook_id, is_enabled=enabled)
                return JSONResponse(content=res)
            return JSONResponse(content={"error": "SOAR engine unavailable"}, status_code=500)
        except Exception as e:
            import traceback
            return JSONResponse(content={"error": str(e), "traceback": traceback.format_exc()}, status_code=500)

    @app.post("/api/soar/playbooks/{playbook_id}/run")
    async def run_soar_playbook_manual_api(playbook_id: str, request: Request):
        try:
            try:
                body = await request.json()
            except Exception:
                body = {}
            target = body.get("target") or "203.0.113.154"
            if mgr.soar_engine:
                res = mgr.soar_engine.run_manual(playbook_id, target=target, manager_core=mgr)
                return JSONResponse(content=res)
            return JSONResponse(content={"error": "SOAR engine unavailable"}, status_code=500)
        except Exception as e:
            import traceback
            return JSONResponse(content={"error": str(e), "traceback": traceback.format_exc()}, status_code=500)

    @app.get("/api/soar/playbook-runs")
    async def list_soar_playbook_runs_api(limit: int = 20):
        try:
            if mgr.soar_engine:
                return JSONResponse(content={"runs": mgr.soar_engine.get_recent_runs(limit=limit)})
            return JSONResponse(content={"runs": []})
        except Exception as e:
            import traceback
            return JSONResponse(content={"error": str(e), "traceback": traceback.format_exc()}, status_code=500)

    # ------------------------------------------------------------- Custom Detection Rules & Sigma
    @app.get("/api/rules")
    async def list_rules_api():
        try:
            rules = mgr.get_custom_rules()
            return JSONResponse(content={
                "rules": rules,
                "total": len(rules),
                "active": sum(1 for r in rules if r.get("enabled", True)),
                "templates_count": len(SigmaRuleConverter.get_templates()),
            })
        except Exception as e:
            return JSONResponse(content={"error": str(e)}, status_code=500)

    @app.get("/api/rules/templates")
    async def get_rule_templates_api():
        try:
            return JSONResponse(content={"templates": SigmaRuleConverter.get_templates()})
        except Exception as e:
            return JSONResponse(content={"error": str(e)}, status_code=500)

    @app.post("/api/rules/sigma/convert")
    async def convert_sigma_api(request: Request):
        try:
            body = await request.json()
            yaml_text = body.get("sigma") or body.get("yaml") or ""
            if not yaml_text.strip():
                return JSONResponse(content={"error": "Missing 'sigma' or 'yaml' string"}, status_code=400)
            rule_id = body.get("rule_id")
            converted = SigmaRuleConverter.convert(yaml_text, rule_id=int(rule_id) if rule_id else None)
            return JSONResponse(content={"rule": converted})
        except Exception as e:
            return JSONResponse(content={"error": str(e)}, status_code=400)

    @app.post("/api/rules")
    async def save_rule_api(request: Request):
        try:
            body = await request.json()
            rule_data = body.get("rule") if "rule" in body else body
            raw_sigma = body.get("raw_sigma") or rule_data.get("raw_sigma", "")
            saved = mgr.save_custom_rule(rule_data, raw_sigma=raw_sigma)
            return JSONResponse(content={"status": "saved", "rule": saved})
        except ValueError as e:
            return JSONResponse(content={"error": str(e)}, status_code=400)
        except Exception as e:
            return JSONResponse(content={"error": str(e)}, status_code=500)

    @app.delete("/api/rules/{rule_id}")
    async def delete_rule_api(rule_id: int):
        try:
            deleted = mgr.delete_custom_rule(rule_id)
            if not deleted:
                return JSONResponse(content={"error": f"Rule {rule_id} not found"}, status_code=404)
            return JSONResponse(content={"status": "deleted", "rule_id": rule_id})
        except Exception as e:
            return JSONResponse(content={"error": str(e)}, status_code=500)

    @app.post("/api/rules/{rule_id}/toggle")
    async def toggle_rule_api(rule_id: int):
        try:
            res = mgr.toggle_custom_rule(rule_id)
            return JSONResponse(content=res)
        except ValueError as e:
            return JSONResponse(content={"error": str(e)}, status_code=404)
        except Exception as e:
            return JSONResponse(content={"error": str(e)}, status_code=500)

    @app.post("/api/rules/test")
    async def test_rule_api(request: Request):
        try:
            body = await request.json()
            rule = body.get("rule")
            rule_id = body.get("rule_id")
            log_line = body.get("log", "").strip()
            host = body.get("host", "logtest-host")

            if not log_line:
                return JSONResponse(content={"error": "Missing 'log' line to test"}, status_code=400)

            if not rule and rule_id:
                rules = mgr.get_custom_rules()
                rule = next((r for r in rules if r.get("id") == int(rule_id)), None)

            if not rule:
                return JSONResponse(content={"error": "Provide either a 'rule' object or valid 'rule_id'"}, status_code=400)

            result = mgr.test_custom_rule(rule, log_line=log_line, host=host)
            return JSONResponse(content=result)
        except Exception as e:
            return JSONResponse(content={"error": str(e)}, status_code=500)

    # ------------------------------------------------------------- Phase 1 SOC Endpoints

    # --- Authentication & User Management ---
    @app.post("/api/auth/login")
    async def login_api(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        username = body.get("username", "").strip()
        password = body.get("password", "")
        auth_result = mgr.auth.authenticate(username, password)
        ip = request.client.host if request.client else "127.0.0.1"
        if not auth_result:
            mgr.audit.log(
                username=username or "anonymous",
                role="unknown",
                action="login_failed",
                resource_type="auth",
                outcome="failure",
                ip=ip
            )
            return JSONResponse(status_code=401, content={"error": "Invalid username or password"})
        mgr.audit.log(
            username=username,
            role=auth_result["role"],
            action="login_success",
            resource_type="auth",
            outcome="success",
            ip=ip
        )
        return JSONResponse(content=auth_result)

    @app.get("/api/auth/me")
    async def get_me_api(request: Request):
        user = get_current_user(request)
        if not user:
            # Fallback to default admin for local dev if unauthenticated
            return JSONResponse(content={"username": "admin", "role": "admin", "permissions": ["all"]})
        return JSONResponse(content=user)

    @app.post("/api/auth/logout")
    async def logout_api(request: Request):
        user = get_current_user(request)
        if user:
            mgr.audit.log(
                username=user["username"],
                role=user["role"],
                action="logout",
                resource_type="auth",
                outcome="success"
            )
        return JSONResponse(content={"status": "ok"})

    @app.get("/api/users")
    async def list_users_api():
        return JSONResponse(content={"users": mgr.auth.list_users()})

    @app.post("/api/users")
    async def create_user_api(request: Request):
        try:
            body = await request.json()
            u = body.get("username", "").strip()
            p = body.get("password", "")
            r = body.get("role", "analyst")
            created = mgr.auth.create_user(u, p, r)
            curr = get_current_user(request)
            mgr.audit.log(
                username=curr["username"] if curr else "admin",
                role=curr["role"] if curr else "admin",
                action="create_user",
                resource_type="user",
                resource_id=u,
                details={"role": r},
                outcome="success"
            )
            return JSONResponse(content=created)
        except ValueError as e:
            return JSONResponse(status_code=400, content={"error": str(e)})
        except Exception as e:
            return JSONResponse(status_code=500, content={"error": str(e)})

    @app.delete("/api/users/{username}")
    async def delete_user_api(username: str, request: Request):
        ok = mgr.auth.delete_user(username)
        if not ok:
            return JSONResponse(status_code=400, content={"error": "Cannot delete user or user not found"})
        curr = get_current_user(request)
        mgr.audit.log(
            username=curr["username"] if curr else "admin",
            role=curr["role"] if curr else "admin",
            action="delete_user",
            resource_type="user",
            resource_id=username,
            outcome="success"
        )
        return JSONResponse(content={"status": "ok", "deleted": username})

    # --- Audit Trail ---
    @app.get("/api/audit")
    async def list_audit_logs_api(
        action: Optional[str] = None,
        username: Optional[str] = None,
        outcome: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ):
        logs = mgr.audit.query(action=action, username=username, outcome=outcome, limit=limit, offset=offset)
        return JSONResponse(content={"audit_logs": logs, "count": len(logs)})

    @app.post("/api/audit")
    async def record_audit_api(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        curr = get_current_user(request)
        logged = mgr.audit.log(
            username=body.get("username") or (curr["username"] if curr else "analyst"),
            role=body.get("role") or (curr["role"] if curr else "analyst"),
            action=body.get("action", "operator_action"),
            resource_type=body.get("resource_type", "system"),
            resource_id=body.get("resource_id"),
            details=body.get("details"),
            outcome=body.get("outcome", "success"),
            ip=request.client.host if request.client else "127.0.0.1"
        )
        return JSONResponse(content=logged)

    # --- Key Rotation & Fleet Security ---
    @app.post("/api/agents/{agent_id}/rotate-key")
    async def rotate_agent_key_api(agent_id: str, request: Request):
        res = mgr.agent_sec.rotate_agent_key(agent_id)
        curr = get_current_user(request)
        mgr.audit.log(
            username=curr["username"] if curr else "admin",
            role=curr["role"] if curr else "admin",
            action="rotate_agent_key",
            resource_type="agent",
            resource_id=agent_id,
            outcome="success"
        )
        return JSONResponse(content=res)

    # --- Ingestion Telemetry & Dead-Man Switch ---
    @app.get("/api/fleet/telemetry")
    async def fleet_telemetry_api():
        return JSONResponse(content=mgr.quiet_monitor.get_telemetry())

    # --- Saved & Scheduled Searches ---
    @app.get("/api/searches")
    async def list_searches_api():
        return JSONResponse(content={"searches": mgr.saved_searches.list_saved_searches()})

    @app.post("/api/searches")
    async def create_saved_search_api(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        curr = get_current_user(request)
        created_by = curr["username"] if curr else "analyst"
        item = mgr.saved_searches.create_saved_search(
            name=body.get("name", "Untitled Search"),
            query=body.get("query", "*"),
            description=body.get("description", ""),
            created_by=created_by,
            is_scheduled=bool(body.get("is_scheduled", False)),
            schedule_interval_mins=int(body.get("schedule_interval_mins", 15)),
            alert_threshold=int(body.get("alert_threshold", 1)),
            alert_severity=body.get("alert_severity", "HIGH")
        )
        mgr.audit.log(
            username=created_by,
            role=curr["role"] if curr else "analyst",
            action="create_saved_search",
            resource_type="search",
            resource_id=item["id"],
            details=item["name"],
            outcome="success"
        )
        return JSONResponse(content=item)

    @app.delete("/api/searches/{search_id}")
    async def delete_saved_search_api(search_id: str):
        ok = mgr.saved_searches.delete_saved_search(search_id)
        return JSONResponse(content={"deleted": ok, "id": search_id})

    @app.post("/api/searches/{search_id}/run")
    async def run_saved_search_api(search_id: str):
        res = mgr.saved_searches.run_search(search_id)
        return JSONResponse(content=res)

    # --- CERT-In 6-Hour Incident Compliance Report ---
    @app.get("/api/cases/{case_id}/cert-in-report")
    async def cert_in_report_api(case_id: str, request: Request):
        case_doc = mgr.get_case(case_id)
        if not case_doc:
            return JSONResponse(status_code=404, content={"error": f"Case {case_id} not found"})
        fmt = request.query_params.get("format", "json").lower()
        org_name = request.query_params.get("org", "Enterprise SOC")
        report = generate_cert_in_report(case_doc, organization_name=org_name)
        curr = get_current_user(request)
        mgr.audit.log(
            username=curr["username"] if curr else "analyst",
            role=curr["role"] if curr else "analyst",
            action="generate_cert_in_report",
            resource_type="case",
            resource_id=case_id,
            details={"format": fmt, "compliance": report.get("cert_in_metadata", {}).get("compliance_status")},
            outcome="success"
        )
        if fmt in ("markdown", "md"):
            return PlainTextResponse(content=report["markdown_report"], media_type="text/markdown")
        return JSONResponse(content=report)

    # --- Schema Mapping Export (OCSF & ECS) ---
    @app.post("/api/events/export")
    async def export_events_schema_api(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        raw_events = body.get("events", [])
        fmt = body.get("format", "ocsf").lower()
        if fmt == "ecs":
            mapped = [cem_to_ecs(ev) for ev in raw_events]
        else:
            mapped = [cem_to_ocsf(ev) for ev in raw_events]
        return JSONResponse(content={"format": fmt, "count": len(mapped), "events": mapped})

    # --- Generic Ingestion (Syslog / Cloud / Firewalls) ---
    @app.post("/api/ingest")
    async def ingest_generic_api(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        raw_line = body.get("raw") or body.get("log") or ""
        host = body.get("host") or "syslog-source"
        agent_id = body.get("agent_id") or "syslog-receiver"
        if not raw_line and "events" in body:
            res = mgr.ingest_agent_events(agent_id, body["events"])
            return JSONResponse(content=res)
        res = mgr.ingest_generic_log(raw_line, host=host, agent_id=agent_id)
        return JSONResponse(content=res)

    return app


def main():
    parser = argparse.ArgumentParser(description="Kavalan SIEM Central Manager (Tier 2)")
    parser.add_argument("--db", default="manager.db", help="Manager database path")
    parser.add_argument("--indexer", default="http://127.0.0.1:8920", help="Indexer URL")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8910, help="Bind port (default: 8910)")
    parser.add_argument("--window", type=int, default=15, help="Window minutes")
    parser.add_argument("--interval", type=int, default=5, help="Scan interval seconds")
    args = parser.parse_args()

    db_path = str(SIEM_ROOT / args.db) if not os.path.isabs(args.db) else args.db
    init_db(db_path)
    mgr = ManagerCore(db_path, indexer_url=args.indexer, window_minutes=args.window, interval=args.interval)
    app = create_manager_app(mgr)
    print(f"[*] Kavalan Manager (Tier 2) running on http://{args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()

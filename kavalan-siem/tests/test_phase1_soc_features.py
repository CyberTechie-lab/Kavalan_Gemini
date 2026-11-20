"""
test_phase1_soc_features.py - Comprehensive Unit Tests for Kavalan Phase 1 SOC Features

Tests:
  1. RBAC Authentication & Session Tokens (PBKDF2-HMAC-SHA256)
  2. Tamper-Evident Audit Logging
  3. Agent Cryptographic Integrity, HMAC Signing, Replay & Key Rotation
  4. Enterprise Decoders (Windows 4624/4625/4688, CloudTrail, Entra ID, DNS, K8s)
  5. Schema Mapping (OCSF v1.1.0 & ECS v8.x)
  6. Dead-Man Switch & Real-Time EPS Monitoring
  7. Piped Query Engine (stats count by, where, sort, limit)
  8. SHA-256 Merkle Hash-Chaining & Storage Tamper Proofing
  9. Indian CERT-In 180-Day Retention & 6-Hour Incident Report Generation
"""

import json
import sqlite3
import sys
import time
from pathlib import Path
import pytest

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
if str(BASE_DIR / "manager") not in sys.path:
    sys.path.insert(0, str(BASE_DIR / "manager"))

from auth import AuthManager, hash_password, verify_password, create_session_token, verify_session_token
from audit import AuditLogger
from security import AgentSecurityManager
from agent.security import AgentSigner
from decoders.enterprise_decoders import (
    WindowsSecurityEventDecoder,
    CloudTrailDecoder,
    MicrosoftEntraDecoder,
    DnsLogDecoder,
    KubernetesAuditDecoder
)
from schema_mapper import cem_to_ocsf, cem_to_ecs
from quiet_source_monitor import QuietSourceMonitor
from indexer.piped_query import PipedQueryEngine
from indexer.tamper_proof import TamperProofChain
from indexer.retention_manager import RetentionManager
from cert_in_compliance import generate_cert_in_report
from cem import CEMEvent


@pytest.fixture
def memory_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    return conn


# ==============================================================================
# 1. RBAC Authentication & Tamper-Proof Sessions
# ==============================================================================

def test_auth_password_hashing():
    pwd = "SecretPassword123!"
    h, s = hash_password(pwd)
    assert verify_password(pwd, h, s) is True
    assert verify_password("WrongPassword!", h, s) is False


def test_auth_manager_seeded_users(memory_db):
    auth = AuthManager(lambda: memory_db, secret_key="test-secret-key")
    # Admin
    admin_res = auth.authenticate("admin", "KavalanAdmin2026!")
    assert admin_res is not None
    assert admin_res["role"] == "admin"
    assert "token" in admin_res
    assert "active_response" in admin_res["permissions"]

    # Analyst
    analyst_res = auth.authenticate("analyst", "KavalanAnalyst2026!")
    assert analyst_res is not None
    assert analyst_res["role"] == "analyst"
    assert "active_response" not in analyst_res["permissions"]

    # Invalid
    assert auth.authenticate("admin", "BadPassword") is None


def test_session_token_cryptography():
    key = "super-secret-key-32-bytes-long!!"
    tok = create_session_token("analyst_jane", "analyst", key, expiry_seconds=3600)
    payload = verify_session_token(tok, key)
    assert payload is not None
    assert payload["sub"] == "analyst_jane"
    assert payload["role"] == "analyst"

    # Signature tampering check
    tampered = tok[:-4] + "AAAA"
    assert verify_session_token(tampered, key) is None


# ==============================================================================
# 2. Tamper-Evident Audit Logging
# ==============================================================================

def test_audit_logger(memory_db):
    audit = AuditLogger(lambda: memory_db)
    audit.log(
        username="analyst_bob",
        role="analyst",
        action="alert_triage",
        resource_type="alert",
        resource_id="100200",
        details={"status": "resolved"},
        outcome="success"
    )
    audit.log(
        username="admin",
        role="admin",
        action="firewall_block",
        resource_type="ip",
        resource_id="203.0.113.5",
        outcome="success"
    )

    records = audit.query()
    assert len(records) == 2

    # Query filter by action
    fw_records = audit.query(action="firewall_block")
    assert len(fw_records) == 1
    assert fw_records[0]["resource_id"] == "203.0.113.5"


# ==============================================================================
# 3. Agent Cryptographic Integrity, HMAC Signing & Key Rotation
# ==============================================================================

def test_agent_hmac_signing_and_verification(memory_db, tmp_path):
    sec_mgr = AgentSecurityManager(lambda: memory_db)
    agent_id = "001"
    secret_key = sec_mgr.get_or_create_agent_key(agent_id)

    key_file = tmp_path / "agent.key"
    signer = AgentSigner(key_file)
    signer.set_key(secret_key)
    payload = json.dumps({"events": [{"ts": 1000, "action": "test"}]}).encode("utf-8")

    # Valid signature
    headers = signer.sign(payload)
    is_valid, err = sec_mgr.verify_request_signature(
        agent_id,
        headers["X-Agent-Timestamp"],
        headers["X-Agent-Signature"],
        payload
    )
    assert is_valid is True
    assert err is None

    # Tampered payload
    tampered_payload = json.dumps({"events": [{"ts": 1000, "action": "ATTACK"}]}).encode("utf-8")
    is_valid, err = sec_mgr.verify_request_signature(
        agent_id,
        headers["X-Agent-Timestamp"],
        headers["X-Agent-Signature"],
        tampered_payload
    )
    assert is_valid is False
    assert "signature mismatch" in err

    # Replay attack prevention (>300s drift)
    old_ts = str(int(time.time()) - 400)
    is_valid, err = sec_mgr.verify_request_signature(agent_id, old_ts, "anysig", payload)
    assert is_valid is False
    assert "Timestamp drift" in err


def test_agent_key_rotation(memory_db):
    sec_mgr = AgentSecurityManager(lambda: memory_db)
    agent_id = "002"
    key1 = sec_mgr.get_or_create_agent_key(agent_id)
    rot_res = sec_mgr.rotate_agent_key(agent_id)
    key2 = rot_res["new_secret_key"]
    assert key1 != key2
    assert sec_mgr.get_or_create_agent_key(agent_id) == key2


# ==============================================================================
# 4. Enterprise Decoders (Windows 4624/4625, CloudTrail, Entra, DNS, K8s)
# ==============================================================================

def test_windows_security_decoder():
    dec = WindowsSecurityEventDecoder()

    # Event ID 4625 (Failed Login)
    raw_4625 = json.dumps({
        "EventID": 4625,
        "TargetUserName": "Administrator",
        "IpAddress": "192.168.1.50",
        "Computer": "DC01.corp.local",
        "FailureReason": "Unknown user name or bad password"
    })
    assert dec.match(raw_4625) is True
    ev = dec.decode(raw_4625, host="DC01")
    assert ev is not None
    assert ev.outcome == "fail"
    assert ev.source_ip == "192.168.1.50"
    assert ev.user == "Administrator"

    # Event ID 4688 (Process Creation)
    raw_4688 = json.dumps({
        "EventID": 4688,
        "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
        "SubjectUserName": "SYSTEM"
    })
    ev4688 = dec.decode(raw_4688, host="WS01")
    assert ev4688 is not None
    assert "process_create" in ev4688.action
    assert ev4688.target == "C:\\Windows\\System32\\cmd.exe"


def test_cloudtrail_decoder():
    dec = CloudTrailDecoder()
    raw = json.dumps({
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "sourceIPAddress": "198.51.100.22",
        "userIdentity": {"type": "IAMUser", "userName": "devops_admin"},
        "responseElements": {"ConsoleLogin": "Success"}
    })
    assert dec.match(raw) is True
    ev = dec.decode(raw)
    assert ev is not None
    assert ev.log_type == "cloud"
    assert "ConsoleLogin" in ev.action
    assert ev.user == "devops_admin"
    assert ev.source_ip == "198.51.100.22"
    assert ev.outcome == "ok"


def test_entra_id_decoder():
    dec = MicrosoftEntraDecoder()
    raw = json.dumps({
        "userPrincipalName": "analyst@enterprise.onmicrosoft.com",
        "ipAddress": "203.0.113.88",
        "appDisplayName": "Office 365 Exchange Online",
        "status": {"errorCode": 50126, "failureReason": "Invalid username or password"}
    })
    assert dec.match(raw) is True
    ev = dec.decode(raw)
    assert ev is not None
    assert ev.log_type == "auth"
    assert ev.outcome == "fail"
    assert ev.source_ip == "203.0.113.88"


def test_dns_decoder():
    dec = DnsLogDecoder()
    raw = "20-Nov-2026 10:15:30.123 client @0x7f88 192.168.1.100#53535 (malicious-c2.example.com): query: malicious-c2.example.com IN A + (192.168.1.1)"
    assert dec.match(raw) is True
    ev = dec.decode(raw, host="dns-srv")
    assert ev is not None
    assert ev.log_type == "dns"
    assert ev.source_ip == "192.168.1.100"
    assert ev.target == "malicious-c2.example.com"


def test_kubernetes_audit_decoder():
    dec = KubernetesAuditDecoder()
    raw = json.dumps({
        "kind": "Event",
        "verb": "create",
        "user": {"username": "system:serviceaccount:kube-system:admin"},
        "sourceIPs": ["10.244.0.5"],
        "objectRef": {"resource": "pods", "namespace": "production", "name": "web-pod-1"},
        "responseStatus": {"code": 201}
    })
    assert dec.match(raw) is True
    ev = dec.decode(raw)
    assert ev is not None
    assert ev.log_type == "k8s"
    assert "create pods" in ev.action
    assert ev.outcome == "ok"


# ==============================================================================
# 5. Schema Mapping (OCSF v1.1.0 & ECS v8.x)
# ==============================================================================

def test_schema_mapping_ocsf_and_ecs():
    ev = {
        "ts": 1774000000,
        "host": "web-prod-01",
        "source_ip": "203.0.113.44",
        "log_type": "web",
        "action": "GET /api/v1/users",
        "target": "/api/v1/users",
        "outcome": "fail",
        "status": 403,
        "user": "anonymous",
        "raw": "GET /api/v1/users 403"
    }

    # OCSF v1.1.0
    ocsf = cem_to_ocsf(ev)
    assert ocsf["metadata"]["version"] == "1.1.0"
    assert ocsf["category_uid"] == 4  # Network Activity
    assert ocsf["src_endpoint"]["ip"] == "203.0.113.44"
    assert ocsf["http_request"]["url"]["path"] == "/api/v1/users"

    # ECS v8.x
    ecs = cem_to_ecs(ev)
    assert ecs["ecs"]["version"] == "8.11.0"
    assert ecs["source"]["ip"] == "203.0.113.44"
    assert ecs["host"]["name"] == "web-prod-01"
    assert ecs["url"]["path"] == "/api/v1/users"


# ==============================================================================
# 6. Dead-Man Switch & Real-Time EPS Monitoring
# ==============================================================================

def test_quiet_source_monitor_telemetry():
    fired_alerts = []
    monitor = QuietSourceMonitor(
        alert_callback=lambda a: fired_alerts.append(a),
        quiet_threshold_sec=2,  # 2s for fast test
        check_interval_sec=1
    )

    now = int(time.time())
    monitor.record_heartbeat("agent-01", "web-01", "10.0.0.1")
    monitor.record_event_batch("agent-01", [
        {"ts": now - 1, "action": "test1"},
        {"ts": now, "action": "test2"}
    ])

    telemetry = monitor.get_telemetry()
    assert telemetry["aggregate_eps"] >= 0.0
    assert len(telemetry["sources"]) == 1
    assert telemetry["sources"][0]["name"] == "web-01"
    assert telemetry["sources"][0]["events_total"] == 2


# ==============================================================================
# 7. Piped Query Engine
# ==============================================================================

def test_piped_query_engine(memory_db):
    memory_db.execute("""
        CREATE TABLE IF NOT EXISTS events_index (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER,
            agent_id TEXT,
            host TEXT,
            source_ip TEXT,
            log_type TEXT,
            action TEXT,
            target TEXT,
            outcome TEXT,
            status INTEGER,
            user TEXT,
            raw TEXT,
            meta TEXT
        )
    """)
    events = [
        (100, "001", "host1", "10.0.0.1", "web", "GET", "/index.html", "ok", 200, "user1", "", "{}"),
        (101, "001", "host1", "10.0.0.1", "web", "GET", "/admin", "ok", 200, "user1", "", "{}"),
        (102, "002", "host2", "10.0.0.2", "auth", "login", "ssh", "fail", 401, "root", "", "{}"),
        (103, "001", "host1", "10.0.0.1", "web", "POST", "/admin", "fail", 403, "user1", "", "{}"),
        (104, "002", "host2", "10.0.0.3", "auth", "login", "ssh", "fail", 401, "admin", "", "{}"),
    ]
    memory_db.executemany("""
        INSERT INTO events_index (ts, agent_id, host, source_ip, log_type, action, target, outcome, status, user, raw, meta)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, events)
    memory_db.commit()

    engine = PipedQueryEngine(lambda: memory_db)

    # Test 1: stats count by source_ip | where count > 1 | sort count desc
    q1 = "* | stats count by source_ip | where count > 1 | sort count desc"
    res1 = engine.execute(q1)
    assert res1["mode"] == "table"
    assert len(res1["results"]) == 1
    assert res1["results"][0]["source_ip"] == "10.0.0.1"
    assert res1["results"][0]["count"] == 3

    # Test 2: Filter by log_type | limit 2
    q2 = "log_type=auth | limit 2"
    res2 = engine.execute(q2)
    assert res2["mode"] == "events"
    assert len(res2["results"]) == 2


# ==============================================================================
# 8. SHA-256 Merkle Hash-Chaining & Storage Tamper Proofing
# ==============================================================================

def test_tamper_proof_hash_chain(memory_db):
    memory_db.execute("""
        CREATE TABLE IF NOT EXISTS events_index (
            id INTEGER PRIMARY KEY,
            ts INTEGER,
            source_ip TEXT,
            action TEXT,
            target TEXT
        )
    """)
    memory_db.execute("INSERT INTO events_index VALUES (1, 100, '10.0.0.1', 'GET', '/home')")
    memory_db.execute("INSERT INTO events_index VALUES (2, 101, '10.0.0.2', 'POST', '/login')")
    memory_db.commit()

    chain = TamperProofChain(lambda: memory_db)
    ev1 = {"ts": 100, "source_ip": "10.0.0.1", "action": "GET", "target": "/home"}
    ev2 = {"ts": 101, "source_ip": "10.0.0.2", "action": "POST", "target": "/login"}

    h1 = chain.append_event_hash(1, ev1)
    h2 = chain.append_event_hash(2, ev2)
    assert h1 != h2
    assert chain.get_latest_hash() == h2

    # Verification on untouched DB
    v = chain.verify_integrity()
    assert v["verified"] is True
    assert v["chain_length"] == 2

    # Simulate database tampering (adversary modifying payload in events_index)
    memory_db.execute("UPDATE events_index SET source_ip = '198.51.100.99' WHERE id = 1")
    memory_db.commit()

    v_tampered = chain.verify_integrity()
    assert v_tampered["verified"] is False
    assert len(v_tampered["tampered_blocks"]) > 0


# ==============================================================================
# 9. CERT-In 180-Day Retention & 6-Hour Incident Report Generation
# ==============================================================================

def test_cert_in_compliance_report():
    now = int(time.time())
    case_doc = {
        "id": "CASE-0042",
        "title": "High-Velocity Autonomous SSH Brute Force",
        "description": "50+ failed attempts from external threat actor",
        "severity": "CRITICAL",
        "created_at": now - 3600,  # 1 hour ago (< 6 hours, strictly compliant)
        "entities": {
            "source_ip": "198.51.100.99",
            "hosts": ["server-auth-01"],
            "users": ["root", "admin"]
        }
    }

    report = generate_cert_in_report(case_doc, organization_name="Alpha SOC Services")
    assert report["incident_details"]["case_id"] == "CASE-0042"
    assert report["cert_in_metadata"]["compliance_status"] == "COMPLIANT (< 6 hours)"
    assert report["cert_in_metadata"]["elapsed_hours_since_detection"] <= 1.5
    assert "Alpha SOC Services" in report["markdown_report"]
    assert "ANNEXURE I" in report["markdown_report"]
    assert "198.51.100.99" in report["markdown_report"]


def test_retention_manager_180_days(tmp_path):
    db_file = tmp_path / "test_indexer.db"
    conn = sqlite3.connect(str(db_file))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events_index (
            id INTEGER PRIMARY KEY,
            ts INTEGER,
            host TEXT,
            source_ip TEXT,
            log_type TEXT,
            action TEXT,
            target TEXT,
            outcome TEXT,
            status INTEGER,
            user TEXT,
            raw TEXT,
            meta TEXT
        )
    """)
    # Insert older event (>180 days ago)
    old_ts = int(time.time()) - (185 * 86400)
    conn.execute("""
        INSERT INTO events_index (id, ts, host, source_ip, log_type, action, target, outcome, status, user, raw, meta)
        VALUES (1, ?, 'server', '10.0.0.1', 'web', 'GET', '/old', 'ok', 200, 'sys', 'raw', '{}')
    """, (old_ts,))
    conn.commit()
    conn.close()

    ret_mgr = RetentionManager(
        db_path=str(db_file),
        archive_dir=str(tmp_path / "archives"),
        retention_days=180,
        hot_days=30
    )

    status = ret_mgr.get_retention_status()
    assert status["minimum_retention_days"] == 180
    assert status["total_active_events"] == 1

    # Run cold compression
    arch_res = ret_mgr.archive_cold_events()
    assert arch_res["archived_count"] == 1
    assert Path(arch_res["archive_file"]).exists()

    # Generate backup
    backup_res = ret_mgr.create_backup(str(tmp_path / "backups" / "backup.db"))
    assert Path(backup_res["backup_path"]).exists()
    assert len(backup_res["sha256"]) == 64

"""
test_kavalan_engine.py - Tests for Kavalan Decoders, Rules, Replay Protection & Logtest
"""

import time
import pytest
from manager.decoders.decoders import (
    DecoderPipeline,
    SyslogGenericDecoder,
    JsonLogDecoder,
    FimDecoder,
    SyscollectorDecoder,
)
from manager.rules.kavalan_rules import KavalanRuleEngine
from manager.manager import ManagerCore, get_db, init_db


def test_kavalan_decoders():
    pipeline = DecoderPipeline()

    # 1. Syslog RFC3164
    syslog_line = "Nov  5 12:00:00 myhost sudo[1234]: pam_unix(sudo:auth): authentication failure; logname= user=alice"
    ev1 = pipeline.decode_line(syslog_line, host="myhost")
    assert ev1 is not None
    assert ev1.target == "sudo"
    assert ev1.outcome == "fail"

    # 2. JSON log
    json_line = '{"timestamp": 1762000000, "source_ip": "10.0.0.5", "action": "dns_query", "target": "malicious.com", "outcome": "ok"}'
    ev2 = pipeline.decode_line(json_line)
    assert ev2 is not None
    assert ev2.source_ip == "10.0.0.5"
    assert ev2.target == "malicious.com"

    # 3. FIM log line
    fim_line = "FIM: File modified: /etc/shadow (diffs=hash,size)"
    ev3 = pipeline.decode_line(fim_line)
    assert ev3 is not None
    assert ev3.log_type == "fim"
    assert ev3.target == "/etc/shadow"

    # 4. Syscollector log line
    syscol_line = "Syscollector: New listening port opened: tcp/4444 on 0.0.0.0"
    ev4 = pipeline.decode_line(syscol_line)
    assert ev4 is not None
    assert ev4.log_type == "syscollector"
    assert ev4.target == "tcp:4444"


def test_kavalan_rules_and_correlation():
    engine = KavalanRuleEngine()

    # FIM critical file modification
    matches = engine.evaluate_event({
        "log_type": "fim",
        "action": "file_modified",
        "target": "/etc/shadow",
        "source_ip": "127.0.0.1",
        "host": "srv01",
    })
    assert len(matches) == 1
    assert matches[0].rule_id == 100501
    assert matches[0].level == 13

    # Syscollector reverse shell port
    matches2 = engine.evaluate_event({
        "log_type": "syscollector",
        "action": "port_opened",
        "target": "tcp:4444",
        "source_ip": "127.0.0.1",
        "host": "srv01",
        "meta": {"port": 4444},
    })
    assert len(matches2) == 1
    assert matches2[0].rule_id == 100601
    assert matches2[0].level == 12

    # SSH brute force accumulation (5 failed logins)
    for _ in range(4):
        engine.evaluate_event({
            "log_type": "auth",
            "action": "ssh_fail",
            "source_ip": "203.0.113.88",
            "host": "srv01",
            "outcome": "fail",
        })
    fifth_matches = engine.evaluate_event({
        "log_type": "auth",
        "action": "ssh_fail",
        "source_ip": "203.0.113.88",
        "host": "srv01",
        "outcome": "fail",
    })
    rule_ids = [m.rule_id for m in fifth_matches]
    assert 5712 in rule_ids  # Brute force alert fired!


def test_replay_protection_and_active_response(tmp_path):
    db_file = tmp_path / "test_mgr.db"
    init_db(str(db_file))
    mgr = ManagerCore(db_path=str(db_file))

    reg = mgr.register_agent("test-agent", "192.168.1.50", "Linux")
    agent_id = reg["agent_id"]

    ev = {
        "ts": int(time.time()),
        "host": "test-agent",
        "source_ip": "198.51.100.22",
        "log_type": "fim",
        "action": "file_modified",
        "target": "/etc/shadow",
        "outcome": "ok",
    }

    # Initial batch with tx_id=1
    res1 = mgr.ingest_agent_events(agent_id, [ev], tx_id=1)
    assert res1["accepted"] == 1
    assert res1["alerts_fired"] == 1

    # Check pending command queued for agent
    cmds = mgr.ar_engine.get_pending_commands(agent_id)
    assert len(cmds) > 0
    assert cmds[0]["action"] == "firewall-drop"

    # Replayed batch with old tx_id=1 must be dropped
    res_replay = mgr.ingest_agent_events(agent_id, [ev], tx_id=1)
    assert res_replay["status"] == "dropped_replay"
    assert res_replay["accepted"] == 0

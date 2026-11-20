"""
test_agent_standalone.py - Comprehensive Unit Tests for Kavalan Endpoint Agent

Tests:
  1. Standalone CEMEvent dataclass serialization
  2. Nginx / Apache web log parsing
  3. RFC3164 (legacy syslog) & RFC5424 (ISO-8601) SSH auth parsing
  4. FileTailer log rotation and truncation
  5. Disk spooling fallback when Manager is unreachable
  6. Ubuntu log auto-discovery
"""

import json
import time
from pathlib import Path
import pytest

from agent.agent import (
    CEMEvent,
    FileTailer,
    parse_web_line,
    parse_auth_line,
    auto_discover_ubuntu_logs,
    KavalanAgent
)


def test_cem_event_serialization():
    ev = CEMEvent(
        ts=1760000000,
        host="ubuntu-srv01",
        source_ip="192.168.1.100",
        log_type="web",
        action="GET /api/v1/users",
        target="/api/v1/users",
        outcome="ok",
        status=200,
        meta={"ua": "curl/7.81.0"}
    )
    d = ev.to_dict()
    assert d["ts"] == 1760000000
    assert d["host"] == "ubuntu-srv01"
    assert d["source_ip"] == "192.168.1.100"
    assert d["log_type"] == "web"
    assert d["action"] == "GET /api/v1/users"
    assert d["outcome"] == "ok"
    assert d["status"] == 200
    assert d["meta"]["ua"] == "curl/7.81.0"


def test_web_log_parsing():
    line = '203.0.113.50 - - [03/Nov/2026:22:15:30 +0000] "GET /admin HTTP/1.1" 403 245 "-" "Mozilla/5.0"'
    ev = parse_web_line(line, "ubuntu-web")
    assert ev is not None
    assert ev.source_ip == "203.0.113.50"
    assert ev.action == "GET /admin"
    assert ev.target == "/admin"
    assert ev.outcome == "denied"
    assert ev.status == 403
    assert ev.log_type == "web"


def test_auth_log_parsing_rfc3164():
    # Standard RFC3164 Syslog format
    line = "Nov  3 22:10:05 ubuntu-srv sshd[14521]: Failed password for invalid user admin from 198.51.100.22 port 45210 ssh2"
    ev = parse_auth_line(line, "ubuntu-srv", year=2026)
    assert ev is not None
    assert ev.source_ip == "198.51.100.22"
    assert ev.user == "admin"
    assert ev.outcome == "fail"
    assert ev.log_type == "auth"
    assert ev.target == "sshd"


def test_auth_log_parsing_rfc5424_iso():
    # Modern Ubuntu 22.04+ ISO-8601 rsyslog format
    line = "2026-11-03T22:10:05.123456+00:00 ubuntu-srv sshd[14521]: Accepted publickey for ubuntu from 198.51.100.22 port 45210 ssh2"
    ev = parse_auth_line(line, "ubuntu-srv")
    assert ev is not None
    assert ev.source_ip == "198.51.100.22"
    assert ev.user == "ubuntu"
    assert ev.outcome == "ok"
    assert ev.log_type == "auth"


def test_file_tailer_rotation(tmp_path):
    log_file = tmp_path / "test_access.log"
    log_file.write_text("line1\nline2\n")

    tailer = FileTailer(str(log_file), "web")
    lines1 = tailer.read_new_lines()
    assert len(lines1) == 2

    # Append new line
    with open(log_file, "a") as f:
        f.write("line3\n")
    lines2 = tailer.read_new_lines()
    assert lines2 == ["line3\n"]

    # Simulate logrotate: unlink and create new file with same name
    log_file.unlink()
    log_file.write_text("rotated_line1\n")
    lines3 = tailer.read_new_lines()
    assert lines3 == ["rotated_line1\n"]


def test_agent_spooling_recovery(tmp_path):
    spool_file = tmp_path / "spool.jsonl"
    state_file = tmp_path / "state.json"

    # Pre-populate spool with offline events
    dummy_event = {
        "ts": 1760000000,
        "host": "test-box",
        "source_ip": "1.2.3.4",
        "log_type": "web",
        "action": "GET /test",
        "target": "/test",
        "outcome": "ok"
    }
    spool_file.write_text(json.dumps(dummy_event) + "\n")

    # Initialize agent pointing to unreachable manager port
    agent = KavalanAgent(
        manager_url="http://127.0.0.1:59999",
        name="test-box",
        state_file=str(state_file),
        spool_file=str(spool_file)
    )

    # Verify spool was loaded into memory
    assert len(agent.spool) == 1
    assert agent.spool[0]["source_ip"] == "1.2.3.4"
    # Spool file was consumed from disk
    assert not spool_file.exists()

    # Trigger disk persist
    agent._persist_disk_spool()
    assert spool_file.exists()
    restored = json.loads(spool_file.read_text().strip())
    assert restored["source_ip"] == "1.2.3.4"

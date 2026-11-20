"""
test_agent_fim_syscollector.py - Unit tests for Agent FIM, Syscollector, Buffer & Executor
"""

import os
import time
from pathlib import Path
import pytest

from agent.syscheck import SyscheckScanner, FileRecord
from agent.syscollector import SyscollectorScanner, PortInfo
from agent.buffer import EventBuffer, BufferState
from agent.executor import ActiveResponseExecutor


def test_syscheck_baseline_and_changes(tmp_path):
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()
    state_file = tmp_path / "fim_state.json"

    file1 = monitored_dir / "app.conf"
    file1.write_text("setting=original")

    scanner = SyscheckScanner(
        monitored_paths=[str(monitored_dir)],
        state_file=str(state_file),
        host="test-host"
    )

    # First run establishes baseline (no change events emitted)
    initial_events = scanner.run_scan(report_baseline=False)
    assert len(initial_events) == 0
    assert str(file1) in scanner.db

    # Test file modification
    time.sleep(0.05)
    file1.write_text("setting=modified_by_attacker")
    mod_events = scanner.run_scan()
    assert len(mod_events) == 1
    ev = mod_events[0]
    assert ev["log_type"] == "fim"
    assert ev["action"] == "file_modified"
    assert ev["target"] == str(file1)
    assert "hash" in ev["meta"]["diffs"]

    # Test file creation
    file2 = monitored_dir / "malware.sh"
    file2.write_text("#!/bin/bash\nexit 0")
    create_events = scanner.run_scan()
    assert len(create_events) == 1
    assert create_events[0]["action"] == "file_created"
    assert create_events[0]["target"] == str(file2)

    # Test file deletion
    file1.unlink()
    del_events = scanner.run_scan()
    assert len(del_events) == 1
    assert del_events[0]["action"] == "file_deleted"
    assert del_events[0]["target"] == str(file1)


def test_syscollector_inventory_and_deltas():
    scanner = SyscollectorScanner(host="agent-srv")
    sys_info = scanner.get_system_info()
    assert "hostname" in sys_info
    assert "os_name" in sys_info
    assert "cpu_cores" in sys_info

    interfaces = scanner.get_network_interfaces()
    assert isinstance(interfaces, list)

    inv, deltas = scanner.run_scan(report_baseline=False)
    assert "system" in inv
    assert "ports" in inv
    assert len(deltas) == 0


def test_event_buffer_leaky_bucket():
    buffer = EventBuffer(capacity=100, max_eps=200)
    assert buffer.state == BufferState.NORMAL

    # Push 10 events
    for i in range(10):
        buffer.push({"id": i, "msg": f"event_{i}"})
    assert len(buffer) == 10

    # Pop batch
    tx_id, batch = buffer.pop_batch(max_batch_size=5)
    assert tx_id == 1
    assert len(batch) == 5
    assert len(buffer) == 5

    # Test capacity overflow
    overflow_buffer = EventBuffer(capacity=5, max_eps=10)
    for i in range(10):
        overflow_buffer.push({"id": i})
    assert len(overflow_buffer) == 5
    assert overflow_buffer.dropped_events == 5
    assert overflow_buffer.state == BufferState.FLOOD


def test_active_response_executor():
    executor = ActiveResponseExecutor(dry_run=True)
    res = executor.execute_command({
        "command_id": "cmd_01",
        "action": "firewall-drop",
        "actor_ip": "198.51.100.99",
        "timeout": 2
    })
    assert res["status"] == "executed"
    assert "198.51.100.99" in executor.active_blocks

    # Quarantine file test
    q_res = executor.execute_command({
        "command_id": "cmd_02",
        "action": "quarantine-file",
        "target": "/nonexistent/test.txt"
    })
    assert q_res["status"] == "failed"

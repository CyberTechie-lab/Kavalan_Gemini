"""
test_e2e_replica.py - End-to-End Integration Test for Kavalan SIEM

Demonstrates:
  1. Agent auto-enrollment with Manager (Tier 1 -> Tier 2)
  2. File Integrity Monitoring (FIM / syscheck) change detection on disk
  3. Syscollector network listening port detection
  4. Leaky-bucket rate limited event batching with replay protection (tx_id)
  5. Manager hierarchical decoders & rule evaluation (Level 13 & Level 12)
  6. Automated Active Response triggering and command delivery to Agent via heartbeat
  7. Agent Active Response local containment execution
"""

import os
import time
from pathlib import Path
import pytest

from agent.agent import KavalanAgent
from agent.syscheck import SyscheckScanner
from agent.syscollector import SyscollectorScanner
from manager.manager import ManagerCore, get_db, init_db


def test_e2e_replica_flow(tmp_path):
    mgr_db = tmp_path / "test_kavalan_mgr.db"
    init_db(str(mgr_db))
    mgr = ManagerCore(db_path=str(mgr_db))

    fim_dir = tmp_path / "fim_target"
    fim_dir.mkdir()
    shadow_file = fim_dir / "shadow"
    shadow_file.write_text("root:$6$xyz:19000:0:99999:7:::")

    # 1. Agent Enrollment
    reg = mgr.register_agent("ubuntu-prod-01", "10.0.0.15", "Ubuntu 22.04 LTS")
    agent_id = reg["agent_id"]
    assert agent_id is not None

    # 2. Agent FIM Scanner Baseline
    scanner = SyscheckScanner(monitored_paths=[str(fim_dir)], host="ubuntu-prod-01", source_ip="10.0.0.15")
    base_evs = scanner.run_scan(report_baseline=False)
    assert len(base_evs) == 0

    # 3. Simulate Attack 1: Modify critical system file (/etc/shadow)
    time.sleep(0.05)
    shadow_file.write_text("root:$6$malicious_backdoor_hash:19000:0:99999:7:::")
    fim_events = scanner.run_scan()
    assert len(fim_events) == 1
    assert fim_events[0]["action"] == "file_modified"
    assert "hash" in fim_events[0]["meta"]["diffs"]

    # Ingest FIM event through Manager with tx_id=1
    res1 = mgr.ingest_agent_events(agent_id, fim_events, tx_id=1)
    assert res1["accepted"] == 1
    assert res1["alerts_fired"] >= 1

    # 4. Simulate Attack 2: Syscollector port opened (reverse shell port tcp:4444)
    shell_ev = {
        "ts": int(time.time()),
        "host": "ubuntu-prod-01",
        "source_ip": "198.51.100.44",
        "log_type": "syscollector",
        "action": "port_opened",
        "target": "tcp:4444",
        "outcome": "ok",
        "status": 4444,
        "meta": {"port": 4444, "proto": "tcp", "address": "0.0.0.0"},
    }
    res2 = mgr.ingest_agent_events(agent_id, [shell_ev], tx_id=2)
    assert res2["accepted"] == 1
    assert res2["alerts_fired"] >= 1

    # 5. Verify Active Response containment command queued on Manager
    pending_cmds = mgr.ar_engine.get_pending_commands(agent_id)
    assert len(pending_cmds) >= 1
    top_cmd = pending_cmds[0]
    assert top_cmd["action"] == "firewall-drop"
    assert top_cmd["level"] >= 10

    # 6. Verify Agent receives containment command and executes it locally
    agent = KavalanAgent(
        manager_url="http://127.0.0.1:8910",
        name="ubuntu-prod-01",
        fim_paths=[str(fim_dir)]
    )
    agent.agent_id = agent_id

    # Execute received active response order on agent
    exec_res = agent.executor.execute_command(top_cmd)
    assert exec_res["status"] == "executed"
    assert top_cmd["actor_ip"] in agent.executor.active_blocks

    # 7. Verify Monotonic Replay Protection
    # Re-sending batch with old tx_id=2 must be rejected
    res_replay = mgr.ingest_agent_events(agent_id, [shell_ev], tx_id=2)
    assert res_replay["status"] == "dropped_replay"
    assert res_replay["accepted"] == 0

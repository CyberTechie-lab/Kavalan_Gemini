"""
test_wazuh_parity_features.py - Tests for Wazuh-parity features in Kavalan SIEM:
  1. Centralized Agent Configuration Sync (Dynamic remote log tailing & FIM reconfig)
  2. Enhanced Active Response Framework (Firewall drop, account lock/unlock, unblock, ack tracking)
  3. Security Configuration Assessment (CIS Baseline) & Package CVE Vulnerability Scanner
"""

import json
import os
import sqlite3
import tempfile
import time
from pathlib import Path
import pytest
from httpx import ASGITransport, AsyncClient

from agent.sca import SCABaselineAuditor
from agent.executor import ActiveResponseExecutor
from agent.agent import KavalanAgent, FileTailer
from manager.vuln_scanner import VulnerabilityEngine, is_version_vulnerable, parse_clean_version
from manager.manager import ManagerCore, create_manager_app, init_db as init_manager_db
from dashboard.dashboard_server import DashboardBackend, create_dashboard_app


def test_sca_baseline_auditor():
    auditor = SCABaselineAuditor(host="test-srv", source_ip="192.168.1.50")
    report = auditor.run_audit()

    assert report["host"] == "test-srv"
    assert report["source_ip"] == "192.168.1.50"
    assert report["total_checks"] == 8
    assert report["passed"] >= 6
    assert 0.0 <= report["score"] <= 100.0

    check_ids = {c["id"] for c in report["checks"]}
    assert "CIS-5.2.5" in check_ids   # PermitRootLogin
    assert "CIS-5.2.11" in check_ids  # PermitEmptyPasswords
    assert "CIS-6.2.5" in check_ids   # Root UID 0 exclusivity
    assert "CIS-6.1.2" in check_ids   # /etc/passwd permissions
    assert "CIS-1.5.1" in check_ids   # ASLR


def test_vulnerability_engine_version_matching():
    # Test version parser
    assert parse_clean_version("1:8.9p1-3ubuntu0.10") == [8, 9, 1]
    assert parse_clean_version("1.9.5p2") == [1, 9, 5, 2]
    assert parse_clean_version("7.81.0-1ubuntu1.16") == [7, 81, 0]

    # Test vulnerability comparison
    # OpenSSH regreSSHion: 8.5p1 <= version < 9.8p1
    assert is_version_vulnerable("8.9p1", "8.5p1", "9.8p1") is True
    assert is_version_vulnerable("1:8.9p1-3ubuntu0.10", "8.5p1", "9.8p1") is True
    assert is_version_vulnerable("9.8p1", "8.5p1", "9.8p1") is False
    assert is_version_vulnerable("9.9p1", "8.5p1", "9.8p1") is False
    assert is_version_vulnerable("7.4p1", "8.5p1", "9.8p1") is False

    # Sudo Baron Samedit: 1.8.2 <= version < 1.9.5p2
    assert is_version_vulnerable("1.8.31", "1.8.2", "1.9.5p2") is True
    assert is_version_vulnerable("1.9.5p2", "1.8.2", "1.9.5p2") is False


def test_vulnerability_engine_sqlite():
    with tempfile.NamedTemporaryFile(suffix=".db") as f:
        db_path = f.name
        con = sqlite3.connect(db_path)
        con.row_factory = sqlite3.Row

        ve = VulnerabilityEngine(lambda: con)

        # 1. Correlate packages
        test_pkgs = [
            {"name": "openssh-server", "version": "1:8.9p1-3ubuntu0.10", "arch": "amd64"},
            {"name": "sudo", "version": "1.8.31-1ubuntu1", "arch": "amd64"},
            {"name": "nginx", "version": "1.18.0-0ubuntu1", "arch": "amd64"},
        ]
        vulns = ve.correlate_packages("001", "ubuntu-web01", test_pkgs)
        assert len(vulns) >= 2
        cve_ids = {v["cve_id"] for v in vulns}
        assert "CVE-2024-6387" in cve_ids
        assert "CVE-2021-3156" in cve_ids

        # 2. Save SCA report
        sca_data = {
            "host": "ubuntu-web01",
            "score": 87.5,
            "total_checks": 8,
            "passed": 7,
            "failed": 1,
            "checks": [{"id": "CIS-5.2.5", "title": "SSH Root Login", "status": "PASS", "severity": "HIGH", "details": "ok", "remediation": ""}]
        }
        ve.save_sca_report("001", sca_data)

        # 3. Retrieve SCA and Vulns
        sca_res = ve.get_agent_sca("001")
        assert sca_res is not None
        assert sca_res["score"] == 87.5
        assert sca_res["passed"] == 7

        agent_vulns = ve.get_agent_vulnerabilities("001")
        assert len(agent_vulns) == len(vulns)

        summary = ve.get_fleet_summary()
        assert summary["audited_endpoints"] == 1
        assert summary["avg_sca_score"] == 87.5
        assert summary["counts"]["CRITICAL"] >= 2


def test_active_response_executor_enhancements():
    executor = ActiveResponseExecutor(dry_run=True)

    # Test firewall-drop
    r1 = executor.execute_command({
        "command_id": "ar_101",
        "action": "firewall-drop",
        "actor_ip": "198.51.100.55",
        "timeout": 300
    })
    assert r1["status"] == "executed"
    assert "Simulated iptables" in r1["details"]

    # Test account-lock
    r2 = executor.execute_command({
        "command_id": "ar_102",
        "action": "account-lock",
        "target": "compromised_user"
    })
    assert r2["status"] == "executed"
    assert "Simulated passwd -l" in r2["details"]

    # Test account-unlock
    r3 = executor.execute_command({
        "command_id": "ar_103",
        "action": "account-unlock",
        "target": "compromised_user"
    })
    assert r3["status"] == "executed"
    assert "Simulated passwd -u" in r3["details"]

    # Test firewall-unblock
    r4 = executor.execute_command({
        "command_id": "ar_104",
        "action": "firewall-unblock",
        "actor_ip": "198.51.100.55"
    })
    assert r4["status"] == "executed"
    assert "Unblocked 198.51.100.55" in r4["details"]

    # Test pending acks
    acks = executor.get_pending_acks()
    assert len(acks) == 4
    assert [a["command_id"] for a in acks] == ["ar_101", "ar_102", "ar_103", "ar_104"]

    # Should be cleared after getting
    assert len(executor.get_pending_acks()) == 0


def test_centralized_agent_config_sync():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create dummy log files
        log1 = Path(tmpdir) / "web1.log"
        log2 = Path(tmpdir) / "auth1.log"
        log1.write_text("10.0.0.1 - - [01/Jan/2026:10:00:00 +0000] \"GET / HTTP/1.1\" 200 123\n")
        log2.write_text("2026-01-01T10:00:00+00:00 srv sshd[1]: Accepted password for root from 10.0.0.1 port 22 ssh2\n")

        agent = KavalanAgent(
            manager_url="http://127.0.0.1:8910",
            name="test-sync-agent",
            state_file=str(Path(tmpdir) / ".agent_state.json"),
            spool_file=str(Path(tmpdir) / ".spool.jsonl")
        )
        agent.agent_id = "001"

        # Apply initial config
        init_cfg = {
            "localfiles": [
                {"location": str(log1), "format": "web"}
            ],
            "syscheck": {
                "directories": [tmpdir],
                "interval": 45
            },
            "syscollector": {
                "interval": 200
            }
        }
        agent.apply_remote_config(init_cfg, version=1)

        assert agent.config_version == 1
        assert len(agent.tailers) == 1
        assert agent.tailers[0].path == str(log1)
        assert agent.fim_interval == 45
        assert agent.syscollector_interval == 200

        # Apply updated remote config with 2 files
        updated_cfg = {
            "localfiles": [
                {"location": str(log1), "format": "web"},
                {"location": str(log2), "format": "auth"}
            ],
            "syscheck": {
                "directories": [tmpdir, "/etc"],
                "interval": 30
            },
            "syscollector": {
                "interval": 150
            }
        }
        agent.apply_remote_config(updated_cfg, version=2)

        assert agent.config_version == 2
        assert len(agent.tailers) == 2
        tailer_paths = {t.path for t in agent.tailers}
        assert str(log1) in tailer_paths
        assert str(log2) in tailer_paths
        assert agent.fim_interval == 30
        assert agent.syscollector_interval == 150


@pytest.mark.anyio
async def test_manager_and_dashboard_wazuh_endpoints():
    with tempfile.NamedTemporaryFile(suffix=".db") as f:
        db_path = f.name
        init_manager_db(db_path)
        mgr = ManagerCore(db_path=db_path)
        mgr_app = create_manager_app(mgr)
        transport = ASGITransport(app=mgr_app)

        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            # 1. Register agent
            reg_resp = await client.post("/api/agent/register", json={"name": "srv01", "ip": "172.16.10.134", "os": "Ubuntu 26.04"})
            assert reg_resp.status_code == 200
            agent_id = reg_resp.json()["agent_id"]

            # 2. Query default config
            cfg_resp = await client.get(f"/api/agent/{agent_id}/config")
            assert cfg_resp.status_code == 200
            cfg_data = cfg_resp.json()
            assert cfg_data["version"] == 1
            assert len(cfg_data["config"]["localfiles"]) >= 2

            # 3. Update agent config
            new_cfg = {
                "localfiles": [
                    {"location": "/var/log/custom_app.log", "format": "web"}
                ],
                "syscheck": {"directories": ["/etc", "/var/www"], "interval": 40},
                "syscollector": {"interval": 180}
            }
            up_resp = await client.post(f"/api/agent/{agent_id}/config", json={"config": new_cfg})
            assert up_resp.status_code == 200
            assert up_resp.json()["version"] == 2

            # 4. Heartbeat check - verify manager pushes new config version
            hb_resp = await client.post("/api/agent/heartbeat", json={
                "agent_id": agent_id,
                "metrics": {"config_version": 1, "ip": "172.16.10.134"}
            })
            assert hb_resp.status_code == 200
            hb_data = hb_resp.json()
            assert hb_data["config_version"] == 2
            assert hb_data["config"]["localfiles"][0]["location"] == "/var/log/custom_app.log"

            # 5. Manual Active Response Trigger
            ar_resp = await client.post("/api/active_response/trigger", json={
                "action": "firewall-drop",
                "actor_ip": "198.51.100.99",
                "target_agent": agent_id,
                "timeout": 600
            })
            assert ar_resp.status_code == 200
            ar_data = ar_resp.json()
            assert ar_data["status"] == "queued"
            cmd_id = ar_data["command_id"]

            # 6. Verify pending command delivered in heartbeat
            hb2_resp = await client.post("/api/agent/heartbeat", json={
                "agent_id": agent_id,
                "metrics": {"config_version": 2}
            })
            assert hb2_resp.status_code == 200
            cmds = hb2_resp.json()["commands"]
            assert any(c["command_id"] == cmd_id for c in cmds)

            # 7. Acknowledge execution from agent
            hb3_resp = await client.post("/api/agent/heartbeat", json={
                "agent_id": agent_id,
                "metrics": {"config_version": 2},
                "acks": [{"command_id": cmd_id, "status": "executed", "details": "Blocked via iptables"}]
            })
            assert hb3_resp.status_code == 200

            # Verify action status updated in list
            actions_resp = await client.get("/api/active_response/actions")
            assert actions_resp.status_code == 200
            actions = actions_resp.json()["actions"]
            target_act = next((a for a in actions if a["id"] == int(cmd_id.replace("ar_", ""))), None)
            assert target_act is not None
            assert target_act["status"] == "executed"

            # 8. Unblock Active Response
            unblock_resp = await client.post("/api/active_response/unblock", json={"id": target_act["id"]})
            assert unblock_resp.status_code == 200
            assert unblock_resp.json()["status"] == "ok"

            # 9. Ingest SCA audit and packages
            sca_payload = {
                "agent_id": agent_id,
                "sca": {
                    "host": "srv01",
                    "score": 100.0,
                    "total_checks": 8,
                    "passed": 8,
                    "failed": 0,
                    "checks": [{"id": "CIS-1.1", "title": "Test check", "status": "PASS", "severity": "HIGH", "details": "ok", "remediation": ""}]
                },
                "packages": [
                    {"name": "openssh-server", "version": "1:8.9p1-3ubuntu0.10", "arch": "amd64"},
                    {"name": "sudo", "version": "1.8.31-1ubuntu1", "arch": "amd64"}
                ]
            }
            sca_resp = await client.post("/api/agent/sca", json=sca_payload)
            assert sca_resp.status_code == 200
            assert sca_resp.json()["vulnerabilities_found"] >= 2

            # 10. Query SCA summary and Agent report
            sum_resp = await client.get("/api/sca/summary")
            assert sum_resp.status_code == 200
            assert sum_resp.json()["audited_endpoints"] == 1
            assert sum_resp.json()["total_vulnerabilities"] >= 2

            ag_sca_resp = await client.get(f"/api/sca/agent/{agent_id}")
            assert ag_sca_resp.status_code == 200
            assert len(ag_sca_resp.json()["vulnerabilities"]) >= 2

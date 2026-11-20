import pytest
import time
from pathlib import Path
from threat_intel import ThreatIntelEngine
from soar_playbook_engine import AutonomousSoarPlaybookEngine


def test_threat_intel_lookup_and_seed(tmp_path):
    db_file = tmp_path / "ti_test.db"
    ti = ThreatIntelEngine(str(db_file))

    # Test seeded known malicious IOC
    res = ti.lookup("203.0.113.154")
    assert res["found"] is True
    assert res["reputation"] == "MALICIOUS"
    assert res["threat_score"] >= 95
    assert "RU" in res["country"]
    assert "Hostkey" in res["asn"]

    # Test Tor exit node
    tor_res = ti.lookup("185.220.101.5")
    assert tor_res["found"] is True
    assert tor_res["is_tor_exit"] is True
    assert tor_res["reputation"] in ("SUSPICIOUS", "MALICIOUS")

    # Test RFC 1918 Private IP
    lan_res = ti.lookup("192.168.1.100")
    assert lan_res["is_private"] is True
    assert lan_res["reputation"] == "BENIGN"
    assert lan_res["threat_score"] == 0

    # Test Loopback
    local_res = ti.lookup("127.0.0.1")
    assert local_res["is_loopback"] is True
    assert local_res["reputation"] == "BENIGN"


def test_threat_intel_custom_ioc_and_summary(tmp_path):
    db_file = tmp_path / "ti_custom.db"
    ti = ThreatIntelEngine(str(db_file))

    custom = ti.add_ioc(
        ioc="198.51.100.250",
        ioc_type="ip",
        threat_score=90,
        threat_level="CRITICAL",
        reputation="MALICIOUS",
        feed="SOC Blacklist",
        categories=["Data Exfiltration"],
        country="IS",
        country_name="Iceland",
        asn="AS12345 Bulletproof",
        is_tor=False,
        description="Observed staging stolen database dumps."
    )
    assert custom["found"] is True
    assert custom["threat_score"] == 90
    assert custom["country"] == "IS"

    summary = ti.get_summary()
    assert summary["total_iocs"] >= 11
    assert summary["malicious_iocs"] >= 5


def test_autonomous_soar_playbook_execution(tmp_path):
    db_file = tmp_path / "soar_test.db"
    soar = AutonomousSoarPlaybookEngine(str(db_file))

    playbooks = soar.get_playbooks()
    assert len(playbooks) >= 3

    # Toggle playbook
    soar.toggle_playbook("PB-AUTO-001", False)
    updated = [p for p in soar.get_playbooks() if p["id"] == "PB-AUTO-001"][0]
    assert updated["is_enabled"] is False

    soar.toggle_playbook("PB-AUTO-001", True)

    # Mock Manager Core for testing execution
    class MockManager:
        def __init__(self):
            self.ar_calls = []
            self.cases_created = []
            self.webhooks_called = []

        def queue_active_response(self, command, target, target_agent, timeout, reason):
            self.ar_calls.append({"cmd": command, "target": target, "timeout": timeout})
            return {"id": "AR-MOCK-1", "status": "queued"}

        def create_case(self, title, description, severity, entities, assignee):
            self.cases_created.append({"title": title, "severity": severity})
            return {"id": "CASE-MOCK-1", "status": "created"}

        def dispatch_webhooks(self, alert_payload, event_type):
            self.webhooks_called.append(event_type)
            return {"dispatched": 1}

    mock_mgr = MockManager()

    # Trigger Alert with High Threat Intel score (should trigger PB-AUTO-001)
    alert = {
        "source_ip": "203.0.113.154",
        "level": 10,
        "summary": "AI Agent intrusion attempt",
        "threat_intel": {
            "threat_score": 95,
            "is_tor_exit": False
        }
    }

    runs = soar.evaluate_alert(alert, manager_core=mock_mgr)
    assert len(runs) >= 1
    assert runs[0]["playbook_id"] == "PB-AUTO-001"
    assert runs[0]["status"] == "SUCCESS"
    assert len(mock_mgr.ar_calls) >= 1
    assert mock_mgr.ar_calls[0]["cmd"] == "firewall-drop"
    assert len(mock_mgr.cases_created) >= 1

    # Check runs history
    recent = soar.get_recent_runs()
    assert len(recent) >= 1
    assert recent[0]["playbook_name"] == "Auto-Quarantine High-Risk Malicious IOCs"


def test_autonomous_soar_manual_trigger(tmp_path):
    db_file = tmp_path / "soar_manual.db"
    soar = AutonomousSoarPlaybookEngine(str(db_file))

    class MockManager:
        def queue_active_response(self, **kwargs):
            return {"id": "AR-TEST"}
        def create_case(self, **kwargs):
            return {"id": "CASE-TEST"}
        def dispatch_webhooks(self, **kwargs):
            return {"dispatched": 0}

    res = soar.run_manual("PB-AUTO-003", target="198.51.100.99", manager_core=MockManager())
    assert res["status"] == "SUCCESS"
    assert res["trigger_source"] == "manual_simulation"
    assert res["trigger_entity"] == "198.51.100.99"

"""
test_detection_rules_and_sigma.py - Test Suite for Custom Detection Rules & Sigma Importer

Tests:
  1. Zero-dependency Sigma YAML parser & conversion to Kavalan CEM rules
  2. Rule validation, MITRE ATT&CK extraction, and severity mappings
  3. Dynamic custom rule evaluation in KavalanRuleEngine (modifiers: contains, endswith, regex, not)
  4. Frequency/timeframe stateful correlation accumulator with custom rules
  5. Manager REST API endpoints: /api/rules, /api/rules/templates, /api/rules/sigma/convert, /api/rules/test
"""

import json
import pytest
from httpx import ASGITransport, AsyncClient

from manager.rules.sigma_converter import SigmaRuleConverter, parse_simple_yaml
from manager.rules.kavalan_rules import KavalanRuleEngine
from manager.manager import ManagerCore, create_manager_app, init_db as init_manager_db


def test_parse_simple_yaml():
    yaml_text = """
title: Test Malicious Curl Execution
description: Detects curl piping to bash
tags:
  - attack.t1059.004
  - attack.execution
logsource:
  category: system
detection:
  selection:
    target|contains:
      - "curl -s"
      - "wget -q"
    action: proc_exec
  condition: selection
level: high
"""
    parsed = parse_simple_yaml(yaml_text)
    assert parsed["title"] == "Test Malicious Curl Execution"
    assert parsed["level"] == "high"
    assert parsed["logsource"]["category"] == "system"
    assert len(parsed["tags"]) == 2
    assert "curl -s" in parsed["detection"]["selection"]["target|contains"]


def test_sigma_converter_and_validation():
    yaml_text = """
title: Suspicious Web Shell Upload
id: c9281a02-1111-2222-3333-444455556666
description: Detects php shell uploaded into uploads dir
tags:
  - attack.t1505.003
  - attack.persistence
logsource:
  category: web
detection:
  selection:
    target|endswith:
      - ".php"
      - ".phtml"
    outcome: ok
  condition: selection
level: critical
"""
    rule = SigmaRuleConverter.convert(yaml_text, rule_id=200099)
    assert rule["id"] == 200099
    assert rule["title"] == "Suspicious Web Shell Upload"
    assert rule["level"] == 13
    assert rule["log_type"] == "web"
    assert rule["mitre_id"] == "T1505.003"
    assert rule["mitre_tactic"] == "Persistence"
    assert rule["active_response"] is True

    valid, msg = SigmaRuleConverter.validate_kavalan_rule(rule)
    assert valid is True
    assert msg == "Valid"


def test_kavalan_engine_custom_rules_modifiers():
    engine = KavalanRuleEngine()

    custom_rule = {
        "id": 200101,
        "name": "php_webshell_detector",
        "title": "PHP Web Shell Uploaded",
        "level": 12,
        "log_type": "fim",
        "match": {
            "action": "file_created",
            "target|endswith": [".php", ".jsp"],
        },
        "frequency": 1,
        "timeframe_sec": 60,
        "mitre_id": "T1505.003",
        "mitre_tactic": "Persistence",
        "enabled": True,
    }
    engine.set_custom_rules([custom_rule])

    # 1. Non-matching event (text file created)
    ev1 = {
        "log_type": "fim",
        "action": "file_created",
        "target": "/var/www/html/readme.txt",
        "source_ip": "192.168.1.10",
        "host": "web-01",
    }
    m1 = engine.evaluate_event(ev1)
    custom_m1 = [m for m in m1 if m.rule_id == 200101]
    assert len(custom_m1) == 0

    # 2. Matching event (.php file created)
    ev2 = {
        "log_type": "fim",
        "action": "file_created",
        "target": "/var/www/html/uploads/c99.php",
        "source_ip": "192.168.1.10",
        "host": "web-01",
    }
    m2 = engine.evaluate_event(ev2)
    custom_m2 = [m for m in m2 if m.rule_id == 200101]
    assert len(custom_m2) == 1
    assert custom_m2[0].name == "php_webshell_detector"
    assert custom_m2[0].level == 12
    assert custom_m2[0].mitre_id == "T1505.003"


def test_kavalan_engine_frequency_accumulator():
    engine = KavalanRuleEngine()

    freq_rule = {
        "id": 200105,
        "name": "fast_admin_403_probe",
        "title": "Fast Admin 403 Forbidden Probe",
        "level": 10,
        "log_type": "web",
        "match": {
            "target|contains": "admin",
            "status": "403",
        },
        "frequency": 3,
        "timeframe_sec": 30,
        "enabled": True,
    }
    engine.set_custom_rules([freq_rule])

    ev = {
        "log_type": "web",
        "target": "/admin/dashboard",
        "status": 403,
        "source_ip": "10.0.0.99",
        "host": "web-01",
    }

    # Attempts 1 and 2 should not fire the custom threshold
    m1 = [m for m in engine.evaluate_event(ev) if m.rule_id == 200105]
    assert len(m1) == 0
    m2 = [m for m in engine.evaluate_event(ev) if m.rule_id == 200105]
    assert len(m2) == 0

    # Attempt 3 reaches threshold -> fires!
    m3 = [m for m in engine.evaluate_event(ev) if m.rule_id == 200105]
    assert len(m3) == 1
    assert m3[0].level == 10
    assert "threshold met" in m3[0].fired_reason.lower()


@pytest.fixture
def manager_rule_stack(tmp_path):
    mgr_db = str(tmp_path / "test_rules_mgr.db")
    init_manager_db(mgr_db)
    mgr_core = ManagerCore(mgr_db, indexer_url="http://test-indexer", window_minutes=15, interval=1)
    mgr_app = create_manager_app(mgr_core)
    return {"mgr_core": mgr_core, "mgr_app": mgr_app, "db": mgr_db}


@pytest.mark.anyio
async def test_manager_rules_endpoints(manager_rule_stack):
    mgr_app = manager_rule_stack["mgr_app"]

    async with AsyncClient(transport=ASGITransport(app=mgr_app), base_url="http://test-mgr") as client:
        # 1. GET /api/rules -> check seeded templates
        res = await client.get("/api/rules")
        assert res.status_code == 200
        data = res.json()
        assert data["total"] >= 5
        assert data["active"] >= 5

        # 2. GET /api/rules/templates
        res_tmpl = await client.get("/api/rules/templates")
        assert res_tmpl.status_code == 200
        templates = res_tmpl.json()["templates"]
        assert len(templates) >= 5

        # 3. POST /api/rules/sigma/convert
        sample_sigma = """
title: Reconnaissance Nmap Scan Detected
logsource:
  category: auth
detection:
  selection:
    target|contains: "nmap"
  condition: selection
level: medium
"""
        res_conv = await client.post("/api/rules/sigma/convert", json={"sigma": sample_sigma})
        assert res_conv.status_code == 200
        converted_rule = res_conv.json()["rule"]
        assert converted_rule["title"] == "Reconnaissance Nmap Scan Detected"
        assert converted_rule["level"] == 7

        # 4. POST /api/rules -> Save the new converted rule
        res_save = await client.post("/api/rules", json=converted_rule)
        assert res_save.status_code == 200
        saved_rule = res_save.json()["rule"]
        rule_id = saved_rule["id"]

        # 5. POST /api/rules/{id}/toggle
        res_tog = await client.post(f"/api/rules/{rule_id}/toggle")
        assert res_tog.status_code == 200
        assert res_tog.json()["enabled"] is False

        # Toggle back on
        await client.post(f"/api/rules/{rule_id}/toggle")

        # 6. POST /api/rules/test -> Logtest sandbox execution
        log_sample = "Feb 23 12:44:01 web-01 sshd[1234]: Failed password for invalid user nmap from 198.51.100.42 port 54321 ssh2"
        res_test = await client.post("/api/rules/test", json={
            "rule": saved_rule,
            "log": log_sample,
            "host": "web-01"
        })
        assert res_test.status_code == 200
        test_out = res_test.json()
        assert test_out["decoded"] is True
        assert test_out["rule_id"] == rule_id

        # 7. DELETE /api/rules/{id}
        res_del = await client.delete(f"/api/rules/{rule_id}")
        assert res_del.status_code == 200
        assert res_del.json()["status"] == "deleted"

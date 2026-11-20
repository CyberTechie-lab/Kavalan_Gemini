"""
test_ai_analyst.py - Unit and Integration Tests for Kavalan AI Threat Reasoning Layer
"""

import pytest
import httpx
from manager.ai.ai_analyst import AIAttackAnalyst
from manager.manager import create_manager_app, ManagerCore


@pytest.fixture
def sample_threat_source():
    return {
        "ip": "203.0.113.66",
        "level": "CRITICAL",
        "cross_source": True,
        "channels": ["web", "ssh"],
        "hosts": ["web-01"],
        "web_score": 95,
        "ssh_score": 100,
        "tactics": {
            "recon_files": 444,
            "path_guessing": 192,
            "command_injection": 234,
            "path_traversal": 180,
            "ssrf": 150,
            "ssh_credential_guessing": 330,
            "ssh_login_success": 6
        },
        "reasons": [
            "1020 requests in its busiest 10 seconds",
            "1800 requests in a 17-second lifetime",
            "81% of responses were refusals or errors",
            "6 tactics: command_injection, path_guessing, path_traversal, protected_resource_probing, recon_files, ssrf",
            "SUCCESSFUL login after 330 failures - account(s): msfadmin"
        ]
    }


def test_ai_actor_analysis(sample_threat_source):
    analyst = AIAttackAnalyst()
    res = analyst.analyze_actor(sample_threat_source["ip"], sample_threat_source, [])

    assert res["ip"] == "203.0.113.66"
    assert res["is_ai_agent"] is True
    assert res["agent_confidence"] >= 85.0
    assert "Autonomous AI" in res["classification"]
    assert len(res["ai_indicators"]) >= 3
    assert len(res["attack_phases"]) >= 3
    assert "msfadmin" in res["compromised_accounts"]
    assert any("iptables" in p["command"] for p in res["playbook"])


def test_ai_copilot_chat(sample_threat_source):
    analyst = AIAttackAnalyst()
    state = {
        "sources": [sample_threat_source],
        "alerts": [{"type": "cross_source_agent", "source_ip": "203.0.113.66"}],
        "counts": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0}
    }

    # Test "why" question
    r_why = analyst.chat("Why is 203.0.113.66 classified as an AI agent?", state)
    assert "Autonomous AI Agent Attribution Analysis" in r_why["reply"]
    assert "203.0.113.66" in r_why["reply"]

    # Test "compromised" question
    r_comp = analyst.chat("What accounts were compromised?", state)
    assert "msfadmin" in r_comp["reply"]

    # Test "remediation" question
    r_rem = analyst.chat("Show remediation playbook commands", state)
    assert "iptables" in r_rem["reply"]


@pytest.mark.anyio
async def test_manager_ai_endpoints(tmp_path, sample_threat_source):
    mgr_db = tmp_path / "test_ai_mgr.db"
    manager = ManagerCore(db_path=str(mgr_db), indexer_url="http://127.0.0.1:8920")
    manager.state["sources"] = [sample_threat_source]
    manager.state["counts"]["CRITICAL"] = 1

    app = create_manager_app(manager)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # POST /api/ai/analyze
        r_ana = await client.post("/api/ai/analyze", json={"ip": "203.0.113.66"})
        assert r_ana.status_code == 200
        data = r_ana.json()
        assert data["ip"] == "203.0.113.66"
        assert data["is_ai_agent"] is True

        # POST /api/ai/chat
        r_chat = await client.post("/api/ai/chat", json={"message": "Show remediation playbook"})
        assert r_chat.status_code == 200
        assert "iptables" in r_chat.json()["reply"]

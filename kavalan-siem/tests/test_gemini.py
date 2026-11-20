"""
test_gemini.py - Unit & Integration Tests for Google Gemini Integration in Kavalan SIEM
"""

import pytest
import httpx
from manager.gemini.client import GeminiClient
from manager.gemini.service import GeminiAIService
from manager.manager import create_manager_app, ManagerCore


def test_gemini_client_configuration():
    client = GeminiClient(api_key="test_dummy_key", model="gemini-1.5-flash")
    assert client.is_configured() is True
    assert client.model == "gemini-1.5-flash"
    assert client.api_key == "test_dummy_key"

    client.set_config(api_key="new_key", model="gemini-2.0-flash")
    assert client.api_key == "new_key"
    assert client.model == "gemini-2.0-flash"


def test_gemini_client_unconfigured_call(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    client = GeminiClient(api_key="")
    assert client.is_configured() is False
    res = client.generate_content("test prompt")
    assert res["success"] is False
    assert "GEMINI_API_KEY is not configured" in res["error"]


def test_gemini_service_infer_and_explain():
    svc = GeminiAIService()
    info = svc.get_model_info()
    assert "Google" in info["model_name"]
    assert info["provider"] == "Google DeepMind"
    assert "1,000,000" in info["context_window"]

    # Grounded heuristic inference
    out = svc.infer("Correlate multi-source telemetry for actor 203.0.113.66", max_tokens=50)
    assert "generated_text" in out
    assert "inference_time_ms" in out
    assert "attention_weights" in out
    assert len(out["attention_weights"]) > 0

    # Threat attribution explanation
    threat_exp = svc.explain_threat({
        "ip": "203.0.113.66",
        "tactics": {"recon_files": 10, "command_injection": 5, "sql_injection": 2, "ssrf": 1},
        "reasons": ["1,246 requests in its busiest 10s burst"]
    })
    assert threat_exp["ip"] == "203.0.113.66"
    assert threat_exp["is_ai_agent"] is True
    assert threat_exp["agent_confidence"] >= 90.0
    assert "Google DeepMind" in threat_exp["provider"]


def test_gemini_copilot_chat():
    svc = GeminiAIService()
    state = {
        "sources": [{"ip": "203.0.113.66", "reasons": ["Superhuman request burst"]}],
        "alerts": [{"rule_id": 100100, "description": "High-velocity attack"}],
        "counts": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 0}
    }
    chat_res = svc.chat("Why is 203.0.113.66 an AI agent?", state)
    assert "reply" in chat_res
    assert "Autonomous AI Agent" in chat_res["reply"] or "Google Gemini" in chat_res["reply"]
    assert len(chat_res["suggestions"]) > 0


@pytest.mark.anyio
async def test_manager_gemini_endpoints(tmp_path):
    mgr_db = tmp_path / "test_gemini_mgr.db"
    manager = ManagerCore(db_path=str(mgr_db), indexer_url="http://127.0.0.1:8920")
    manager.gemini = GeminiAIService()
    manager.sec_llm = manager.gemini

    app = create_manager_app(manager)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # GET /api/gemini/model-info
        r_info = await client.get("/api/gemini/model-info")
        assert r_info.status_code == 200
        info_json = r_info.json()
        assert "Google" in info_json["model_name"]
        assert info_json["provider"] == "Google DeepMind"

        # GET /api/gemini/config
        r_cfg = await client.get("/api/gemini/config")
        assert r_cfg.status_code == 200
        assert "model" in r_cfg.json()

        # POST /api/gemini/config
        r_set_cfg = await client.post("/api/gemini/config", json={"model": "gemini-2.0-flash"})
        assert r_set_cfg.status_code == 200
        assert r_set_cfg.json()["model"] == "gemini-2.0-flash"

        # POST /api/gemini/generate
        r_gen = await client.post("/api/gemini/generate", json={"prompt": "Analyze IP 203.0.113.66", "max_tokens": 50})
        assert r_gen.status_code == 200
        assert "generated_text" in r_gen.json()

        # POST /api/gemini/explain
        r_exp = await client.post("/api/gemini/explain", json={"ip": "203.0.113.66"})
        assert r_exp.status_code == 200
        assert r_exp.json()["ip"] == "203.0.113.66"

        # Backwards compatibility check: /api/sec-llm/model-info
        r_compat = await client.get("/api/sec-llm/model-info")
        assert r_compat.status_code == 200
        assert "Google" in r_compat.json()["model_name"]

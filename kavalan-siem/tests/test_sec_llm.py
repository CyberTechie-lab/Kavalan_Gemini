"""
test_sec_llm.py - Backwards-Compatibility Tests for Decommissioned Self-Made LLM
"""

import pytest
import httpx
from manager.sec_llm.service import SecLLMService
from manager.manager import create_manager_app, ManagerCore


def test_sec_llm_service():
    svc = SecLLMService(d_model=32, n_heads=2, n_layers=1)
    info = svc.get_model_info()
    assert "Google" in info["model_name"]
    assert info["provider"] == "Google DeepMind"

    out = svc.infer("Evaluate IP 203.0.113.66", max_tokens=10, temperature=0.2)
    assert "generated_text" in out
    assert "inference_time_ms" in out
    assert "attention_weights" in out

    threat_exp = svc.explain_threat({"ip": "203.0.113.66", "tactics": {"recon_files": 10, "cmdi": 5, "sqli": 2, "ssrf": 1}})
    assert threat_exp["ip"] == "203.0.113.66"
    assert threat_exp["is_ai_agent"] is True
    assert threat_exp["agent_confidence"] >= 90.0


@pytest.mark.anyio
async def test_manager_sec_llm_endpoints(tmp_path):
    mgr_db = tmp_path / "test_sec_mgr.db"
    manager = ManagerCore(db_path=str(mgr_db), indexer_url="http://127.0.0.1:8920")
    manager.sec_llm = SecLLMService(d_model=32, n_heads=2, n_layers=1)

    app = create_manager_app(manager)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # GET /api/sec-llm/model-info
        r_info = await client.get("/api/sec-llm/model-info")
        assert r_info.status_code == 200
        assert "Google" in r_info.json()["model_name"]

        # POST /api/sec-llm/generate
        r_gen = await client.post("/api/sec-llm/generate", json={"prompt": "Analyze IP 203.0.113.66", "max_tokens": 10})
        assert r_gen.status_code == 200
        assert "generated_text" in r_gen.json()

        # POST /api/sec-llm/explain
        r_exp = await client.post("/api/sec-llm/explain", json={"ip": "203.0.113.66"})
        assert r_exp.status_code == 200
        assert r_exp.json()["ip"] == "203.0.113.66"

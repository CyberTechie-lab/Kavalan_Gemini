import os
import json
import tempfile
import pytest
from httpx import ASGITransport, AsyncClient

from indexer.indexer import IndexerService, create_indexer_app, init_db as init_indexer_db
from manager.manager import ManagerCore, create_manager_app, init_db as init_manager_db
from dashboard.dashboard_server import DashboardBackend, create_dashboard_app
from agent.agent import KavalanAgent


@pytest.fixture
def enterprise_stack(tmp_path):
    idx_db = str(tmp_path / "test_indexer.db")
    mgr_db = str(tmp_path / "test_manager.db")
    init_indexer_db(idx_db)
    init_manager_db(mgr_db)

    indexer_svc = IndexerService(idx_db)
    indexer_app = create_indexer_app(indexer_svc)

    mgr_core = ManagerCore(mgr_db, indexer_url="http://test-indexer", window_minutes=15, interval=1)
    mgr_app = create_manager_app(mgr_core)

    backend = DashboardBackend(manager_url="http://test-mgr", indexer_url="http://test-indexer")
    dash_app = create_dashboard_app(backend)

    return {
        "indexer_svc": indexer_svc,
        "indexer_app": indexer_app,
        "mgr_core": mgr_core,
        "mgr_app": mgr_app,
        "dash_app": dash_app,
        "tmp_path": tmp_path,
    }


@pytest.mark.anyio
async def test_indexer_crud_and_search(enterprise_stack):
    indexer_app = enterprise_stack["indexer_app"]

    events = [
        {
            "ts": 1760930000,
            "agent_id": "001",
            "host": "web-01",
            "source_ip": "203.0.113.66",
            "log_type": "web",
            "action": "GET /admin",
            "target": "/admin",
            "outcome": "fail",
            "status": 401,
            "user": None,
            "tactics": {"recon_files": 1},
        },
        {
            "ts": 1760930010,
            "agent_id": "002",
            "host": "auth-01",
            "source_ip": "203.0.113.66",
            "log_type": "auth",
            "action": "ssh_fail",
            "target": "sshd",
            "outcome": "fail",
            "status": 1,
            "user": "root",
            "tactics": {"ssh_credential_guessing": 1},
        }
    ]

    async with AsyncClient(transport=ASGITransport(app=indexer_app), base_url="http://test-indexer") as client:
        # Index
        resp = await client.post("/api/index/events", json=events)
        assert resp.status_code == 200
        assert resp.json()["indexed"] == 2

        # Search by source_ip
        s_resp = await client.post("/api/search/events", json={"source_ip": "203.0.113.66"})
        assert s_resp.status_code == 200
        assert s_resp.json()["total"] == 2

        # Filter by agent_id
        s_agent = await client.post("/api/search/events", json={"agent_id": "001"})
        assert s_agent.status_code == 200
        assert s_agent.json()["total"] == 1
        assert s_agent.json()["hits"][0]["host"] == "web-01"

        # Aggregation
        agg_resp = await client.post("/api/aggregate", json={
            "date_histogram": {"start_ts": 1760929000, "end_ts": 1760931000, "interval_seconds": 60},
            "terms": ["source_ip", "log_type"]
        })
        assert agg_resp.status_code == 200
        agg_data = agg_resp.json()
        assert "date_histogram" in agg_data
        assert "terms_source_ip" in agg_data
        assert agg_data["terms_source_ip"][0]["term"] == "203.0.113.66"


@pytest.mark.anyio
async def test_discover_field_stats_context_and_ip_dossier(enterprise_stack):
    indexer_app = enterprise_stack["indexer_app"]

    # 1. Seed sequence of 7 chronological events on host web-prod-01
    seq_events = [
        {"ts": 1760930000 + i * 10, "agent_id": "001", "host": "web-prod-01", "source_ip": "198.51.100.44",
         "log_type": "web", "action": f"GET /endpoint_{i}", "target": f"/endpoint_{i}",
         "outcome": "fail" if i % 2 == 1 else "ok", "status": 403 if i % 2 == 1 else 200, "user": None,
         "tactics": {"recon_files": 1} if i == 3 else {}}
        for i in range(7)
    ]
    # Add a private LAN IP event
    seq_events.append({
        "ts": 1760930100, "agent_id": "002", "host": "db-prod-01", "source_ip": "10.0.0.88",
        "log_type": "auth", "action": "ssh_fail", "target": "sshd", "outcome": "fail", "status": 1, "user": "admin"
    })

    alerts = [
        {
            "ts": 1760930035,
            "agent_id": "001",
            "host": "web-prod-01",
            "rule_id": "90001",
            "level": 12,
            "rule_name": "Web Reconnaissance Detected",
            "description": "Repeated unauthorized probes detected from WAN entity",
            "groups": ["web", "recon"],
            "mitre_id": "T1595.002",
            "mitre_tactic": "Reconnaissance",
            "source_ip": "198.51.100.44",
            "target": "/endpoint_3",
            "reason": "403 forbidden threshold exceeded",
        }
    ]

    async with AsyncClient(transport=ASGITransport(app=indexer_app), base_url="http://test-indexer") as client:
        # Index events and alerts
        idx_ev_resp = await client.post("/api/index/events", json=seq_events)
        assert idx_ev_resp.status_code == 200
        assert idx_ev_resp.json()["indexed"] == 8

        idx_al_resp = await client.post("/api/index/alerts", json=alerts)
        assert idx_al_resp.status_code == 200
        assert idx_al_resp.json()["indexed"] == 1

        # 2. Test Surrounding Events Context (Target = event id 4, index 3 in 0-based list)
        context_resp = await client.get("/api/events/4/context?window=2")
        assert context_resp.status_code == 200
        ctx_data = context_resp.json()
        assert ctx_data["target_id"] == 4
        assert ctx_data["host"] == "web-prod-01"
        assert len(ctx_data["events"]) == 5  # 2 before + target + 2 after
        target_ev = next(e for e in ctx_data["events"] if e.get("is_target"))
        assert target_ev["id"] == 4
        assert target_ev["action"] == "GET /endpoint_3"

        # 3. Test Field Stats Aggregation (Top term counts & percentages)
        stats_resp = await client.post("/api/fields/stats", json={"host": "web-prod-01"})
        assert stats_resp.status_code == 200
        stats = stats_resp.json()
        assert stats["total_events"] == 7
        assert "fields" in stats
        assert "log_type" in stats["fields"]
        assert stats["fields"]["log_type"][0]["term"] == "web"
        assert stats["fields"]["log_type"][0]["percent"] == 100.0

        # 4. Test 360° IP Investigation Dossier for WAN IP
        dossier_wan = (await client.get("/api/entity/ip/198.51.100.44")).json()
        assert dossier_wan["ip"] == "198.51.100.44"
        assert "PUBLIC WAN" in dossier_wan["classification"]
        assert dossier_wan["is_private"] is False
        assert dossier_wan["threat_score"] > 0
        assert len(dossier_wan["alerts"]) == 1
        assert dossier_wan["total_events"] == 7

        # 5. Test 360° IP Investigation Dossier for RFC1918 Private LAN IP
        dossier_lan = (await client.get("/api/entity/ip/10.0.0.88")).json()
        assert dossier_lan["ip"] == "10.0.0.88"
        assert "RFC 1918" in dossier_lan["classification"]
        assert dossier_lan["is_private"] is True



@pytest.mark.anyio
async def test_manager_agent_fleet_and_detection(enterprise_stack):
    mgr_app = enterprise_stack["mgr_app"]
    mgr_core = enterprise_stack["mgr_core"]

    async with AsyncClient(transport=ASGITransport(app=mgr_app), base_url="http://test-mgr") as client:
        # 1. Register agents
        r1 = await client.post("/api/agent/register", json={"name": "web-01", "ip": "10.0.0.1", "os": "Linux"})
        assert r1.status_code == 200
        agent1_id = r1.json()["agent_id"]
        assert agent1_id == "001"

        r2 = await client.post("/api/agent/register", json={"name": "auth-01", "ip": "10.0.0.2", "os": "Linux"})
        assert r2.status_code == 200
        agent2_id = r2.json()["agent_id"]
        assert agent2_id == "002"

        # 2. Heartbeat
        hb = await client.post("/api/agent/heartbeat", json={"agent_id": agent1_id, "metrics": {"cpu": 10}})
        assert hb.status_code == 200
        assert hb.json()["ok"] is True

        # 3. List agents
        agents_list = await client.get("/api/agents")
        assert agents_list.status_code == 200
        agents = agents_list.json()["agents"]
        assert len(agents) == 2
        assert agents[0]["status"] == "active"

        # 4. Ingest events through agents
        web_event = {
            "ts": 1760930000,
            "host": "web-01",
            "source_ip": "203.0.113.99",
            "log_type": "web",
            "action": "GET /admin",
            "target": "/admin",
            "outcome": "fail",
            "status": 401,
        }
        ing_resp = await client.post("/api/agent/events", json={"agent_id": agent1_id, "events": [web_event]})
        assert ing_resp.status_code == 200
        assert ing_resp.json()["accepted"] == 1

        # 5. Run detection pass
        scan_resp = await client.post("/api/scan")
        assert scan_resp.status_code == 200
        st = scan_resp.json()
        assert st["active_agents"] == 2
        assert len(st["sources"]) >= 1

        # 6. Delete agent
        del_resp = await client.delete(f"/api/agents/{agent2_id}")
        assert del_resp.status_code == 200
        assert del_resp.json()["deleted_id"] == agent2_id

        # Verify only 1 agent remains
        agents_after = (await client.get("/api/agents")).json()["agents"]
        assert len(agents_after) == 1
        assert agents_after[0]["id"] == agent1_id

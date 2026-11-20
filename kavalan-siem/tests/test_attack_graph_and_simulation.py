import json
import pytest
from httpx import ASGITransport, AsyncClient

from indexer.indexer import IndexerService, create_indexer_app, init_db as init_indexer_db
from manager.manager import ManagerCore, create_manager_app, init_db as init_manager_db
from dashboard.dashboard_server import DashboardBackend, create_dashboard_app


@pytest.fixture
def sim_stack(tmp_path):
    idx_db = str(tmp_path / "test_idx_graph.db")
    mgr_db = str(tmp_path / "test_mgr_graph.db")
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
        "backend": backend,
    }


@pytest.mark.anyio
async def test_attack_topology_graph_and_blast_radius(sim_stack):
    indexer_app = sim_stack["indexer_app"]

    # 1. Seed events across multiple entities
    events = [
        {"ts": 1760930000, "agent_id": "001", "host": "web-01", "source_ip": "203.0.113.199",
         "log_type": "web", "action": "GET /admin", "target": "/admin", "outcome": "denied", "status": 403, "user": None},
        {"ts": 1760930010, "agent_id": "001", "host": "web-01", "source_ip": "203.0.113.199",
         "log_type": "web", "action": "POST /cmd?x=;id", "target": "/cmd", "outcome": "error", "status": 500, "user": None},
        {"ts": 1760930020, "agent_id": "002", "host": "auth-01", "source_ip": "203.0.113.199",
         "log_type": "auth", "action": "ssh_fail", "target": "sshd", "outcome": "fail", "status": 1, "user": "root"},
        {"ts": 1760930030, "agent_id": "002", "host": "auth-01", "source_ip": "203.0.113.199",
         "log_type": "auth", "action": "ssh_ok", "target": "sshd", "outcome": "ok", "status": 0, "user": "msfadmin"},
        {"ts": 1760930040, "agent_id": "005", "host": "server", "source_ip": "203.0.113.199",
         "log_type": "fim", "action": "file_modified", "target": "/etc/shadow", "outcome": "error", "status": 1, "user": "root"}
    ]

    alerts = [
        {
            "ts": 1760930030,
            "agent_id": "002",
            "host": "auth-01",
            "rule_id": "90002",
            "level": "CRITICAL",
            "type": "cross_source_agent",
            "summary": "Coordinated Web Recon & SSH Breach detected",
            "source_ip": "203.0.113.199",
            "mitre_tactics": {"T1110.001": 1, "T1078": 1},
            "detail": {"host": "auth-01", "target": "sshd"}
        }
    ]

    async with AsyncClient(transport=ASGITransport(app=indexer_app), base_url="http://test-indexer") as client:
        # Index events and alerts
        await client.post("/api/index/events", json=events)
        await client.post("/api/index/alerts", json=alerts)

        # Query attack topology graph
        res = await client.get("/api/graph/attack-topology?window=7200")
        assert res.status_code == 200
        graph = res.json()

        assert "nodes" in graph
        assert "links" in graph
        assert "metrics" in graph
        assert "timeline_steps" in graph

        # Verify node classifications
        node_types = {n["type"] for n in graph["nodes"]}
        assert "actor" in node_types
        assert "host" in node_types
        assert "user" in node_types

        # Verify breach indicator
        msfadmin_node = next((n for n in graph["nodes"] if n["label"] == "msfadmin"), None)
        assert msfadmin_node is not None
        assert msfadmin_node["is_compromised"] is True

        # Verify blast radius metrics
        metrics = graph["metrics"]
        assert metrics["compromised_users"] >= 1
        assert "CRITICAL" in metrics["blast_radius_status"]
        assert metrics["blast_score"] >= 90

        # Verify timeline steps for playback
        assert len(graph["timeline_steps"]) >= 1


@pytest.mark.anyio
async def test_simulation_scenarios_execution(sim_stack):
    backend = sim_stack["backend"]

    # 1. Test FIM Ransomware scenario
    res_fim = backend.simulate_scenario("fim_ransomware", host="server", agent_id="005")
    assert res_fim["scenario"] == "fim_ransomware"
    assert res_fim["generated_events"] >= 5

    # 2. Test Distributed SSH Brute Force scenario
    res_ssh = backend.simulate_scenario("ssh_distributed_brute", host="auth-01", agent_id="002")
    assert res_ssh["scenario"] == "ssh_distributed_brute"
    assert res_ssh["generated_events"] >= 40

    # 3. Test Cross Source Killchain scenario
    res_cross = backend.simulate_scenario("cross_source_killchain", host="server", agent_id="005")
    assert res_cross["scenario"] == "cross_source_killchain"
    assert res_cross["generated_events"] >= 50

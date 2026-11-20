import os
import tempfile
import pytest
from httpx import ASGITransport, AsyncClient

from siem import SiemCore, create_app, init_db, get_db
from cem import validate_event


@pytest.fixture
def temp_siem(tmp_path):
    db_file = str(tmp_path / "test_siem.db")
    dash_file = str(tmp_path / "dashboard.html")
    with open(dash_file, "w") as f:
        f.write("<html><body>Test Dashboard</body></html>")
    init_db(db_file)
    core = SiemCore(db_path=db_file, window_minutes=15, interval=1, dashboard_path=dash_file)
    app = create_app(core)
    return core, app, db_file


@pytest.mark.anyio
async def test_ingest_and_state(temp_siem):
    core, app, db_file = temp_siem

    events = [
        {
            "ts": 1760930000,
            "host": "web-01",
            "source_ip": "192.0.2.10",
            "log_type": "web",
            "action": "GET /products",
            "target": "/products",
            "outcome": "ok",
            "status": 200,
        },
        {
            "ts": 1760930005,
            "host": "web-01",
            "source_ip": "192.0.2.10",
            "log_type": "web",
            "action": "GET /cart",
            "target": "/cart",
            "outcome": "ok",
            "status": 200,
        },
        # malformed event
        {
            "ts": "not-an-int",
            "host": "web-01",
        }
    ]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post("/ingest", json=events)
        assert resp.status_code == 200
        data = resp.json()
        assert data["accepted"] == 2
        assert data["rejected"] == 1
        assert len(data["errors"]) == 1

        # Check DB
        con = get_db(db_file)
        cnt = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        assert cnt == 2
        con.close()

        # Trigger scan
        scan_resp = await ac.post("/api/scan")
        assert scan_resp.status_code == 200
        st = scan_resp.json()
        assert st["total_events"] == 2
        assert st["events_in_window"] == 2
        assert st["sources_in_window"] == 1
        assert len(st["sources"]) == 1
        assert st["sources"][0]["ip"] == "192.0.2.10"
        assert st["sources"][0]["level"] == "OK"

        # Check dashboard
        dash_resp = await ac.get("/")
        assert dash_resp.status_code == 200
        assert "Test Dashboard" in dash_resp.text

        # Test Log Explorer API: GET /api/events
        ev_resp = await ac.get("/api/events?limit=10")
        assert ev_resp.status_code == 200
        ev_data = ev_resp.json()
        assert ev_data["total"] == 2
        assert len(ev_data["events"]) == 2
        assert ev_data["events"][0]["source_ip"] == "192.0.2.10"

        # Filter by outcome
        ev_filter = await ac.get("/api/events?outcome=ok")
        assert ev_filter.status_code == 200
        assert ev_filter.json()["total"] == 2

        # Test source timeline API: GET /api/sources/{ip}/timeline
        tl_resp = await ac.get("/api/sources/192.0.2.10/timeline")
        assert tl_resp.status_code == 200
        tl_data = tl_resp.json()
        assert tl_data["ip"] == "192.0.2.10"
        assert tl_data["events_count"] == 2

        # Test timeline stats: GET /api/stats/timeline
        stats_resp = await ac.get("/api/stats/timeline")
        assert stats_resp.status_code == 200
        assert "buckets" in stats_resp.json()

        # Test simulate endpoint: POST /api/simulate
        sim_resp = await ac.post("/api/simulate", json={"scenario": "benign_burst"})
        assert sim_resp.status_code == 200
        sim_data = sim_resp.json()
        assert sim_data["generated_events"] > 0

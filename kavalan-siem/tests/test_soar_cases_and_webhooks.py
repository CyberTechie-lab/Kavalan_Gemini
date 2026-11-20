import json
import pytest
from httpx import ASGITransport, AsyncClient

from manager.manager import ManagerCore, create_manager_app, init_db as init_manager_db
from dashboard.dashboard_server import DashboardBackend, create_dashboard_app


@pytest.fixture
def soar_stack(tmp_path):
    mgr_db = str(tmp_path / "test_manager_soar.db")
    init_manager_db(mgr_db)

    mgr_core = ManagerCore(mgr_db, indexer_url="http://test-indexer", window_minutes=15, interval=1)
    mgr_app = create_manager_app(mgr_core)

    backend = DashboardBackend(manager_url="http://test-mgr", indexer_url="http://test-indexer")
    dash_app = create_dashboard_app(backend)

    return {
        "mgr_core": mgr_core,
        "mgr_app": mgr_app,
        "dash_app": dash_app,
        "mgr_db": mgr_db,
    }


@pytest.mark.anyio
async def test_case_lifecycle_and_notes(soar_stack):
    mgr_app = soar_stack["mgr_app"]

    async with AsyncClient(transport=ASGITransport(app=mgr_app), base_url="http://test-mgr") as client:
        # 1. Create a case
        create_payload = {
            "title": "Coordinated SSH & Web Penetration Attempt",
            "severity": "HIGH",
            "assignee": "Tier 1 Analyst",
            "description": "Observed multiple 401s and failed SSH logins from WAN entity.",
            "entities": {
                "ips": ["198.51.100.99"],
                "hosts": ["web-01", "auth-01"],
                "users": ["admin", "root"]
            }
        }
        res = await client.post("/api/cases", json=create_payload)
        assert res.status_code == 200
        case_data = res.json()
        case_id = case_data["id"]
        assert case_id == "CASE-0001"
        assert case_data["status"] == "NEW"
        assert case_data["severity"] == "HIGH"
        assert len(case_data["entities"]["ips"]) == 1

        # 2. List cases
        list_res = await client.get("/api/cases")
        assert list_res.status_code == 200
        cases = list_res.json()["cases"]
        assert len(cases) == 1
        assert cases[0]["id"] == "CASE-0001"
        assert cases[0]["notes_count"] == 1

        # 3. Add an investigation note
        note_res = await client.post(f"/api/cases/{case_id}/notes", json={
            "note": "Correlated source IP against threat intelligence; IP is flagged for scanning.",
            "author": "Analyst Shiyam"
        })
        assert note_res.status_code == 200
        assert note_res.json()["status"] == "ok"

        # 4. Update status and assignee
        status_res = await client.patch(f"/api/cases/{case_id}/status", json={
            "status": "INVESTIGATING",
            "assignee": "Lead Responder",
            "note": "Beginning forensic isolation."
        })
        assert status_res.status_code == 200
        updated = status_res.json()
        assert updated["status"] == "INVESTIGATING"
        assert updated["assignee"] == "Lead Responder"
        assert len(updated["notes"]) == 3  # Initial + added + status change note

        # 5. Fetch single case details
        detail_res = await client.get(f"/api/cases/{case_id}")
        assert detail_res.status_code == 200
        detail = detail_res.json()
        assert detail["id"] == "CASE-0001"
        assert len(detail["notes"]) == 3


@pytest.mark.anyio
async def test_soar_playbook_execution(soar_stack):
    mgr_app = soar_stack["mgr_app"]
    mgr_core = soar_stack["mgr_core"]

    async with AsyncClient(transport=ASGITransport(app=mgr_app), base_url="http://test-mgr") as client:
        # Create case
        c = await client.post("/api/cases", json={
            "title": "Compromised Account msfadmin on auth-01",
            "severity": "CRITICAL",
            "entities": {
                "ips": ["203.0.113.88"],
                "hosts": ["auth-01"],
                "users": ["msfadmin"]
            }
        })
        case_id = c.json()["id"]

        # Run perimeter-drop playbook
        pb_drop = await client.post(f"/api/cases/{case_id}/playbook", json={"playbook": "perimeter-drop"})
        assert pb_drop.status_code == 200
        drop_data = pb_drop.json()
        assert drop_data["status"] == "ok"
        assert any("Blocked IP 203.0.113.88" in a for a in drop_data["actions"])

        # Run account-lock playbook
        pb_lock = await client.post(f"/api/cases/{case_id}/playbook", json={"playbook": "account-lock"})
        assert pb_lock.status_code == 200
        lock_data = pb_lock.json()
        assert lock_data["status"] == "ok"
        assert any("Locked user account 'msfadmin'" in a for a in lock_data["actions"])

        # Run full-containment playbook
        pb_full = await client.post(f"/api/cases/{case_id}/playbook", json={"playbook": "full-containment"})
        assert pb_full.status_code == 200
        full_data = pb_full.json()
        assert full_data["status"] == "ok"

        # Verify case status automatically updated to CONTAINED
        c_after = (await client.get(f"/api/cases/{case_id}")).json()
        assert c_after["status"] == "CONTAINED"
        assert len(c_after["playbooks_run"]) == 3


@pytest.mark.anyio
async def test_webhooks_management_and_test(soar_stack):
    mgr_app = soar_stack["mgr_app"]

    async with AsyncClient(transport=ASGITransport(app=mgr_app), base_url="http://test-mgr") as client:
        # 1. Add webhook
        wh_res = await client.post("/api/webhooks", json={
            "name": "SecOps Discord Channel",
            "url": "https://discord.com/api/webhooks/test/123",
            "type": "discord",
            "min_level": "HIGH",
            "enabled": True
        })
        assert wh_res.status_code == 200
        wh = wh_res.json()
        assert wh["name"] == "SecOps Discord Channel"
        wh_id = wh["id"]

        # 2. List webhooks
        list_res = await client.get("/api/webhooks")
        assert list_res.status_code == 200
        hooks = list_res.json()["webhooks"]
        assert len(hooks) == 1
        assert hooks[0]["id"] == wh_id

        # 3. Trigger test probe
        test_res = await client.post("/api/webhooks/test", json={})
        assert test_res.status_code == 200
        assert test_res.json()["status"] == "dispatched"

        # 4. Delete webhook
        del_res = await client.delete(f"/api/webhooks/{wh_id}")
        assert del_res.status_code == 200
        assert del_res.json()["deleted"] is True

        # Verify list is empty
        assert len((await client.get("/api/webhooks")).json()["webhooks"]) == 0

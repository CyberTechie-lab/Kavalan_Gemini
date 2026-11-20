"""
test_deployer.py - Integration Tests for Kavalan Agent Deployer & HTTP Installer

Tests:
  1. Curl command generation logic
  2. Manager HTTP endpoints for /install.sh, /agent/agent.py, /agent/sample.conf
  3. bash -n syntax verification of install.sh
  4. End-to-end simulated deployment workflow
"""

import subprocess
import sys
from pathlib import Path
import pytest
import httpx

from deployer import generate_curl_command, check_manager_health
from manager.manager import create_manager_app, ManagerCore


def test_generate_curl_command():
    cmd = generate_curl_command("http://192.168.1.10:8910", "ubuntu-01")
    assert "curl -sSL http://192.168.1.10:8910/install.sh" in cmd
    assert "--manager http://192.168.1.10:8910" in cmd
    assert "--name ubuntu-01" in cmd

    cmd_default = generate_curl_command("http://10.0.0.1:8910")
    assert "--name $(hostname)" in cmd_default


def test_installer_script_syntax():
    install_sh = Path(__file__).resolve().parent.parent / "agent" / "install.sh"
    assert install_sh.exists()

    res = subprocess.run(["bash", "-n", str(install_sh)], capture_output=True, text=True)
    assert res.returncode == 0, f"Syntax error in install.sh: {res.stderr}"


@pytest.mark.anyio
async def test_manager_installer_endpoints(tmp_path):
    mgr_db = tmp_path / "test_mgr.db"
    manager = ManagerCore(db_path=str(mgr_db), indexer_url="http://127.0.0.1:8920")
    app = create_manager_app(manager)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Health
        r_health = await client.get("/health")
        assert r_health.status_code == 200
        assert r_health.json()["status"] == "ok"

        # 2. GET /install.sh
        r_install = await client.get("/install.sh")
        assert r_install.status_code == 200
        assert "Kavalan Endpoint Agent Installer" in r_install.text
        assert "INSTALL_DIR" in r_install.text

        # 3. GET /agent/agent.py
        r_agent = await client.get("/agent/agent.py")
        assert r_agent.status_code == 200
        assert "class KavalanAgent" in r_agent.text
        assert "parse_web_line" in r_agent.text

        # 4. GET /agent/sample.conf
        r_conf = await client.get("/agent/sample.conf")
        assert r_conf.status_code == 200
        assert "manager" in r_conf.text

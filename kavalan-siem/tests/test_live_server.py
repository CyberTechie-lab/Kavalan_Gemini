import os
import signal
import subprocess
import sys
import time
import urllib.request
import json
import sqlite3
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent
SIEM_DIR = CURRENT_DIR.parent
PROJECT_ROOT = SIEM_DIR.parent
ACCESS_LOG = PROJECT_ROOT / "kavalan-ml" / "access.log"
AUTH_LOG = PROJECT_ROOT / "kavalan-ml" / "auth.log"


def test_live_server_and_collector(tmp_path):
    port = 8912
    db_file = str(tmp_path / "live.db")
    siem_py = str(SIEM_DIR / "siem.py")
    collector_py = str(SIEM_DIR / "collector.py")

    # Start siem.py process with log file
    log_file = tmp_path / "server.log"
    s_log = open(log_file, "w")
    proc = subprocess.Popen(
        [sys.executable, siem_py, "--db", db_file, "--port", str(port), "--interval", "1", "--window", "15"],
        cwd=str(SIEM_DIR),
        stdout=s_log,
        stderr=subprocess.STDOUT,
    )

    core_url = f"http://127.0.0.1:{port}"
    try:
        # Wait up to 10s for server to start
        started = False
        for _ in range(20):
            try:
                with urllib.request.urlopen(f"{core_url}/api/state", timeout=1.0) as resp:
                    if resp.status == 200:
                        started = True
                        break
            except Exception:
                time.sleep(0.5)

        assert started, "siem.py did not start within 10s"

        # 1. Acceptance Criterion 1: serves dashboard at / and /api/state returns valid JSON
        with urllib.request.urlopen(f"{core_url}/", timeout=2.0) as resp:
            assert resp.status == 200
            html = resp.read().decode("utf-8")
            assert "Kavalan SIEM" in html
            assert "Sources" in html
            assert "Alerts" in html

        with urllib.request.urlopen(f"{core_url}/api/state", timeout=2.0) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert "counts" in data
            assert "sources" in data
            assert "alerts" in data
            assert data["total_events"] == 0

        # 2. Acceptance Criterion 2: collector.py tails web access log and auth.log into SQLite
        col_res = subprocess.run(
            [
                sys.executable, collector_py,
                "--web", str(ACCESS_LOG),
                "--auth", str(AUTH_LOG),
                "--core", core_url,
                "--host", "web-01",
                "--year", "2026",
                "--once"
            ],
            capture_output=True,
            text=True,
            cwd=str(SIEM_DIR),
        )
        assert col_res.returncode == 0, f"collector.py failed: {col_res.stderr}"

        # Verify SQLite has events
        con = sqlite3.connect(db_file)
        cnt = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        assert cnt > 800, f"Expected >800 events in SQLite, got {cnt}"
        con.close()

        # 3. Acceptance Criterion 3: Wait for detection pass to run (interval is 1s)
        time.sleep(2.5)

        with urllib.request.urlopen(f"{core_url}/api/state", timeout=2.0) as resp:
            assert resp.status == 200
            state = json.loads(resp.read().decode("utf-8"))

        counts = state["counts"]
        assert counts["CRITICAL"] == 1, f"Expected 1 CRITICAL, got {counts}"
        assert counts["HIGH"] == 1, f"Expected 1 HIGH, got {counts}"
        assert counts["MEDIUM"] == 1, f"Expected 1 MEDIUM, got {counts}"

        sources_by_ip = {s["ip"]: s for s in state["sources"]}

        # Cross-source agent
        assert "203.0.113.66" in sources_by_ip
        cross = sources_by_ip["203.0.113.66"]
        assert cross["level"] == "CRITICAL"
        assert cross["cross_source"] is True
        assert cross["web_score"] == 76
        assert cross["ssh_score"] == 79
        assert "web" in cross["channels"] and "ssh" in cross["channels"]

        # Web scanner
        assert "198.51.100.23" in sources_by_ip
        web = sources_by_ip["198.51.100.23"]
        assert web["level"] == "HIGH"
        assert web["cross_source"] is False
        assert web["web_score"] == 87
        assert web["ssh_score"] == 0

        # SSH brute-forcer
        assert "198.51.100.99" in sources_by_ip
        ssh = sources_by_ip["198.51.100.99"]
        assert ssh["level"] == "MEDIUM"
        assert ssh["cross_source"] is False
        assert ssh["web_score"] == 0
        assert ssh["ssh_score"] == 50

        # Benign users unflagged
        assert "192.0.2.10" in sources_by_ip
        assert sources_by_ip["192.0.2.10"]["level"] == "OK"
        assert "10.0.0.20" in sources_by_ip
        assert sources_by_ip["10.0.0.20"]["level"] == "OK"

        # Check alerts
        alert_ips = {a.get("ip") for a in state["alerts"]}
        assert "203.0.113.66" in alert_ips
        assert "198.51.100.23" in alert_ips
        assert "198.51.100.99" in alert_ips

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            proc.kill()
        try:
            s_log.close()
        except Exception:
            pass

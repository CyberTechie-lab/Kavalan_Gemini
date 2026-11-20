from pathlib import Path
import pytest
from cem import validate_event
from collector import FileTailer, parse_web_line, parse_auth_line
from siem import SiemCore, init_db, get_db

CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent.parent
ACCESS_LOG = PROJECT_ROOT / "kavalan-ml" / "access.log"
AUTH_LOG = PROJECT_ROOT / "kavalan-ml" / "auth.log"


def test_simulation_data_detection(tmp_path):
    assert ACCESS_LOG.exists(), f"access.log not found at {ACCESS_LOG}"
    assert AUTH_LOG.exists(), f"auth.log not found at {AUTH_LOG}"

    db_path = str(tmp_path / "test_sim.db")
    init_db(db_path)

    # 15 minutes window is plenty since simulation runs in ~600 seconds
    core = SiemCore(db_path=db_path, window_minutes=15)

    events = []
    # Parse web log
    web_tailer = FileTailer(str(ACCESS_LOG), "web")
    for line in web_tailer.read_new_lines():
        if not line.strip():
            continue
        ev = parse_web_line(line, host="web-01")
        if ev:
            events.append(ev.to_dict())

    # Parse auth log (2026 year matching simulate_multi.py)
    auth_tailer = FileTailer(str(AUTH_LOG), "auth")
    for line in auth_tailer.read_new_lines():
        if not line.strip():
            continue
        ev = parse_auth_line(line, host="web-01", year=2026)
        if ev:
            events.append(ev.to_dict())

    assert len(events) > 800, f"Expected > 800 events from simulation, got {len(events)}"

    # Ingest in batches of 50
    for i in range(0, len(events), 50):
        batch = events[i:i + 50]
        res = core.ingest_events(batch)
        assert res["accepted"] == len(batch)
        assert res["rejected"] == 0

    # Run detection pass
    state = core.run_detection_pass()

    # Check counts: 1 CRITICAL, 1 HIGH, 1 MEDIUM
    counts = state["counts"]
    assert counts["CRITICAL"] == 1, f"Expected 1 CRITICAL, got {counts['CRITICAL']}"
    assert counts["HIGH"] == 1, f"Expected 1 HIGH, got {counts['HIGH']}"
    assert counts["MEDIUM"] == 1, f"Expected 1 MEDIUM, got {counts['MEDIUM']}"

    sources_by_ip = {s["ip"]: s for s in state["sources"]}

    # 1. Cross-source agent (203.0.113.66)
    cross_ip = "203.0.113.66"
    assert cross_ip in sources_by_ip
    s_cross = sources_by_ip[cross_ip]
    assert s_cross["level"] == "CRITICAL"
    assert s_cross["cross_source"] is True
    assert set(s_cross["channels"]) == {"web", "ssh"}
    assert s_cross["web_score"] == 76
    assert s_cross["ssh_score"] == 79
    assert any("SUCCESSFUL login" in r for r in s_cross["reasons"])

    # 2. Web scanner (198.51.100.23)
    web_ip = "198.51.100.23"
    assert web_ip in sources_by_ip
    s_web = sources_by_ip[web_ip]
    assert s_web["level"] == "HIGH"
    assert s_web["cross_source"] is False
    assert s_web["channels"] == ["web"]
    assert s_web["web_score"] == 87
    assert s_web["ssh_score"] == 0

    # 3. SSH brute (198.51.100.99)
    ssh_ip = "198.51.100.99"
    assert ssh_ip in sources_by_ip
    s_ssh = sources_by_ip[ssh_ip]
    assert s_ssh["level"] == "MEDIUM"
    assert s_ssh["cross_source"] is False
    assert s_ssh["channels"] == ["ssh"]
    assert s_ssh["web_score"] == 0
    assert s_ssh["ssh_score"] == 50

    # 4. Benign web & ssh users must be unflagged (level == "OK")
    benign_web = "192.0.2.10"
    assert benign_web in sources_by_ip
    assert sources_by_ip[benign_web]["level"] == "OK"
    assert sources_by_ip[benign_web]["cross_source"] is False

    benign_ssh = "10.0.0.20"
    assert benign_ssh in sources_by_ip
    assert sources_by_ip[benign_ssh]["level"] == "OK"
    assert sources_by_ip[benign_ssh]["cross_source"] is False

    # Check alerts table in SQLite
    con = get_db(db_path)
    alerts_rows = con.execute("SELECT key, level, type, summary FROM alerts ORDER BY level").fetchall()
    assert len(alerts_rows) == 3
    alert_levels = {r["level"] for r in alerts_rows}
    assert alert_levels == {"CRITICAL", "HIGH", "MEDIUM"}
    con.close()

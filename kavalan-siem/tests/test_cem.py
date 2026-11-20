import pytest
from cem import CEMEvent, validate_event


def test_valid_cem_event():
    sample = {
        "ts": 1760930000,
        "host": "web-01",
        "source_ip": "203.0.113.5",
        "log_type": "web",
        "action": "GET /admin",
        "target": "/admin",
        "outcome": "fail",
        "status": 404,
        "user": "root",
        "raw": '203.0.113.5 - - [20/Oct/2026:06:00:00 +0000] "GET /admin HTTP/1.1" 404 512',
        "meta": {"method": "GET"},
    }
    event = validate_event(sample)
    assert event.ts == 1760930000
    assert event.host == "web-01"
    assert event.source_ip == "203.0.113.5"
    assert event.log_type == "web"
    assert event.action == "GET /admin"
    assert event.target == "/admin"
    assert event.outcome == "fail"
    assert event.status == 404
    assert event.user == "root"
    assert event.meta == {"method": "GET"}
    d = event.to_dict()
    assert d["ts"] == 1760930000
    assert d["outcome"] == "fail"


def test_minimal_cem_event():
    sample = {
        "ts": 1760930000,
        "host": "web-01",
        "source_ip": "203.0.113.5",
        "log_type": "auth",
        "action": "ssh_login",
        "target": "sshd",
        "outcome": "ok",
    }
    event = validate_event(sample)
    assert event.status is None
    assert event.user is None
    assert event.raw is None
    assert event.meta == {}


def test_missing_required_field():
    sample = {
        "ts": 1760930000,
        "host": "web-01",
        "source_ip": "203.0.113.5",
        "log_type": "web",
        "action": "GET /admin",
        # missing target and outcome
    }
    with pytest.raises(ValueError, match="Missing required CEM fields"):
        validate_event(sample)


def test_invalid_outcome():
    sample = {
        "ts": 1760930000,
        "host": "web-01",
        "source_ip": "203.0.113.5",
        "log_type": "web",
        "action": "GET /admin",
        "target": "/admin",
        "outcome": "invalid_status",
    }
    with pytest.raises(ValueError, match="'outcome' must be one of"):
        validate_event(sample)


def test_invalid_ts_type():
    sample = {
        "ts": "1760930000",
        "host": "web-01",
        "source_ip": "203.0.113.5",
        "log_type": "web",
        "action": "GET /admin",
        "target": "/admin",
        "outcome": "ok",
    }
    with pytest.raises(ValueError, match="'ts' must be an integer"):
        validate_event(sample)

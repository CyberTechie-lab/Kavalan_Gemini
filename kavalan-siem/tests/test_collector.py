import os
import tempfile
import pytest
from collector import parse_web_line, parse_auth_line, FileTailer, ship_batch
from cem import validate_event


def test_parse_web_line():
    line = '203.0.113.66 - - [20/Oct/2026:06:05:00 +0000] "GET /admin?id=1 HTTP/1.1" 403 512 "-" "Mozilla/5.0"'
    ev = parse_web_line(line, host="web-01")
    assert ev is not None
    assert ev.source_ip == "203.0.113.66"
    assert ev.log_type == "web"
    assert ev.action == "GET /admin?id=1"
    assert ev.target == "/admin"
    assert ev.outcome == "denied"
    assert ev.status == 403
    assert ev.meta["method"] == "GET"
    assert ev.meta["path"] == "/admin?id=1"
    # Verify it strictly satisfies CEM validation
    validated = validate_event(ev.to_dict())
    assert validated.source_ip == "203.0.113.66"


def test_parse_auth_line():
    fail_line = "Oct 20 06:50:01 target sshd[1234]: Failed password for invalid user admin from 203.0.113.66 port 54321 ssh2"
    ev_fail = parse_auth_line(fail_line, host="host-01", year=2026)
    assert ev_fail is not None
    assert ev_fail.source_ip == "203.0.113.66"
    assert ev_fail.log_type == "auth"
    assert ev_fail.outcome == "fail"
    assert ev_fail.user == "admin"
    assert ev_fail.status == 1
    validated_fail = validate_event(ev_fail.to_dict())
    assert validated_fail.outcome == "fail"

    ok_line = "Oct 20 06:51:00 target sshd[1240]: Accepted password for deploy from 10.0.0.20 port 54400 ssh2"
    ev_ok = parse_auth_line(ok_line, host="host-01", year=2026)
    assert ev_ok is not None
    assert ev_ok.source_ip == "10.0.0.20"
    assert ev_ok.outcome == "ok"
    assert ev_ok.user == "deploy"
    assert ev_ok.status == 0
    validated_ok = validate_event(ev_ok.to_dict())
    assert validated_ok.outcome == "ok"


def test_file_tailer(tmp_path):
    log_file = tmp_path / "test.log"
    log_file.write_text("line 1\nline 2\n")

    tailer = FileTailer(str(log_file), "web")
    lines1 = tailer.read_new_lines()
    assert lines1 == ["line 1\n", "line 2\n"]

    # No new lines yet
    assert tailer.read_new_lines() == []

    # Append
    with open(log_file, "a") as f:
        f.write("line 3\n")

    lines2 = tailer.read_new_lines()
    assert lines2 == ["line 3\n"]

    # Truncate
    log_file.write_text("truncated line\n")
    lines3 = tailer.read_new_lines()
    assert lines3 == ["truncated line\n"]

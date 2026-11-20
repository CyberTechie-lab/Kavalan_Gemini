"""
Detection-quality gate for Kavalan.

These tests encode the invariants the product must hold on every change:
  1. A multi-source agent campaign is detected.
  2. Ordinary human users are never flagged (zero false positives).
  3. A benign high-volume crawler is not flagged.
  4. A classic noisy scanner is flagged.
  5. A single, aggressive automated source scores HIGH on its own.

They run rules-only (no trained model needed), so CI needs no dataset download
and is deterministic. Run locally with:  pytest -q
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import detector  # noqa: E402


def _run_simulation(seed=7):
    """Generate a labelled simulated log and return (sources, campaigns, truth)."""
    tmp = tempfile.mkdtemp()
    log = os.path.join(tmp, "sim.log")
    truth_path = os.path.join(tmp, "truth.json")
    subprocess.run(
        [sys.executable, os.path.join(HERE, "simulate.py"),
         "--seed", str(seed), "--out", log, "--truth", truth_path],
        check=True, capture_output=True,
    )
    by_ip, _ = detector.parse(log)
    detector.ML_LABELS = {}
    sources = [s for s in (detector.analyse(ip, ev) for ip, ev in by_ip.items()) if s]
    campaigns = detector.find_campaigns(sources)
    with open(truth_path) as f:
        truth = json.load(f)
    return sources, campaigns, truth


def _by_label(sources, truth):
    groups = {}
    for s in sources:
        groups.setdefault(truth.get(s["ip"], "unknown"), []).append(s)
    return groups


def test_agent_campaign_detected():
    sources, campaigns, truth = _run_simulation()
    assert campaigns, "no agent campaign detected"
    agent_ips = {ip for ip, label in truth.items() if label == "agent"}
    flagged = {ip for c in campaigns for ip in c["sources"]}
    # the campaign should cover the large majority of agent sources
    assert len(flagged & agent_ips) >= 0.8 * len(agent_ips)


def test_no_false_positives_on_humans():
    sources, _, truth = _run_simulation()
    humans = _by_label(sources, truth).get("human", [])
    assert humans, "simulation produced no human sources"
    flagged = [s for s in humans if s["score"] >= detector.MEDIUM]
    assert not flagged, f"human users falsely flagged: {[s['ip'] for s in flagged]}"


def test_crawler_not_flagged():
    sources, _, truth = _run_simulation()
    crawlers = _by_label(sources, truth).get("crawler", [])
    for s in crawlers:
        assert s["score"] < detector.MEDIUM, f"benign crawler flagged (score {s['score']})"


def test_scanner_flagged():
    sources, _, truth = _run_simulation()
    scanners = _by_label(sources, truth).get("scanner", [])
    assert scanners, "simulation produced no scanner"
    assert any(s["score"] >= detector.MEDIUM for s in scanners), "scanner not flagged"


def test_single_aggressive_agent_scores_high():
    """One source: fast, broad, hitting protected paths -> HIGH on its own."""
    ip = "10.0.0.9"
    events = []
    t = 1_700_000_000
    for i in range(1500):
        # machine-speed sweep across many distinct protected endpoints
        path = f"/api/v1/admin/resource/{i}"
        status = 403 if i % 3 else 200
        events.append((t + i // 50, "GET", path, status))
    s = detector.analyse(ip, events)
    assert s is not None
    assert s["score"] >= detector.HIGH, f"aggressive agent only scored {s['score']}"

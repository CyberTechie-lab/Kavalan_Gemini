#!/usr/bin/env python3
"""
manage.py - Kavalan SIEM SOC Management CLI

Commands:
  python3 manage.py start [--port 8900] [--live]
  python3 manage.py stop
  python3 manage.py status
  python3 manage.py simulate [cross_source | web_scan | ssh_brute | benign_burst]
  python3 manage.py test
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

SIEM_DIR = Path(__file__).resolve().parent
PID_FILE = SIEM_DIR / ".siem.pid"
FEED_PID_FILE = SIEM_DIR / ".feed.pid"
DB_FILE = SIEM_DIR / "kavalan_siem.db"


def is_pid_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def start_service(port: int = 8900, live: bool = False, window: int = 15, interval: int = 5):
    # Check if already running
    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text().strip())
            if is_pid_running(pid):
                print(f"[!] Kavalan SIEM is already running (PID: {pid}).")
                print(f"[*] Dashboard: http://127.0.0.1:{port}")
                return
        except Exception:
            pass

    cmd = [
        sys.executable, str(SIEM_DIR / "siem.py"),
        "--db", str(DB_FILE),
        "--port", str(port),
        "--window", str(window),
        "--interval", str(interval),
    ]

    log_path = SIEM_DIR / "siem.log"
    log_file = open(log_path, "a")

    proc = subprocess.Popen(
        cmd, cwd=str(SIEM_DIR),
        stdin=subprocess.DEVNULL,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        start_new_session=True
    )
    PID_FILE.write_text(str(proc.pid))
    print(f"[+] Started Kavalan SIEM Core (PID: {proc.pid})")
    print(f"[*] Dashboard live at: http://127.0.0.1:{port}")

    # Wait for server to be responsive
    for _ in range(15):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/state", timeout=1.0) as resp:
                if resp.status == 200:
                    break
        except Exception:
            time.sleep(0.5)

    if live:
        start_live_feed(port=port)


def start_live_feed(port: int = 8900, rate: float = 2.0):
    if FEED_PID_FILE.exists():
        try:
            pid = int(FEED_PID_FILE.read_text().strip())
            if is_pid_running(pid):
                print(f"[!] Live background traffic feed already running (PID: {pid}).")
                return
        except Exception:
            pass

    feed_cmd = [
        sys.executable, str(SIEM_DIR / "live_feed.py"),
        "--core", f"http://127.0.0.1:{port}",
        "--rate", str(rate),
        "--attack-interval", "45",
    ]
    feed_log = open(SIEM_DIR / "live_feed.log", "a")
    feed_proc = subprocess.Popen(
        feed_cmd, cwd=str(SIEM_DIR),
        stdin=subprocess.DEVNULL,
        stdout=feed_log,
        stderr=subprocess.STDOUT,
        start_new_session=True
    )
    FEED_PID_FILE.write_text(str(feed_proc.pid))
    print(f"[+] Started Live Traffic Generator (PID: {feed_proc.pid}, rate: {rate} EPS)")


def stop_service():
    stopped_any = False

    # Stop Live Feed
    if FEED_PID_FILE.exists():
        try:
            pid = int(FEED_PID_FILE.read_text().strip())
            if is_pid_running(pid):
                os.kill(pid, signal.SIGTERM)
                print(f"[-] Stopped Live Traffic Generator (PID: {pid})")
                stopped_any = True
        except Exception as e:
            print(f"[!] Error stopping live feed: {e}")
        FEED_PID_FILE.unlink(missing_ok=True)

    # Stop SIEM core
    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text().strip())
            if is_pid_running(pid):
                os.kill(pid, signal.SIGTERM)
                print(f"[-] Stopped Kavalan SIEM Core (PID: {pid})")
                stopped_any = True
        except Exception as e:
            print(f"[!] Error stopping core: {e}")
        PID_FILE.unlink(missing_ok=True)

    if not stopped_any:
        print("[*] No running Kavalan services found.")


def print_status(port: int = 8900):
    siem_running = False
    siem_pid = None
    if PID_FILE.exists():
        try:
            siem_pid = int(PID_FILE.read_text().strip())
            siem_running = is_pid_running(siem_pid)
        except Exception:
            pass

    feed_running = False
    feed_pid = None
    if FEED_PID_FILE.exists():
        try:
            feed_pid = int(FEED_PID_FILE.read_text().strip())
            feed_running = is_pid_running(feed_pid)
        except Exception:
            pass

    print("=" * 64)
    print(" KAVALAN SIEM &middot; SYSTEM STATUS")
    print("=" * 64)
    print(f" SIEM Core:     {'[RUNNING] (PID ' + str(siem_pid) + ')' if siem_running else '[STOPPED]'}")
    print(f" Live Feed:     {'[RUNNING] (PID ' + str(feed_pid) + ')' if feed_running else '[STOPPED]'}")
    print(f" Database:      {DB_FILE} ({'exists' if DB_FILE.exists() else 'not created'})")

    if siem_running:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/state", timeout=2.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                counts = data.get("counts", {})
                print(f" Dashboard:     http://127.0.0.1:{port}")
                print(f" Ingestion EPS: {data.get('eps', 0.0)} events/sec")
                print(f" Total Events:  {data.get('total_events', 0):,}")
                print(f" Active Alerts: {len(data.get('alerts', []))} "
                      f"(CRIT: {counts.get('CRITICAL',0)}, HIGH: {counts.get('HIGH',0)}, MED: {counts.get('MEDIUM',0)})")
                print(f" Window:        {data.get('window_minutes', 15)} min ({data.get('events_in_window', 0):,} events from {data.get('sources_in_window', 0)} sources)")
        except Exception as e:
            print(f" Health check:  Failed to reach http://127.0.0.1:{port}: {e}")
    print("=" * 64)


def simulate_scenario(scenario: str, port: int = 8900, host: str = "server"):
    url = f"http://127.0.0.1:{port}/api/simulate"
    req = urllib.request.Request(
        url,
        data=json.dumps({"scenario": scenario, "host": host}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"[+] Scenario '{scenario}' successfully injected into SIEM!")
            print(f"    Generated events: {data.get('generated_events')}")
            print(f"    Actor IP:         {data.get('actor_ip')}")
            print(f"    Accepted:         {data.get('ingest_result', {}).get('accepted')}")
            print(f"[*] Check dashboard at: http://127.0.0.1:{port}")
    except Exception as e:
        print(f"[!] Error sending simulation request: {e}", file=sys.stderr)


def run_tests():
    cmd = [sys.executable, "-m", "pytest", "-v", str(SIEM_DIR / "tests")]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SIEM_DIR)
    subprocess.run(cmd, env=env)


def main():
    parser = argparse.ArgumentParser(description="Kavalan SIEM SOC Manager")
    sub = parser.add_subparsers(dest="command")

    p_start = sub.add_parser("start", help="Start Kavalan SIEM Core service")
    p_start.add_argument("--port", type=int, default=8900, help="Port to bind (default: 8900)")
    p_start.add_argument("--live", action="store_true", help="Also start real-time continuous background traffic generator")
    p_start.add_argument("--window", type=int, default=15, help="Rolling detection window in minutes")
    p_start.add_argument("--interval", type=int, default=5, help="Detection pass interval in seconds")

    p_stop = sub.add_parser("stop", help="Stop running Kavalan SIEM services")

    p_status = sub.add_parser("status", help="Show live system status, EPS and alert counts")
    p_status.add_argument("--port", type=int, default=8900)

    p_sim = sub.add_parser("simulate", help="Inject live attack scenario")
    p_sim.add_argument("scenario", choices=["cross_source", "web_scan", "ssh_brute", "benign_burst"], default="cross_source", nargs="?")
    p_sim.add_argument("--port", type=int, default=8900)

    p_test = sub.add_parser("test", help="Run full automated test suite")

    args = parser.parse_args()

    if args.command == "start":
        start_service(port=args.port, live=args.live, window=args.window, interval=args.interval)
    elif args.command == "stop":
        stop_service()
    elif args.command == "status":
        print_status(port=args.port)
    elif args.command == "simulate":
        simulate_scenario(scenario=args.scenario, port=args.port)
    elif args.command == "test":
        run_tests()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

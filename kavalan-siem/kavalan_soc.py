#!/usr/bin/env python3
"""
kavalan_soc.py - Unified Orchestrator for the 4-Tier Distributed SIEM

Manages the entire distributed 4-tier lightweight architecture:
  Tier 1: Agent Fleet (web-01, auth-01 persistent daemons)
  Tier 2: Manager (8910)
  Tier 3: Indexer (8920)
  Tier 4: Dashboard (8900)

Usage:
  python3 kavalan_soc.py start
  python3 kavalan_soc.py restart
  python3 kavalan_soc.py status
  python3 kavalan_soc.py stop
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

try:
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(10240, hard), hard))
except Exception:
    pass

BASE_DIR = Path(__file__).resolve().parent
PID_DIR = BASE_DIR / ".pids"
PID_DIR.mkdir(exist_ok=True)

SERVICES = {
    "indexer": {
        "file": BASE_DIR / "indexer" / "indexer.py",
        "args": ["--port", "8920"],
        "port": 8920,
        "pid_file": PID_DIR / "indexer.pid",
        "log": BASE_DIR / "indexer.log"
    },
    "manager": {
        "file": BASE_DIR / "manager" / "manager.py",
        "args": ["--host", "0.0.0.0", "--port", "8910"],
        "port": 8910,
        "pid_file": PID_DIR / "manager.pid",
        "log": BASE_DIR / "manager.log"
    },
    "dashboard": {
        "file": BASE_DIR / "dashboard" / "dashboard_server.py",
        "args": ["--host", "0.0.0.0", "--port", "8900"],
        "port": 8900,
        "pid_file": PID_DIR / "dashboard.pid",
        "log": BASE_DIR / "dashboard.log"
    },
    "agent_web": {
        "file": BASE_DIR / "agent" / "agent.py",
        "args": [
            "--name", "web-01",
            "--web", str(BASE_DIR.parent / "kavalan-ml" / "access.log"),
            "--manager", "http://127.0.0.1:8910"
        ],
        "port": None,
        "pid_file": PID_DIR / "agent_web.pid",
        "log": BASE_DIR / "agent_web.log"
    },
    "agent_auth": {
        "file": BASE_DIR / "agent" / "agent.py",
        "args": [
            "--name", "auth-01",
            "--auth", str(BASE_DIR.parent / "kavalan-ml" / "auth.log"),
            "--year", "2026",
            "--manager", "http://127.0.0.1:8910"
        ],
        "port": None,
        "pid_file": PID_DIR / "agent_auth.pid",
        "log": BASE_DIR / "agent_auth.log"
    },
}


def is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def kill_port_listener(port: int):
    try:
        out = subprocess.check_output(["lsof", "-t", f"-i:{port}"], text=True).strip()
        for p in out.split():
            try:
                pid = int(p)
                os.kill(pid, signal.SIGKILL)
            except Exception:
                pass
    except Exception:
        pass


def start_tier(name: str) -> None:
    cfg = SERVICES[name]
    pid_file = cfg["pid_file"]
    port = cfg.get("port")

    if pid_file.exists():
        try:
            pid = int(pid_file.read_text().strip())
            if is_running(pid):
                port_str = f", port: {port}" if port else ""
                print(f"[*] {name.replace('_', ' ').capitalize()} is already running (PID: {pid}{port_str})")
                return
        except Exception:
            pass

    if port:
        kill_port_listener(port)

    log_f = open(cfg["log"], "a", buffering=1)
    cmd = [sys.executable, "-u", str(cfg["file"])] + cfg.get("args", [])
    proc = subprocess.Popen(
        cmd,
        cwd=str(BASE_DIR),
        stdin=subprocess.DEVNULL,
        stdout=log_f,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        env={**os.environ, "PYTHONUNBUFFERED": "1"}
    )
    pid_file.write_text(str(proc.pid))
    port_str = f", port: {port}" if port else " (daemon)"
    print(f"[+] Started {name.replace('_', ' ').capitalize()} (PID: {proc.pid}{port_str})")

    # Wait for service readiness
    if port:
        for _ in range(25):
            try:
                url = f"http://127.0.0.1:{port}/health" if name != "dashboard" else f"http://127.0.0.1:{port}/"
                with urllib.request.urlopen(url, timeout=1.0) as resp:
                    if resp.status == 200:
                        break
            except Exception:
                time.sleep(0.2)
    else:
        # Agent daemon: ensure it didn't immediately crash
        time.sleep(0.5)
        if not is_running(proc.pid):
            print(f"[!] Warning: {name} exited unexpectedly. Inspect {cfg['log']}")


def stop_tier(name: str) -> None:
    cfg = SERVICES[name]
    pid_file = cfg["pid_file"]
    if pid_file.exists():
        try:
            pid = int(pid_file.read_text().strip())
            if is_running(pid):
                os.kill(pid, signal.SIGTERM)
                # Wait up to 2 seconds for graceful shutdown
                for _ in range(20):
                    if not is_running(pid):
                        break
                    time.sleep(0.1)
                if is_running(pid):
                    os.kill(pid, signal.SIGKILL)
                print(f"[-] Stopped {name.replace('_', ' ').capitalize()} (PID: {pid})")
        except Exception:
            pass
        pid_file.unlink(missing_ok=True)

    if cfg.get("port"):
        kill_port_listener(cfg["port"])


def start_all():
    print("=" * 68)
    print(" STARTING KAVALAN 4-TIER DISTRIBUTED SOC ARCHITECTURE")
    print("=" * 68)
    # Tier 3: Indexer first
    start_tier("indexer")
    # Tier 2: Manager
    start_tier("manager")
    # Tier 4: Dashboard
    start_tier("dashboard")

    # Tier 1: Agents (Persistent Background Daemons)
    print("[*] Starting persistent Tier 1 Agent daemons (web-01 & auth-01)...")
    start_tier("agent_web")
    start_tier("agent_auth")

    # Give agents time to harvest & manager to score
    time.sleep(1.5)
    try:
        req = urllib.request.Request(
            "http://127.0.0.1:8910/api/scan",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        urllib.request.urlopen(req, timeout=3.0)
    except Exception:
        pass

    print("=" * 68)
    print(" KAVALAN 4-TIER PLATFORM IS ONLINE & READY!")
    print(" Dashboard Console: http://127.0.0.1:8900  <-- Open in browser")
    print(" Manager API:       http://127.0.0.1:8910")
    print(" Indexer API:       http://127.0.0.1:8920")
    print(" Tip: In your browser, press Cmd+Shift+R (Mac) or Ctrl+F5 (Win)")
    print("      to bypass any cached version of the dashboard.")
    print("=" * 68)


def stop_all():
    print("[-] Shutting down all Kavalan SIEM tiers and agents...")
    # Stop agents first
    stop_tier("agent_web")
    stop_tier("agent_auth")
    # Stop servers
    stop_tier("dashboard")
    stop_tier("manager")
    stop_tier("indexer")

    # Kill anything still bound to SIEM ports
    kill_port_listener(8900)
    kill_port_listener(8910)
    kill_port_listener(8920)

    # Clean up any leftover agent state files
    for f in BASE_DIR.glob(".agent_*.json"):
        f.unlink(missing_ok=True)
    print("[*] All services stopped cleanly.")


def restart_all():
    print("[*] Performing clean restart of Kavalan SIEM...")
    stop_all()
    time.sleep(1.0)
    start_all()


def status_all():
    print("=" * 68)
    print(" KAVALAN DISTRIBUTED SOC \u00b7 FLEET STATUS")
    print("=" * 68)
    for name, cfg in SERVICES.items():
        running = False
        pid = None
        if cfg["pid_file"].exists():
            try:
                pid = int(cfg["pid_file"].read_text().strip())
                running = is_running(pid)
            except Exception:
                pass
        p_info = f", port {cfg['port']}" if cfg.get("port") else ""
        st = f"[RUNNING] (PID {pid}{p_info})" if running else "[STOPPED]"
        label = name.replace("_", " ").capitalize()
        print(f" {label:<16} {st}")

    print("-" * 68)
    try:
        with urllib.request.urlopen("http://127.0.0.1:8910/api/agents", timeout=1.5) as r:
            agents = json.loads(r.read().decode("utf-8")).get("agents", [])
            print(f" Registered Agents: {len(agents)}")
            for a in agents:
                st_color = a["status"].upper()
                print(f"   [{a['id']}] {a['name']:<12} ({a['ip']}) - {st_color} (OS: {a['os']})")
    except Exception:
        print(" Agents:            Manager not reachable")

    try:
        with urllib.request.urlopen("http://127.0.0.1:8920/api/stats", timeout=1.5) as r:
            idx = json.loads(r.read().decode("utf-8"))
            print(f" Indexer Stats:     {idx.get('total_events', 0):,} events indexed ({idx.get('db_size_mb', 0)} MB)")
    except Exception:
        print(" Indexer:           Indexer not reachable")

    try:
        with urllib.request.urlopen("http://127.0.0.1:8910/api/state", timeout=1.5) as r:
            st = json.loads(r.read().decode("utf-8"))
            c = st.get("counts", {})
            print(f" Active Threats:    CRITICAL: {c.get('CRITICAL', 0)} | HIGH: {c.get('HIGH', 0)} | MEDIUM: {c.get('MEDIUM', 0)}")
    except Exception:
        pass
    print("=" * 68)


def main():
    parser = argparse.ArgumentParser(description="Kavalan 4-Tier Distributed SOC Platform")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("start", help="Start all 4 tiers (Indexer, Manager, Dashboard, Agents)")
    sub.add_parser("restart", help="Restart all 4 tiers cleanly")
    sub.add_parser("stop", help="Stop all tiers")
    sub.add_parser("status", help="Inspect status of all 4 tiers and agent fleet")
    args = parser.parse_args()

    if args.cmd == "start":
        start_all()
    elif args.cmd == "restart":
        restart_all()
    elif args.cmd == "stop":
        stop_all()
    elif args.cmd == "status":
        status_all()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

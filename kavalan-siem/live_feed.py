#!/usr/bin/env python3
"""
live_feed.py - Kavalan SIEM Live Real-Time Traffic Generator

Generates realistic background traffic and security scenarios with current
timestamps, continuously feeding Kavalan SIEM core like a live production environment.

Usage:
  python3 live_feed.py --core http://127.0.0.1:8900 --rate 2.0
  python3 live_feed.py --scenario cross_source   # instant attack injection
"""

import argparse
import json
import random
import signal
import sys
import time
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List

WEB_PAGES = [
    "/", "/products", "/about", "/cart", "/rest/products/search?q=shoes",
    "/rest/products/search?q=juice", "/login", "/contact", "/api/Products",
    "/rest/basket/1", "/assets/styles.css", "/assets/main.js"
]

WEB_ATTACKS = [
    ("GET", "/admin", 401, "denied"),
    ("GET", "/api/v1/admin/tokens", 403, "denied"),
    ("GET", "/page?file=../../../../etc/passwd", 404, "fail"),
    ("POST", "/rest/products/search?q=1' OR '1'='1", 500, "error"),
    ("GET", "/.env", 404, "fail"),
    ("GET", "/.git/config", 404, "fail"),
    ("GET", "/redirect?url=http://169.254.169.254/", 403, "denied"),
    ("POST", "/cmd?x=;id", 403, "denied"),
]

SSH_USERS = ["root", "admin", "ubuntu", "msfadmin", "deploy", "postgres", "test", "git"]


def ship_events(core_url: str, events: List[Dict]) -> bool:
    if not events:
        return True
    url = f"{core_url.rstrip('/')}/ingest"
    data = json.dumps(events).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return resp.status == 200
    except Exception as e:
        print(f"[live_feed] Error shipping {len(events)} events: {e}", file=sys.stderr)
        return False


def make_benign_web_event(host="web-01") -> Dict:
    now = int(time.time())
    ip = f"192.0.2.{random.randint(10, 39)}"
    path = random.choice(WEB_PAGES)
    method = "POST" if ("login" in path and random.random() < 0.3) else "GET"
    status_code = 200 if random.random() > 0.05 else 404
    outcome = "ok" if status_code == 200 else "fail"
    return {
        "ts": now,
        "host": host,
        "source_ip": ip,
        "log_type": "web",
        "action": f"{method} {path}",
        "target": path.split("?", 1)[0],
        "outcome": outcome,
        "status": status_code,
        "user": None,
        "raw": f'{ip} - - [{datetime.fromtimestamp(now, timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {path} HTTP/1.1" {status_code} 512',
        "meta": {"method": method, "path": path},
    }


def make_benign_ssh_event(host="web-01") -> Dict:
    now = int(time.time())
    ip = f"10.0.0.{random.randint(20, 25)}"
    user = random.choice(["deploy", "backup", "ci"])
    return {
        "ts": now,
        "host": host,
        "source_ip": ip,
        "log_type": "auth",
        "action": "ssh_ok",
        "target": "sshd",
        "outcome": "ok",
        "status": 0,
        "user": user,
        "raw": f'{datetime.fromtimestamp(now, timezone.utc).strftime("%b %d %H:%M:%S")} {host} sshd[1050]: Accepted password for {user} from {ip} port 51234 ssh2',
        "meta": {"service": "sshd"},
    }


def inject_cross_source_attack(core_url: str, host="web-01"):
    now = int(time.time())
    ip = f"203.0.113.{random.randint(200, 240)}"
    print(f"[*] INJECTING CROSS-SOURCE ATTACK from actor: {ip}")
    events = []

    # 1. Rapid web attack
    for _ in range(50):
        method, path, status_code, outcome = random.choice(WEB_ATTACKS)
        events.append({
            "ts": now,
            "host": host,
            "source_ip": ip,
            "log_type": "web",
            "action": f"{method} {path}",
            "target": path.split("?", 1)[0],
            "outcome": outcome,
            "status": status_code,
            "user": None,
            "raw": f'{ip} - - [{datetime.fromtimestamp(now, timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {path} HTTP/1.1" {status_code} 512',
            "meta": {"method": method, "path": path},
        })

    # 2. SSH Brute-force & Breach
    for _ in range(25):
        u = random.choice(SSH_USERS)
        events.append({
            "ts": now,
            "host": host,
            "source_ip": ip,
            "log_type": "auth",
            "action": "ssh_fail",
            "target": "sshd",
            "outcome": "fail",
            "status": 1,
            "user": u,
            "raw": f'{datetime.fromtimestamp(now, timezone.utc).strftime("%b %d %H:%M:%S")} {host} sshd[1055]: Failed password for {u} from {ip} port 52345 ssh2',
            "meta": {"service": "sshd"},
        })

    # Accepted login breach
    events.append({
        "ts": now + 1,
        "host": host,
        "source_ip": ip,
        "log_type": "auth",
        "action": "ssh_ok",
        "target": "sshd",
        "outcome": "ok",
        "status": 0,
        "user": "msfadmin",
        "raw": f'{datetime.fromtimestamp(now + 1, timezone.utc).strftime("%b %d %H:%M:%S")} {host} sshd[1056]: Accepted password for msfadmin from {ip} port 52345 ssh2',
        "meta": {"service": "sshd"},
    })

    ship_events(core_url, events)
    print(f"[+] Cross-source attack shipped ({len(events)} events).")


def run_continuous_feed(core_url: str, rate: float = 2.0, host: str = "web-01",
                        attack_interval: int = 45):
    running = True

    def _sig(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    print(f"[*] Live continuous feed started -> {core_url}")
    print(f"[*] Target EPS: ~{rate:.1f} events/s | Periodic attacks: every {attack_interval}s")

    last_attack = time.time()
    buffer = []
    last_flush = time.time()

    while running:
        # Generate benign events
        if random.random() < 0.85:
            buffer.append(make_benign_web_event(host))
        else:
            buffer.append(make_benign_ssh_event(host))

        now = time.time()
        # Flush batch
        if len(buffer) >= 10 or (now - last_flush >= 1.0 and buffer):
            ship_events(core_url, buffer)
            buffer.clear()
            last_flush = now

        # Periodic attack scenario
        if attack_interval > 0 and (now - last_attack >= attack_interval):
            inject_cross_source_attack(core_url, host)
            last_attack = now

        delay = 1.0 / max(0.1, rate)
        time.sleep(delay)

    if buffer:
        ship_events(core_url, buffer)
    print("[*] Live feed stopped.")


def main():
    parser = argparse.ArgumentParser(description="Kavalan SIEM Real-Time Live Traffic Generator")
    parser.add_argument("--core", default="http://127.0.0.1:8900", help="Core SIEM URL")
    parser.add_argument("--rate", type=float, default=2.0, help="Events per second (default: 2.0)")
    parser.add_argument("--host", default="web-01", help="Host ID (default: web-01)")
    parser.add_argument("--attack-interval", type=int, default=45, help="Seconds between periodic attacks (default: 45, 0 to disable)")
    parser.add_argument("--scenario", choices=["cross_source", "web_scan", "ssh_brute"], help="Inject single scenario and exit")
    args = parser.parse_args()

    if args.scenario:
        if args.scenario == "cross_source":
            inject_cross_source_attack(args.core, args.host)
        else:
            req = urllib.request.Request(
                f"{args.core}/api/simulate",
                data=json.dumps({"scenario": args.scenario}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            urllib.request.urlopen(req, timeout=5.0)
            print(f"[+] Scenario '{args.scenario}' injected.")
        return

    run_continuous_feed(args.core, rate=args.rate, host=args.host, attack_interval=args.attack_interval)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
simulate_multi.py - writes a matching web access.log and SSH auth.log for the
multi-source prototype. No network traffic; documentation IPs only (RFC 5737).

Scenario:
  - benign web users and benign SSH logins
  - a web-only scanner
  - an SSH-only brute-forcer
  - a CROSS-SOURCE agent: ONE IP that attacks the web app AND brute-forces SSH

Usage:  python3 simulate_multi.py   # writes access.log and auth.log
"""
import random
from datetime import datetime, timedelta, timezone

random.seed(20)
START = datetime(2026, 10, 20, 6, 0, 0, tzinfo=timezone.utc)
WEB_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0 Safari/537.36"

CROSS_IP = "203.0.113.66"      # attacks web AND ssh
WEB_SCANNER = "198.51.100.23"  # web only
SSH_BRUTE = "198.51.100.99"    # ssh only

web_lines, auth_lines = [], []


def w(ip, dt, method, path, status):
    t = dt.strftime("%d/%b/%Y:%H:%M:%S %z")
    web_lines.append(f'{ip} - - [{t}] "{method} {path} HTTP/1.1" {status} 512 "-" "{WEB_UA}"')


def a(dt, msg):
    auth_lines.append(f'{dt.strftime("%b %d %H:%M:%S")} target sshd[{random.randint(1000,9999)}]: {msg}')


# --- benign web users -------------------------------------------------------
pages = ["/", "/products", "/about", "/cart", "/rest/products/search?q=shoes", "/login"]
for u in range(20):
    ip = f"192.0.2.{10 + u}"
    t = START + timedelta(seconds=random.randint(0, 540))
    for _ in range(random.randint(4, 9)):
        w(ip, t, "GET", random.choice(pages), 200)
        t += timedelta(seconds=random.randint(5, 40))

# --- benign SSH logins ------------------------------------------------------
for i in range(3):
    t = START + timedelta(seconds=random.randint(0, 540))
    a(t, f"Accepted password for deploy from 10.0.0.{20+i} port {random.randint(40000,60000)} ssh2")

# --- web-only scanner -------------------------------------------------------
t = START + timedelta(seconds=120)
scan_paths = ["/admin", "/.env", "/.git/config", "/backup.zip", "/config.json",
              "/phpinfo.php", "/server-status", "/wp-login.php", "/api/v1/admin/users"]
for _ in range(400):
    p = random.choice(scan_paths) + f"/{random.randint(1,999)}"
    w(WEB_SCANNER, t, "GET", p, random.choice([404, 404, 403, 401]))
    t += timedelta(seconds=random.uniform(0.05, 0.3))

# --- ssh-only brute-forcer --------------------------------------------------
t = START + timedelta(seconds=200)
users = ["root", "admin", "test", "oracle", "postgres", "ubuntu", "git", "ftp", "user", "msfadmin"]
for _ in range(70):
    u = random.choice(users)
    a(t, f"Failed password for {'invalid user ' if u not in ('root','msfadmin') else ''}{u} "
         f"from {SSH_BRUTE} port {random.randint(40000,60000)} ssh2")
    t += timedelta(seconds=random.uniform(0.3, 1.5))

# --- CROSS-SOURCE agent: same IP, both channels -----------------------------
# web side: broad, fast, attack tactics, hits protected paths
t = START + timedelta(seconds=300)
atk = ["/admin", "/api/v1/admin/tokens", "/rest/products/search?q=1' OR '1'='1",
       "/page?file=../../../../etc/passwd", "/api/v1/datasets/internal-evals",
       "/.env", "/.git/config", "/cmd?x=;id", "/redirect?url=http://169.254.169.254/"]
for i in range(300):
    p = random.choice(atk) + (f"/{i}" if random.random() < 0.5 else "")
    status = random.choice([404, 403, 401, 500, 200])
    w(CROSS_IP, t, random.choice(["GET", "POST"]), p, status)
    t += timedelta(seconds=random.uniform(0.02, 0.1))
# ssh side: brute force from the SAME ip, then a success (breach)
t = START + timedelta(seconds=300)
for i in range(55):
    u = random.choice(users)
    a(t, f"Failed password for {'invalid user ' if u not in ('root','msfadmin') else ''}{u} "
         f"from {CROSS_IP} port {random.randint(40000,60000)} ssh2")
    t += timedelta(seconds=random.uniform(0.5, 2.0))
a(t, f"Accepted password for msfadmin from {CROSS_IP} port {random.randint(40000,60000)} ssh2")

random.shuffle(web_lines)  # interleave sources as a real log would
# auth.log is time-ordered in reality; sort by writing order is fine for the demo
open("access.log", "w").write("\n".join(web_lines) + "\n")
open("auth.log", "w").write("\n".join(auth_lines) + "\n")
print(f"wrote access.log ({len(web_lines)} lines) and auth.log ({len(auth_lines)} lines)")
print(f"cross-source agent = {CROSS_IP}  |  web scanner = {WEB_SCANNER}  |  ssh brute = {SSH_BRUTE}")

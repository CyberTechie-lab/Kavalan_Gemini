#!/usr/bin/env python3
"""
script_attack.py - simulates a SCRIPTED scanner against the lab, for contrast with
the human attacker and the AI agent.

A scripted scanner (think an off-the-shelf dir-buster / vuln scanner) is the opposite
of a human: it runs one tool's fixed playbook at machine speed from a single source,
blasting a big wordlist of guessed paths, almost all of which 404. One IP, one tactic,
very noisy, high error rate - exactly the "classic scanner" signature.

Running it alongside the normal users, the human attacker and the AI agent shows that
Kavalan separates a dumb fast script from an adaptive autonomous agent.

It sends real (but harmless) GET probes to the lab target only. Run it only against your lab.

Usage:
    python3 script_attack.py --base http://nginx --minutes 5 --rate 10
"""
import argparse
import random
import time
import urllib.request

# A dir-buster style wordlist: common files and folders a scanner guesses.
WORDS = [
    "admin", "administrator", "backup", "backups", "old", "test", "dev", "staging",
    "config", "config.php", "db", "database", "dump.sql", "db.sql", "login", "logout",
    "portal", "private", "secret", "uploads", "files", "tmp", "temp", "logs", "log",
    "status", "info.php", "phpinfo.php", "phpmyadmin", "wp-admin", "wp-login.php",
    "console", "manager", "shell", "cgi-bin", "data", "export", "internal", "debug",
    "panel", "user", "users", "account", "billing", "api", "api/v1", "server-status",
    "web.config", ".env", ".git/config", ".git/HEAD", ".htaccess", "robots.txt",
    "sitemap.xml", "README.md", "CHANGELOG", "package.json", "composer.json",
    "swagger", "swagger.json", "api-docs", "actuator", "actuator/health", "metrics",
    "vendor", "node_modules", "assets", "images", "img", "css", "js", "docs",
    "ftp", "ftp/", "ftp/legal.md", "ftp/package.json.bak", "ftp/coupons_2013.md.bak",
]
SUFFIXES = ["", "/", ".bak", ".zip", ".tar.gz", ".old"]
# A scanner announces itself with a tool-shaped User-Agent.
UA = "Mozilla/5.0 (compatible; dirbuster/1.0; +scripted-scan)"


def send(base, path):
    req = urllib.request.Request(base + path, method="GET",
                                 headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read(256)
            return r.status
    except Exception as e:
        return getattr(e, "code", None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://nginx")
    ap.add_argument("--minutes", type=float, default=5)
    ap.add_argument("--rate", type=float, default=10, help="requests per second")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    rng = random.Random(args.seed or None)

    targets = [w + s for w in WORDS for s in SUFFIXES]
    rng.shuffle(targets)

    gap = 1.0 / args.rate if args.rate > 0 else 0
    stop = time.time() + args.minutes * 60
    sent = hits = 0
    print(f"Scripted scanner hammering {args.base} at ~{args.rate}/s for {args.minutes} min.")
    i = 0
    while time.time() < stop:
        path = "/" + targets[i % len(targets)]
        i += 1
        code = send(args.base, path)
        sent += 1
        if code and 200 <= code < 300:
            hits += 1
        if sent % 50 == 0:
            print(f"  {sent} requests sent, {hits} hits so far")
        if gap:
            time.sleep(gap)
    print(f"Scripted scanner done: {sent} requests, {hits} non-404 hits.")


if __name__ == "__main__":
    main()

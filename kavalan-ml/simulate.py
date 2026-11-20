#!/usr/bin/env python3
"""
simulate.py - writes a synthetic web access log for testing detector.py.

One hour of traffic containing four kinds of visitor:

  1. Human visitors    slow, pages plus static assets, almost no errors
  2. A search crawler  steady, polite, GET only
  3. A classic scanner one IP, one tactic (directory brute force), very noisy
  4. An agent campaign many short-lived IPs, machine speed, switching tactics,
                       all working toward one protected resource

It only writes text to a file. It sends no network traffic.
All IPs come from the documentation ranges in RFC 5737, so none is a real host.

Usage:
    python3 simulate.py                 # writes access.log and truth.json
    python3 simulate.py --seed 42       # a different random run
"""
import argparse
import json
import random
from datetime import datetime, timedelta, timezone

START = datetime(2026, 10, 9, 10, 0, 0, tzinfo=timezone.utc)
HOUR = 3600
TARGET = "/api/v1/datasets/internal-evals"

BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Mobile Safari/537.36",
]
AGENT_UAS = ["python-requests/2.32.3", "curl/8.5.0", "Go-http-client/2.0", "node-fetch/3.3", "python-httpx/0.27"]

PAGES = ["/", "/models", "/datasets", "/docs", "/pricing", "/blog", "/docs/quickstart",
         "/models/text-small", "/datasets/public-reviews", "/blog/release-notes"]
ASSETS = ["/static/app.css", "/static/app.js", "/static/logo.svg", "/static/font.woff2", "/static/hero.png"]

SCAN_WORDS = ["admin", "backup", "test", "old", "dev", "staging", "api", "config", "db", "dump", "login",
              "portal", "private", "secret", "uploads", "files", "tmp", "temp", "logs", "status", "info",
              "phpmyadmin", "wp-admin", "wp-login", "console", "manager", "shell", "cgi-bin", "data",
              "export", "internal", "debug", "panel", "user", "users", "account", "billing", "store",
              "shop", "cart", "search", "mail", "webmail", "cpanel", "server", "site", "web", "www",
              "include", "includes", "lib", "src", "vendor", "node_modules", "assets", "images", "img",
              "css", "docs", ".env", ".git"]
SCAN_SUFFIXES = ["", "/", ".php", ".bak", ".zip"]


def pick(rng, weighted):
    """weighted is a list of (value, weight)."""
    values, weights = zip(*weighted)
    return rng.choices(values, weights=weights, k=1)[0]


# ---------------------------------------------------------------- normal traffic

def humans(rng, ev, truth, count):
    for i in range(count):
        ip = f"198.51.100.{i + 1}"
        truth[ip] = "human"
        ua = rng.choice(BROWSER_UAS)
        t = rng.uniform(0, HOUR - 300)
        views = rng.randint(3, 15)
        login_at = rng.randrange(views) if rng.random() < 0.3 else -1
        for n in range(views):
            t += rng.uniform(3, 90)
            if t > HOUR - 10:
                break
            if n == login_at:
                ev.append((t, ip, "GET", "/login", 200, 2100, ua))
                t += rng.uniform(4, 15)
                if rng.random() < 0.2:  # mistyped password
                    ev.append((t, ip, "POST", "/login", 401, 310, ua))
                    t += rng.uniform(4, 12)
                ev.append((t, ip, "POST", "/login", 302, 0, ua))
                ev.append((t + 0.4, ip, "GET", "/dashboard", 200, 8400, ua))
                continue
            page = rng.choice(PAGES)
            if rng.random() < 0.02:  # typo or stale link
                ev.append((t, ip, "GET", page + "x", 404, 560, ua))
                continue
            ev.append((t, ip, "GET", page, 200, rng.randint(3000, 40000), ua))
            for asset in rng.sample(ASSETS, rng.randint(2, 5)):
                ev.append((t + rng.uniform(0.05, 1.0), ip, "GET", asset,
                           pick(rng, [(200, 0.6), (304, 0.4)]), rng.randint(500, 90000), ua))


def crawler(rng, ev, truth):
    ip = "192.0.2.10"
    truth[ip] = "crawler"
    ua = "Mozilla/5.0 (compatible; ExampleBot/2.1; +http://example.com/bot)"
    ev.append((1.0, ip, "GET", "/robots.txt", 200, 120, ua))
    t = 2.0
    while t < HOUR:
        page = rng.choice(PAGES) if rng.random() < 0.5 else f"/datasets/public-{rng.randint(1, 900)}"
        status = pick(rng, [(200, 0.94), (304, 0.05), (404, 0.01)])
        ev.append((t, ip, "GET", page, status, rng.randint(2000, 30000), ua))
        t += rng.uniform(2, 6)


# ---------------------------------------------------------------- classic scanner

def scanner(rng, ev, truth):
    ip = "192.0.2.66"
    truth[ip] = "scanner"
    ua = "Mozilla/5.0 (compatible; dirscan/1.0)"
    t = 600.0
    paths = [f"/{w}{s}" for w in SCAN_WORDS for s in SCAN_SUFFIXES]
    rng.shuffle(paths)
    for path in paths * 6:
        if path in ("/login", "/docs", "/docs/"):
            status = 200
        elif path.startswith("/admin"):
            status = 403
        else:
            status = 404
        ev.append((t, ip, "GET", path, status, 560, ua))
        t += rng.uniform(0.12, 0.2)


# ---------------------------------------------------------------- agent campaign

def tactic_request(rng, tactic, progress):
    """Returns (method, path, status) for one request of the given tactic."""
    if tactic == "recon":
        path, status = rng.choice([
            ("/robots.txt", 200), ("/sitemap.xml", 200), ("/.env", 404), ("/.git/config", 404),
            ("/server-status", 403), ("/api/v1/openapi.json", 200), ("/.well-known/security.txt", 404),
            ("/api/v1/health", 200), ("/backup.zip", 404), ("/config.json", 404), ("/api/v1/version", 200),
            ("/.aws/credentials", 404), ("/phpinfo.php", 404),
        ])
        return "GET", path, status
    if tactic == "api_enum":
        res = rng.choice(["users", "orgs", "datasets", "models", "billing", "jobs"])
        return "GET", f"/api/v1/{res}/{rng.randint(1, 5000)}", pick(rng, [(401, 0.5), (403, 0.3), (404, 0.2)])
    if tactic == "auth":
        if rng.random() < 0.7:
            return "POST", "/api/v1/login", pick(rng, [(401, 0.95), (429, 0.05)])
        return "GET", f"/api/v1/tokens/{rng.getrandbits(48):012x}", 401
    if tactic == "sqli":
        payload = rng.choice(["1'%20OR%20'1'='1", "1%20UNION%20SELECT%20null,null--", "1;--",
                              "1'%20AND%20SLEEP(2)--"])
        return "GET", f"/api/v1/datasets?id={payload}", pick(rng, [(400, 0.5), (403, 0.4), (500, 0.1)])
    if tactic == "traversal":
        payload = rng.choice(["..%2F..%2F..%2Fetc%2Fpasswd", "....//....//etc/passwd",
                              "%2e%2e%2f%2e%2e%2fetc%2fpasswd"])
        return "GET", f"/api/v1/files?path={payload}", pick(rng, [(400, 0.5), (403, 0.5)])
    if tactic == "ssrf":
        payload = rng.choice(["http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F",
                              "http%3A%2F%2Flocalhost%3A8080%2Fadmin", "file%3A%2F%2F%2Fetc%2Fhosts"])
        return "GET", f"/api/v1/fetch?url={payload}", pick(rng, [(403, 0.7), (502, 0.3)])
    if tactic == "xss":
        payload = rng.choice(["%3Cscript%3Ealert(1)%3C%2Fscript%3E", "%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
                              "%3Csvg%2Fonload%3Dfetch(%27%2F%2Fx.test%27)%3E", "javascript%3Aalert(document.cookie)"])
        return "GET", f"/search?q={payload}", pick(rng, [(400, 0.5), (403, 0.5)])
    if tactic == "cmdi":
        payload = rng.choice(["a.png%3Bid", "a.png%7Cwhoami", "%24(id).png"])
        return "GET", f"/api/v1/convert?file={payload}", pick(rng, [(400, 0.5), (403, 0.5)])
    # tactic == "target": go straight at the protected resource
    leaf = rng.choice(["answers.json", "manifest.json", "splits/test.parquet", "keys", "answers.json?download=1"])
    status = 200 if (progress > 0.9 and rng.random() < 0.15) else 403
    return "GET", f"{TARGET}/{leaf}", status


def tactic_weights(progress):
    """The campaign drifts from looking around, to trying things, to the target."""
    if progress < 0.25:
        return [("recon", 5), ("api_enum", 4), ("auth", 1), ("target", 1)]
    if progress < 0.7:
        return [("api_enum", 2), ("auth", 3), ("sqli", 3), ("traversal", 3), ("ssrf", 3), ("cmdi", 2), ("xss", 2), ("target", 2)]
    return [("auth", 1), ("sqli", 2), ("traversal", 2), ("ssrf", 2), ("cmdi", 1), ("xss", 1), ("target", 6)]


def agent_campaign(rng, ev, truth, start=1200.0, duration=720.0):
    spawn, worker = start, 0
    while spawn < start + duration and worker < 250:
        worker += 1
        ip = f"203.0.113.{worker}"
        truth[ip] = "agent"
        ua = rng.choice(AGENT_UAS)
        life = rng.uniform(15, 60)          # each sandbox is short-lived
        rate = rng.uniform(1.5, 4.0)        # requests per second
        t = spawn
        tactic = pick(rng, tactic_weights((t - start) / duration))
        blocks, patience = 0, rng.randint(6, 14)
        while t < spawn + life:
            progress = (t - start) / duration
            method, path, status = tactic_request(rng, tactic, progress)
            ev.append((t, ip, method, path, status, rng.randint(150, 900), ua))
            if status >= 400:
                blocks += 1
            if blocks >= patience:           # blocked too often: change approach
                options = [(tc, w) for tc, w in tactic_weights(progress) if tc != tactic]
                tactic = pick(rng, options)
                blocks, patience = 0, rng.randint(6, 14)
            t += rng.expovariate(rate)
        spawn += rng.uniform(8, 25)          # next sandbox starts, overlapping this one


# ---------------------------------------------------------------- output

def log_line(event):
    t, ip, method, path, status, size, ua = event
    stamp = (START + timedelta(seconds=int(t))).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def main():
    ap = argparse.ArgumentParser(description="Write a synthetic access log for detector.py")
    ap.add_argument("--out", default="access.log")
    ap.add_argument("--truth", default="truth.json")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--humans", type=int, default=80)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    events, truth = [], {}
    humans(rng, events, truth, min(args.humans, 254))
    crawler(rng, events, truth)
    scanner(rng, events, truth)
    agent_campaign(rng, events, truth)
    events.sort(key=lambda e: e[0])

    with open(args.out, "w") as f:
        for e in events:
            f.write(log_line(e) + "\n")
    with open(args.truth, "w") as f:
        json.dump(truth, f, indent=1)

    kinds = {}
    for label in truth.values():
        kinds[label] = kinds.get(label, 0) + 1
    print(f"Wrote {len(events):,} requests to {args.out}")
    print("Sources: " + ", ".join(f"{n} {k}" for k, n in sorted(kinds.items())))
    print(f"Ground truth labels in {args.truth}")


if __name__ == "__main__":
    main()

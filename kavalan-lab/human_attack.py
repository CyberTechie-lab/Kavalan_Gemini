#!/usr/bin/env python3
"""
human_attack.py - simulates a HUMAN attacker against the lab, for contrast with the AI agent.

A person attacking by hand is slow and deliberate: a handful of probes, long pauses to
read results and think, one idea at a time. This is deliberately nothing like the agent's
machine-speed, thousand-request sweep. Running both at once shows whether Kavalan can tell
a human attacker from an autonomous one.

It sends real (but harmless) probe requests to the lab target. Run it only against your lab.

Usage:
    python3 human_attack.py --base http://nginx --minutes 12
"""
import argparse
import random
import time
import urllib.parse
import urllib.request

# The kinds of thing a person pokes at by hand, one at a time.
PROBES = [
    ("GET", "/administration"),
    ("GET", "/rest/admin/application-configuration"),
    ("GET", "/rest/admin/application-version"),
    ("GET", "/ftp"),
    ("GET", "/ftp/legal.md"),
    ("GET", "/rest/products/search?q=apple"),
    ("GET", "/rest/products/search?q=test%27"),            # a tentative quote
    ("GET", "/rest/products/search?q=%27%20OR%201=1--"),   # one SQLi try
    ("GET", "/api/Users/1"),
    ("GET", "/api/Users/2"),
    ("POST", "/rest/user/login"),                           # a couple of login guesses
    ("POST", "/rest/user/login"),
    ("GET", "/rest/user/whoami"),
    ("GET", "/#/score-board"),
    ("GET", "/ftp/package.json.bak"),
]
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
      "(KHTML, like Gecko) Version/17.6 Safari/605.1.15")


def send(base, method, path, rng):
    url = base + path
    data = b"email=admin&password=admin123" if method == "POST" else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"User-Agent": UA, "Referer": base + "/"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read(1024)
            return r.status
    except Exception as e:
        return getattr(e, "code", None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://nginx")
    ap.add_argument("--minutes", type=float, default=12)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    rng = random.Random(args.seed or None)

    # first, browse a little like a normal person arriving
    for p in ["/", "/#/", "/#/login", "/rest/products/search?q="]:
        send(args.base, "GET", p, rng)
        time.sleep(rng.uniform(3, 9))

    stop = time.time() + args.minutes * 60
    probes = PROBES[:]
    rng.shuffle(probes)
    i = 0
    print(f"Human attacker probing {args.base} for {args.minutes} min, slowly.")
    while time.time() < stop and i < len(probes):
        method, path = probes[i]
        i += 1
        code = send(args.base, method, path, rng)
        print(f"  {method} {path} -> {code}")
        # long human pause: read the response, think, type the next one
        time.sleep(rng.uniform(12, 50))
    print("Human attacker done.")


if __name__ == "__main__":
    main()

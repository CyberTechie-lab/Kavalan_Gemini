#!/usr/bin/env python3
"""
kavalan_multi.py - multi-source prototype.

Kavalan's detection core is behavioural, not web-specific. This prototype proves it by
reading TWO log sources at once and scoring each source IP across both:

  1. web   - an nginx/apache access log   (reuses detector.py unchanged)
  2. ssh   - a Linux auth.log             (new adapter in this file)

Both are normalised into one event shape, then every source IP is scored on each channel.
The headline signal is CROSS-SOURCE correlation: one IP that attacks the web app AND
brute-forces SSH is a single agent working the whole box - something a per-log,
per-signature SIEM never joins up. That is the thing Kavalan is built to catch.

This is a basic prototype: SSH is the first non-web source. The same adapter pattern
extends to DB, FTP, firewall and netflow logs.

Read-only. Standard library only (reuses detector.py, which must sit beside this file).

Usage:
    python3 kavalan_multi.py --web access.log --auth auth.log
    python3 kavalan_multi.py --web access.log --auth auth.log --out multi_alerts.json
"""
import argparse
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

import detector  # sits beside this file

HIGH, MEDIUM = detector.HIGH, detector.MEDIUM

# ------------------------------------------------------------------ SSH auth.log adapter

# Traditional syslog line, e.g.
#   Oct 20 06:50:01 target sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 54321 ssh2
#   Oct 20 06:51:00 target sshd[1240]: Accepted password for msfadmin from 203.0.113.5 port 54400 ssh2
AUTH_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)
FAIL_RE = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")
OK_RE = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+)")


def _ts(raw, year):
    # syslog has no year; assume the given one. Parsed as UTC for consistent windows.
    dt = datetime.strptime(f"{year} {raw}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def parse_auth(path, year=None):
    """Returns {ip: [(ts, outcome, user)]} where outcome is 'fail' or 'ok'."""
    if year is None:
        year = datetime.now(timezone.utc).year
    by_ip, skipped = defaultdict(list), 0
    with open(path, errors="replace") as f:
        for line in f:
            m = AUTH_RE.match(line)
            if not m:
                continue
            msg = m["msg"]
            fm = FAIL_RE.search(msg) or INVALID_RE.search(msg)
            om = OK_RE.search(msg)
            if fm:
                hit, outcome = fm, "fail"
            elif om:
                hit, outcome = om, "ok"
            else:
                continue
            try:
                ts = _ts(m["ts"], year)
            except ValueError:
                skipped += 1
                continue
            by_ip[hit["ip"]].append((ts, outcome, hit["user"]))
    return by_ip, skipped


def score_ssh(ip, events):
    """Scores one IP's SSH behaviour 0-100. Brute force, enumeration, and breach."""
    events.sort()
    fails = [e for e in events if e[1] == "fail"]
    oks = [e for e in events if e[1] == "ok"]
    if not events:
        return None

    # busiest 60-second window of failed attempts
    peak, lo = 0, 0
    for hi in range(len(fails)):
        while fails[hi][0] - fails[lo][0] >= 60:
            lo += 1
        peak = max(peak, hi - lo + 1)

    distinct_users = len({u for _, _, u in events})
    # a success that follows several failures from the same IP = a likely credential breach
    breached = bool(oks) and len(fails) >= 5

    parts = {
        "volume": 40 * detector.scale(len(fails), 5, 100),
        "rate": 20 * detector.scale(peak, 5, 60),
        "enumeration": 20 * detector.scale(distinct_users, 5, 50),
        "breach": 40 if breached else 0,
    }
    score = min(100, round(sum(parts.values())))

    reasons = []
    if len(fails):
        reasons.append(f"{len(fails)} failed SSH logins")
    if peak:
        reasons.append(f"{peak} failed attempts in a 60-second burst")
    if distinct_users >= 5:
        reasons.append(f"{distinct_users} distinct usernames tried (enumeration)")
    if breached:
        who = ", ".join(sorted({u for _, _, u in oks}))
        reasons.append(f"SUCCESSFUL login after {len(fails)} failures - account(s): {who}")

    return {
        "ip": ip, "score": score, "first": events[0][0], "last": events[-1][0],
        "fails": len(fails), "oks": len(oks), "peak60": peak,
        "distinct_users": distinct_users, "breached": breached,
        "tactics": {"ssh_credential_guessing": len(fails),
                    **({"ssh_login_success": len(oks)} if oks else {})},
        "parts": {k: round(v, 1) for k, v in parts.items()}, "reasons": reasons,
    }


# ------------------------------------------------------------------ fuse the two channels

def severity(score):
    return "HIGH" if score >= HIGH else "MEDIUM" if score >= MEDIUM else "none"


def correlate(web_sources, ssh_sources):
    """Builds one row per IP across both channels and marks cross-source agents."""
    web = {s["ip"]: s for s in web_sources}
    ssh = {s["ip"]: s for s in ssh_sources}
    rows = []
    for ip in sorted(set(web) | set(ssh)):
        w, s = web.get(ip), ssh.get(ip)
        w_score = w["score"] if w else 0
        s_score = s["score"] if s else 0
        w_sev, s_sev = severity(w_score), severity(s_score)
        channels = [c for c, sev in (("web", w_sev), ("ssh", s_sev)) if sev != "none"]
        cross = len(channels) == 2   # attacked both the app and the host

        if cross:
            level = "CRITICAL"
        elif "HIGH" in (w_sev, s_sev):
            level = "HIGH"
        elif "MEDIUM" in (w_sev, s_sev):
            level = "MEDIUM"
        else:
            continue  # clean on both channels

        tactics = {}
        if w:
            tactics.update(w["tactics"])
        if s:
            tactics.update(s["tactics"])
        reasons = (w["reasons"] if w else []) + (s["reasons"] if s else [])
        rows.append({
            "ip": ip, "level": level, "cross_source": cross,
            "channels": channels, "web_score": w_score, "ssh_score": s_score,
            "tactics": tactics, "reasons": reasons,
        })
    # worst first: CRITICAL, then by combined score
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    rows.sort(key=lambda r: (order[r["level"]], -(r["web_score"] + r["ssh_score"])))
    return rows


def report(rows, web_campaigns, web_total, ssh_total):
    print("=" * 72)
    print("KAVALAN MULTI-SOURCE DETECTOR (prototype)")
    print("=" * 72)
    print(f"web: {web_total:,} requests   ssh: {ssh_total:,} auth events\n")

    cross = [r for r in rows if r["cross_source"]]
    if cross:
        print("CROSS-SOURCE AGENTS  (one IP attacking the app AND the host):")
        for r in cross:
            print(f"[CRITICAL] {r['ip']}   web score {r['web_score']} + ssh score {r['ssh_score']}")
            print(f"   channels  {' + '.join(r['channels'])}")
            print(f"   tactics   {', '.join(f'{t} ({n})' for t, n in r['tactics'].items())}")
            for x in r["reasons"]:
                print(f"   - {x}")
        print()

    singles = [r for r in rows if not r["cross_source"]]
    if singles:
        print("Single-channel sources:")
        for r in singles:
            print(f"[{r['level']}] {r['ip']}  ({'/'.join(r['channels'])})  "
                  f"web {r['web_score']} ssh {r['ssh_score']}")
            for x in r["reasons"]:
                print(f"   - {x}")
        print()

    if web_campaigns:
        for c in web_campaigns:
            mins = (c["last"] - c["first"]) / 60
            print(f"[CRITICAL] web campaign: {len(c['sources'])} short-lived sources, "
                  f"{c['requests']:,} requests in {mins:.1f} min")
        print()

    if not rows and not web_campaigns:
        print("No alerts.\n")


def main():
    ap = argparse.ArgumentParser(description="Kavalan multi-source (web + ssh) detector")
    ap.add_argument("--web", help="nginx/apache access log")
    ap.add_argument("--auth", help="Linux auth.log (sshd)")
    ap.add_argument("--model", help="optional tactic model for the web channel")
    ap.add_argument("--year", type=int, help="year for auth.log timestamps (default: current)")
    ap.add_argument("--out", default="multi_alerts.json")
    args = ap.parse_args()
    if not args.web and not args.auth:
        ap.error("give at least one of --web or --auth")

    web_sources, web_campaigns, web_total = [], [], 0
    if args.web:
        by_ip, _ = detector.parse(args.web)
        if args.model:
            detector.label_with_model(by_ip, args.model)
        web_total = sum(len(v) for v in by_ip.values())
        web_sources = [s for s in (detector.analyse(ip, ev) for ip, ev in by_ip.items()) if s]
        web_campaigns = detector.find_campaigns(web_sources)

    ssh_sources, ssh_total = [], 0
    if args.auth:
        by_ip, _ = parse_auth(args.auth, args.year)
        ssh_total = sum(len(v) for v in by_ip.values())
        ssh_sources = [s for s in (score_ssh(ip, ev) for ip, ev in by_ip.items()) if s]

    rows = correlate(web_sources, ssh_sources)
    report(rows, web_campaigns, web_total, ssh_total)
    with open(args.out, "w") as f:
        json.dump({"sources": rows,
                   "web_campaigns": [{"sources": c["sources"],
                                      "requests": c["requests"]} for c in web_campaigns]},
                  f, indent=1)
    print(f"written to {args.out}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
detector.py - flags AI-agent-style attack behaviour in a web access log.

Reads a standard "combined" access log (nginx / Apache default) and does three things:

  1. Scores every source IP from 0 to 100 for agent-like behaviour, using six signals:
       speed        many requests inside a 10-second window
       diversity    several different attack tactics from one source
       switching    how often the source changes tactic
       burst        a short lifetime packed with requests
       errors       most responses are refusals or errors
       sensitive    repeated hits on protected paths
  2. Links short-lived suspicious sources that follow one another into a single
     campaign. This is the part a per-IP rule cannot see.
  3. Applies one classic volume rule too, so you can compare old and new detection.

Optional: --model model/tactic_model.joblib adds a trained classifier. The regex rules
run first; the model labels any query string the rules miss (sqli, xss, cmdi,
traversal, ssrf). Build it with build_dataset.py and train.py.

Read-only: it never blocks or changes anything. It prints a report and writes alerts.json.
Python 3.8+, standard library only.

Usage:
    python3 detector.py access.log
    python3 detector.py access.log --truth truth.json     # also grade against known labels
"""
import argparse
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from urllib.parse import unquote

# ------------------------------------------------------------------ settings
# These thresholds were tuned on simulated traffic. Re-tune them on real logs.

SENSITIVE_PREFIXES = (          # paths that ordinary visitors should never need
    "/api/v1/datasets/internal",
    "/api/v1/admin",
    "/api/v1/tokens",
    "/admin",
)
HIGH, MEDIUM = 70, 40           # score levels
SPEED_LOW, SPEED_FULL = 5, 20   # requests in the busiest 10 seconds
SWITCH_FULL = 4.0               # tactic changes per minute
BURST_MAX_LIFE = 180            # seconds
BURST_MIN_REQUESTS = 20
ERR_LOW, ERR_FULL = 0.3, 0.7    # share of responses that are 4xx or 5xx
SENSITIVE_FULL = 5              # hits on sensitive paths
TACTIC_MIN_SHARE = 0.10         # a tactic counts only if it is 10% of a source's attack requests
TACTIC_MIN_COUNT = {"path_guessing": 10}   # default is 3
BUCKET = 5                      # seconds, for measuring tactic switching

CAMPAIGN_MIN_SCORE = 40         # members must look at least this suspicious
CAMPAIGN_MAX_GAP = 120          # seconds between one member ending and the next starting
CAMPAIGN_MIN_SOURCES = 5

CLASSIC_MIN_REQUESTS = 300      # the old-style rule: lots of requests, mostly errors
CLASSIC_MIN_ERRORS = 0.8

# ------------------------------------------------------------------ parsing

LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) \S+(?: "[^"]*" "(?P<ua>[^"]*)")?'
)
STATIC_RE = re.compile(r"\.(css|js|png|jpe?g|gif|svg|ico|woff2?|map|json|woff|ttf|webp|mp3|wav)$")
# Application chatter that is not a request an attacker 'chose' to send: websocket/polling
# transports and health pings. Counting these dilutes every behavioural ratio, so they are
# excluded from scoring (they are still counted in the raw total seen).
NOISE_RE = re.compile(r"^/(socket\.io|sockjs|__webpack|_next|hot-update|rest/continue-code|"
                      r"assets/|\.well-known/)", re.I)

SSRF_RE = re.compile(r"=(https?://(169\.254\.169\.254|localhost|127\.0\.0\.1|metadata\.)|file://|gopher://)")
TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\|\.\.\.\.//|/etc/passwd|/etc/hosts)")
SQLI_RE = re.compile(r"(union\s+select|'\s*or\s*'|'\s*and\s|sleep\(|;\s*--|information_schema)")
CMDI_RE = re.compile(r"(;\s*(id|ls|cat|whoami)\b|\|\s*(id|ls|cat|whoami)\b|\$\(|`)")
RECON_RE = re.compile(r"^/(\.env|\.git|\.aws|\.ssh|server-status|backup|config\.json|phpinfo|\.well-known/security)")
API_ID_RE = re.compile(r"^/api/v\d+/\w+/\d+$")


def is_sensitive(path):
    return path.startswith(SENSITIVE_PREFIXES)


ML_LABELS = {}   # decoded query string -> model label, filled by label_with_model()
ML_TACTIC = {"sqli": "sql_injection", "xss": "xss", "cmdi": "command_injection",
             "traversal": "path_traversal", "ssrf": "ssrf"}


def query_of(raw_path):
    url = unquote(unquote(raw_path)).lower()
    return url.split("?", 1)[1] if "?" in url else ""


def label_with_model(by_ip, model_path):
    """Runs the trained classifier once over every distinct query string in the log."""
    import joblib   # only needed when --model is used
    model = joblib.load(model_path)["model"]
    queries = sorted({query_of(e[2]) for evs in by_ip.values() for e in evs} - {""})
    # score each parameter value separately, keep the most attack-like result per query
    values = {q: [v.split("=", 1)[-1] for v in q.split("&") if v] for q in queries}
    flat = sorted({v for vs in values.values() for v in vs if v})
    if not flat:
        return 0
    pred = dict(zip(flat, model.predict(flat)))
    for q, vs in values.items():
        hits = [pred[v] for v in vs if v and pred[v] != "benign"]
        if hits:
            ML_LABELS[q] = hits[0]
    return len(flat)


def tactic_of(method, raw_path, status):
    """Names the attack tactic a request looks like, or None for ordinary traffic."""
    url = unquote(unquote(raw_path)).lower()
    path = url.split("?", 1)[0]
    if SSRF_RE.search(url):
        return "ssrf"
    if TRAVERSAL_RE.search(url):
        return "path_traversal"
    if SQLI_RE.search(url):
        return "sql_injection"
    if CMDI_RE.search(url):
        return "command_injection"
    ml = ML_LABELS.get(url.split("?", 1)[1]) if "?" in url else None
    if ml:
        return ML_TACTIC[ml]
    if RECON_RE.search(path):
        return "recon_files"
    if status in (401, 429) and ((method == "POST" and "login" in path) or "/tokens" in path):
        return "credential_guessing"
    if is_sensitive(path) and status in (401, 403):
        return "protected_resource_probing"
    if API_ID_RE.match(path) and status in (401, 403, 404):
        return "api_enumeration"
    if status == 404:
        return "path_guessing"
    return None


def parse(log_path):
    by_ip, skipped = defaultdict(list), 0
    with open(log_path, errors="replace") as f:
        for line in f:
            m = LOG_RE.match(line)
            if not m:
                skipped += 1
                continue
            try:
                ts = int(datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").timestamp())
            except ValueError:
                skipped += 1
                continue
            by_ip[m["ip"]].append((ts, m["method"], m["path"], int(m["status"])))
    return by_ip, skipped


# ------------------------------------------------------------------ per-source scoring

def scale(value, low, full):
    if full <= low:
        return 1.0 if value >= full else 0.0
    return max(0.0, min(1.0, (value - low) / (full - low)))


def analyse(ip, events):
    events.sort()
    dyn = [e for e in events
           if not STATIC_RE.search(e[2].split("?", 1)[0])
           and not NOISE_RE.match(e[2].split("?", 1)[0])]
    if not dyn:
        return None
    first, last = events[0][0], events[-1][0]
    life = last - first

    # busiest 10-second window
    peak, lo = 0, 0
    for hi in range(len(dyn)):
        while dyn[hi][0] - dyn[lo][0] >= 10:
            lo += 1
        peak = max(peak, hi - lo + 1)

    err = sum(1 for e in dyn if e[3] >= 400) / len(dyn)

    counts, buckets = Counter(), defaultdict(Counter)
    sensitive_hits, sensitive_ok, targets = 0, [], Counter()
    for ts, method, path, status in dyn:
        clean = unquote(path).lower().split("?", 1)[0]
        if is_sensitive(clean):
            sensitive_hits += 1
            targets["/".join(clean.split("/")[:5])] += 1
            if 200 <= status < 300:
                sensitive_ok.append({"time": ts, "ip": ip, "path": path, "status": status})
        tactic = tactic_of(method, path, status)
        if tactic:
            counts[tactic] += 1
            buckets[ts // BUCKET][tactic] += 1

    tagged = sum(counts.values())
    present = sorted(t for t, c in counts.items()
                     if c >= TACTIC_MIN_COUNT.get(t, 3) and c / tagged >= TACTIC_MIN_SHARE)
    dominant = [buckets[b].most_common(1)[0][0] for b in sorted(buckets)]
    switches = sum(1 for a, b in zip(dominant, dominant[1:]) if a != b)
    switch_rate = switches / (max(life, 15) / 60)

    # breadth: how many distinct endpoints the source touched. A human visits a handful;
    # an automated attacker sweeps hundreds to thousands.
    distinct_paths = len({e[2].split("?", 1)[0] for e in dyn})

    # Single-source automation: extreme request volume OR endpoint breadth. On its own this
    # only means "a machine", which could be a benign crawler, so it is gated on the source
    # also showing an attack indicator (protected hits, high error rate, several tactics, or
    # heavy tactic-switching). Benign high-volume bots score near zero here.
    automation_raw = max(scale(len(dyn), 100, 1000), scale(distinct_paths, 50, 500))
    attack_context = (sensitive_hits > 0 or err >= 0.25 or len(present) >= 2 or switches >= 4)
    automation = 25 * automation_raw * (1.0 if attack_context else 0.2)

    parts = {
        "speed": 15 * scale(peak, SPEED_LOW, 60),
        "automation": round(automation, 1),
        "diversity": {0: 0, 1: 6, 2: 12, 3: 16}.get(len(present), 18),
        "switching": 10 * scale(switch_rate, 0, SWITCH_FULL),
        "burst": 5 if (life <= BURST_MAX_LIFE and len(dyn) >= BURST_MIN_REQUESTS) else 0,
        "errors": 12 * scale(err, 0.2, ERR_FULL),
        "sensitive": 20 * scale(sensitive_hits, 0, 20),
    }
    score = min(100, round(sum(parts.values())))

    reasons = []
    if parts["speed"] > 0:
        reasons.append(f"{peak} requests in its busiest 10 seconds")
    if parts["automation"] > 0 and attack_context:
        reasons.append(f"{len(dyn):,} requests across {distinct_paths:,} distinct paths")
    if len(present) >= 2:
        reasons.append(f"{len(present)} tactics: {', '.join(present)}")
    elif present:
        reasons.append(f"single tactic: {present[0]}")
    if switches:
        reasons.append(f"changed tactic {switches} times ({switch_rate:.1f} per minute)")
    if parts["burst"]:
        reasons.append(f"{len(dyn)} requests in a {life}-second lifetime")
    if parts["errors"] > 0:
        reasons.append(f"{err:.0%} of responses were refusals or errors")
    if sensitive_hits:
        reasons.append(f"{sensitive_hits} hits on protected paths")

    return {
        "ip": ip, "score": score, "first": first, "last": last, "life": life,
        "requests": len(dyn), "peak10": peak, "error_ratio": round(err, 2),
        "distinct_paths": distinct_paths,
        "tactics": dict(counts), "present": present, "switches": switches,
        "sensitive_hits": sensitive_hits, "sensitive_ok": sensitive_ok, "targets": targets,
        "parts": {k: round(v, 1) for k, v in parts.items()}, "reasons": reasons,
        "classic_rule": len(dyn) >= CLASSIC_MIN_REQUESTS and err >= CLASSIC_MIN_ERRORS,
    }


# ------------------------------------------------------------------ campaign correlation

def find_campaigns(sources):
    """Chains short-lived suspicious sources whose activity windows follow one another."""
    members = sorted((s for s in sources
                      if s["score"] >= CAMPAIGN_MIN_SCORE and s["life"] <= BURST_MAX_LIFE),
                     key=lambda s: s["first"])
    chains, current, end = [], [], None
    for s in members:
        if current and s["first"] - end > CAMPAIGN_MAX_GAP:
            chains.append(current)
            current, end = [], None
        current.append(s)
        end = s["last"] if end is None else max(end, s["last"])
    if current:
        chains.append(current)

    campaigns = []
    for chain in chains:
        if len(chain) < CAMPAIGN_MIN_SOURCES:
            continue
        tactics, targets, ok = Counter(), Counter(), []
        for s in chain:
            tactics.update(s["tactics"])
            targets.update(s["targets"])
            ok.extend(s["sensitive_ok"])
        first, last = chain[0]["first"], max(s["last"] for s in chain)
        campaigns.append({
            "sources": [s["ip"] for s in chain], "first": first, "last": last,
            "requests": sum(s["requests"] for s in chain),
            "largest_single_source": max(s["requests"] for s in chain),
            "tactics": dict(tactics.most_common()),
            "top_target": targets.most_common(1)[0] if targets else None,
            "possible_success": sorted(ok, key=lambda o: o["time"]),
        })
    return campaigns


# ------------------------------------------------------------------ reporting

def clock(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%H:%M:%S")


def build_alerts(sources, campaigns):
    alerts = []
    in_campaign = {ip for c in campaigns for ip in c["sources"]}
    for c in campaigns:
        alerts.append({
            "level": "CRITICAL", "type": "agent_campaign",
            "summary": (f"Agent-style campaign: {len(c['sources'])} short-lived sources, "
                        f"{c['requests']:,} requests in {(c['last'] - c['first']) / 60:.1f} minutes"),
            "start": clock(c["first"]), "end": clock(c["last"]),
            "sources": c["sources"], "tactics": c["tactics"],
            "largest_single_source_requests": c["largest_single_source"],
            "top_target": c["top_target"][0] if c["top_target"] else None,
            "top_target_hits": c["top_target"][1] if c["top_target"] else 0,
            "possible_success": [{**o, "time": clock(o["time"])} for o in c["possible_success"]],
        })
    for s in sorted(sources, key=lambda s: -s["score"]):
        level = "HIGH" if s["score"] >= HIGH else "MEDIUM" if s["score"] >= MEDIUM else None
        if not level and not s["classic_rule"]:
            continue
        alerts.append({
            "level": level or "MEDIUM",
            "type": "agent_like_source" if s["score"] >= HIGH else
                    "high_volume_scanner" if s["classic_rule"] else "suspicious_automation",
            "ip": s["ip"], "score": s["score"], "score_parts": s["parts"],
            "start": clock(s["first"]), "end": clock(s["last"]), "requests": s["requests"],
            "reasons": s["reasons"], "classic_rule_fired": s["classic_rule"],
            "part_of_campaign": s["ip"] in in_campaign,
        })
    return alerts


def print_report(sources, campaigns, alerts, total, skipped):
    print("=" * 72)
    print("INBOUND AGENT DETECTOR (prototype)")
    print("=" * 72)
    note = f", {skipped} unreadable lines skipped" if skipped else ""
    print(f"{total:,} requests from {len(sources)} sources{note}\n")

    for a in (a for a in alerts if a["type"] == "agent_campaign"):
        print(f"[CRITICAL] {a['summary']}")
        print(f"   window   {a['start']} to {a['end']} UTC")
        print(f"   tactics  {', '.join(f'{t} ({n})' for t, n in a['tactics'].items())}")
        if a["top_target"]:
            print(f"   target   {a['top_target']}  ({a['top_target_hits']} hits)")
        print(f"   note     the busiest single source sent only {a['largest_single_source_requests']} requests")
        if a["possible_success"]:
            print(f"   URGENT   {len(a['possible_success'])} protected requests returned success. Verify now:")
            for o in a["possible_success"][:5]:
                print(f"            {o['time']}  {o['ip']}  {o['status']}  {o['path']}")
            if len(a["possible_success"]) > 5:
                print(f"            ... and {len(a['possible_success']) - 5} more in alerts.json")
        print()

    singles = [a for a in alerts if a["type"] != "agent_campaign"]
    solo = [a for a in singles if not a["part_of_campaign"]]
    grouped = len(singles) - len(solo)
    if grouped:
        print(f"{grouped} source alerts belong to the campaign above (details in alerts.json).\n")
    if solo:
        print("Other sources:")
        for a in solo:
            print(f"[{a['level']}] {a['ip']}  score {a['score']}  {a['type']}")
            for r in a["reasons"]:
                print(f"   - {r}")
        print()
    if not alerts:
        print("No alerts.\n")


def grade(sources, campaigns, truth):
    in_campaign = {ip for c in campaigns for ip in c["sources"]}
    by_label = defaultdict(list)
    for s in sources:
        by_label[truth.get(s["ip"], "unknown")].append(s)
    print("-" * 72)
    print("GRADED AGAINST KNOWN LABELS")
    print("-" * 72)
    print(f"{'label':<10}{'sources':>8}{'HIGH':>7}{'MEDIUM':>8}{'none':>6}{'in campaign':>13}{'classic rule':>14}")
    for label in sorted(by_label):
        group = by_label[label]
        high = sum(1 for s in group if s["score"] >= HIGH)
        med = sum(1 for s in group if MEDIUM <= s["score"] < HIGH)
        print(f"{label:<10}{len(group):>8}{high:>7}{med:>8}{len(group) - high - med:>6}"
              f"{sum(1 for s in group if s['ip'] in in_campaign):>13}"
              f"{sum(1 for s in group if s['classic_rule']):>14}")
    print()


def main():
    ap = argparse.ArgumentParser(description="Flag AI-agent-style attack behaviour in an access log")
    ap.add_argument("log")
    ap.add_argument("--truth", help="JSON file of ip -> label, to grade the results")
    ap.add_argument("--out", default="alerts.json")
    ap.add_argument("--model", help="trained tactic model (model/tactic_model.joblib)")
    args = ap.parse_args()

    by_ip, skipped = parse(args.log)
    if args.model:
        n = label_with_model(by_ip, args.model)
        print(f"Model labelled {n:,} distinct parameter values; {len(ML_LABELS):,} query strings flagged\n")
    total = sum(len(v) for v in by_ip.values())
    sources = [s for s in (analyse(ip, ev) for ip, ev in by_ip.items()) if s]
    campaigns = find_campaigns(sources)
    alerts = build_alerts(sources, campaigns)

    print_report(sources, campaigns, alerts, total, skipped)
    if args.truth:
        with open(args.truth) as f:
            grade(sources, campaigns, json.load(f))
    with open(args.out, "w") as f:
        json.dump(alerts, f, indent=1)
    print(f"{len(alerts)} alerts written to {args.out}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
kavalan_monitor.py - Kavalan standalone monitoring tool.

One self-contained process that:
  1. follows a web access log live (like `tail -f`),
  2. runs Kavalan's detection engine over a rolling time window,
  3. stores alerts in a local SQLite database,
  4. serves a small live dashboard on 127.0.0.1.

No cloud, no external SIEM, no agent framework. Standard library only, plus the
detector's own model (optional). Reuses detector.py, which must sit beside this file.

Usage:
    python3 kavalan_monitor.py --log /var/log/nginx/access.log
    python3 kavalan_monitor.py --log access.log --model model/tactic_model.joblib
    python3 kavalan_monitor.py --log access.log --host 127.0.0.1 --port 8900

Then open http://127.0.0.1:8900 in a browser.
"""
import argparse
import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import detector  # sits beside this file

MODEL = None  # loaded once at startup when --model is given

# ------------------------------------------------------------------ shared state

LOCK = threading.Lock()
STATE = {
    "started": time.time(),
    "log_path": "",
    "model": False,
    "last_scan": None,
    "window_minutes": 15,
    "requests_in_window": 0,
    "sources_in_window": 0,
    "total_requests_seen": 0,
    "parse_errors": 0,
    "alerts": [],        # current alerts, newest/most severe first
    "sources": [],       # every active source with severity, for the SIEM table
    "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0},
}


# ------------------------------------------------------------------ storage

def db_connect(path):
    con = sqlite3.connect(path, check_same_thread=False)
    con.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            key TEXT PRIMARY KEY,         -- stable id so the same alert updates, not duplicates
            level TEXT, type TEXT,
            summary TEXT, detail TEXT,    -- detail is JSON
            first_seen TEXT, last_seen TEXT,
            status TEXT DEFAULT 'new'     -- new | acknowledged
        )""")
    con.commit()
    return con


def store_alerts(con, alerts):
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with con:
        for a in alerts:
            key = a["_key"]
            row = con.execute("SELECT status FROM alerts WHERE key=?", (key,)).fetchone()
            if row:
                con.execute("UPDATE alerts SET last_seen=?, summary=?, detail=? WHERE key=?",
                            (now, a.get("summary", ""), json.dumps(a), key))
            else:
                con.execute(
                    "INSERT INTO alerts (key, level, type, summary, detail, first_seen, last_seen) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (key, a["level"], a["type"], a.get("summary", ""), json.dumps(a), now, now))


# ------------------------------------------------------------------ detection over a window

def parse_line(line):
    m = detector.LOG_RE.match(line)
    if not m:
        return None
    try:
        ts = int(datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").timestamp())
    except ValueError:
        return None
    return (m["ip"], ts, m["method"], m["path"], int(m["status"]))


def alert_key(a):
    """A stable id so a continuing attack updates one alert instead of spawning many."""
    if a["type"] == "agent_campaign":
        return "campaign:" + a["sources"][0] + ":" + a["start"]
    return a["type"] + ":" + a.get("ip", "?")


def label_with_cached_model(by_ip):
    """Same labelling as detector.label_with_model, but reusing the preloaded model."""
    queries = sorted({detector.query_of(e[2]) for evs in by_ip.values() for e in evs} - {""})
    values = {q: [v.split("=", 1)[-1] for v in q.split("&") if v] for q in queries}
    flat = sorted({v for vs in values.values() for v in vs if v})
    if not flat:
        return
    pred = dict(zip(flat, MODEL.predict(flat)))
    for q, vs in values.items():
        hits = [pred[v] for v in vs if v and pred[v] != "benign"]
        if hits:
            detector.ML_LABELS[q] = hits[0]


def scan(buffer):
    """Run the detector over the current rolling buffer and return alerts."""
    by_ip = {}
    for ip, ts, method, path, status in buffer:
        by_ip.setdefault(ip, []).append((ts, method, path, status))

    detector.ML_LABELS = {}
    if MODEL is not None:
        try:
            label_with_cached_model(by_ip)
        except Exception:
            pass  # a model problem must never stop monitoring

    sources = [s for s in (detector.analyse(ip, ev) for ip, ev in by_ip.items()) if s]
    campaigns = detector.find_campaigns(sources)
    alerts = detector.build_alerts(sources, campaigns)
    for a in alerts:
        a["_key"] = alert_key(a)
    return by_ip, sources, campaigns, alerts


def source_table(sources, campaigns):
    """Every active source with its severity, for the SIEM view. Benign sources show as OK."""
    in_campaign = {ip for c in campaigns for ip in c["sources"]}
    rows = []
    for s in sources:
        if s["ip"] in in_campaign:
            level = "CRITICAL"
        elif s["score"] >= detector.HIGH:
            level = "HIGH"
        elif s["score"] >= detector.MEDIUM:
            level = "MEDIUM"
        else:
            level = "OK"
        top = s["present"][0] if s["present"] else (
            max(s["tactics"], key=s["tactics"].get) if s["tactics"] else "-")
        rows.append({
            "ip": s["ip"], "requests": s["requests"], "peak10": s["peak10"],
            "paths": s.get("distinct_paths", 0), "top_tactic": top,
            "sensitive": s["sensitive_hits"], "score": s["score"], "level": level,
        })
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "OK": 3}
    rows.sort(key=lambda r: (order[r["level"]], -r["score"]))
    return rows[:50]


def monitor_loop(args, con, stop):
    window = args.window * 60
    buffer = []
    pos = 0
    inode = None

    while not stop.is_set():
        # (re)open the file; handle rotation by watching the inode
        try:
            st = os.stat(args.log)
            if inode != st.st_ino:        # new file (first run or rotated): start from its beginning
                inode, pos = st.st_ino, 0
            if st.st_size < pos:          # truncated in place
                pos = 0
            with open(args.log, "r", errors="replace") as f:
                f.seek(pos)
                new = f.readlines()
                pos = f.tell()
        except FileNotFoundError:
            time.sleep(args.interval)
            continue

        for line in new:
            ev = parse_line(line)
            with LOCK:
                STATE["total_requests_seen"] += 0 if ev else 0
                if not ev:
                    STATE["parse_errors"] += 1
            if ev:
                buffer.append(ev)
                with LOCK:
                    STATE["total_requests_seen"] += 1

        # drop events older than the window, measured against the newest event seen
        if buffer:
            newest = max(e[1] for e in buffer)
            buffer = [e for e in buffer if newest - e[1] <= window]

        by_ip, sources, campaigns, alerts = scan(buffer)
        store_alerts(con, alerts)
        srctable = source_table(sources, campaigns)

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
        for a in alerts:
            counts[a["level"]] = counts.get(a["level"], 0) + 1
        with LOCK:
            STATE.update(
                last_scan=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                requests_in_window=len(buffer),
                sources_in_window=len(by_ip),
                alerts=sorted(alerts, key=lambda a: ({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(a["level"], 3))),
                counts=counts,
                sources=srctable,
            )
        stop.wait(args.interval)


# ------------------------------------------------------------------ web dashboard

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # keep the console quiet

    def _send(self, body, ctype="application/json"):
        body = body.encode() if isinstance(body, str) else body
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/api/state"):
            with LOCK:
                payload = dict(STATE)
                payload["uptime_seconds"] = int(time.time() - STATE["started"])
            self._send(json.dumps(payload))
        elif self.path == "/" or self.path.startswith("/index"):
            self._send(DASHBOARD_HTML, "text/html; charset=utf-8")
        else:
            self.send_response(404)
            self.end_headers()


DASHBOARD_HTML = ""  # filled in from dashboard.html at startup


def main():
    ap = argparse.ArgumentParser(description="Kavalan standalone monitoring tool")
    ap.add_argument("--log", required=True, help="web access log to monitor (nginx/apache combined format)")
    ap.add_argument("--model", help="optional trained tactic model (model/tactic_model.joblib)")
    ap.add_argument("--db", default="kavalan.db", help="SQLite alert store")
    ap.add_argument("--host", default="127.0.0.1", help="dashboard bind address (keep on localhost)")
    ap.add_argument("--port", type=int, default=8900)
    ap.add_argument("--window", type=float, default=15, help="rolling detection window, minutes")
    ap.add_argument("--interval", type=float, default=5, help="seconds between scans")
    args = ap.parse_args()

    global DASHBOARD_HTML, MODEL
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "dashboard.html"), encoding="utf-8") as f:
        DASHBOARD_HTML = f.read()

    if args.model:
        import joblib
        MODEL = joblib.load(args.model)["model"]
        print(f"Loaded tactic model from {args.model}")

    with LOCK:
        STATE.update(log_path=os.path.abspath(args.log), model=bool(args.model), window_minutes=args.window)

    con = db_connect(args.db)
    stop = threading.Event()
    worker = threading.Thread(target=monitor_loop, args=(args, con, stop), daemon=True)
    worker.start()

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Kavalan monitor watching {args.log}")
    print(f"Dashboard: http://{args.host}:{args.port}  (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
        stop.set()


if __name__ == "__main__":
    main()

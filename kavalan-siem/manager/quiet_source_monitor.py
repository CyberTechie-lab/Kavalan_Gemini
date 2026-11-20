"""
quiet_source_monitor.py - Dead-Man Switch & Ingestion Telemetry Monitor for Kavalan SIEM

Monitors fleet telemetry in real time:
  1. Dead-Man Switch Alerting: "Host X stopped sending logs N minutes ago" (Rule 100800)
     Detects adversaries disabling syslog/sshd or terminating endpoint monitoring agents.
  2. Events Per Second (EPS): Tracks real-time velocity per source and fleet-wide aggregate.
  3. Ingestion Lag (ms): Measures latency between event origination timestamp and arrival at SIEM.
"""

import collections
import time
import threading
from typing import Any, Callable, Dict, List, Optional


class QuietSourceMonitor:
    """Tracks per-source ingestion rate, latency, and detects silenced logging pipelines."""

    def __init__(
        self,
        alert_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        quiet_threshold_sec: int = 300,  # 5 minutes default
        check_interval_sec: int = 15
    ):
        self.alert_callback = alert_callback
        self.quiet_threshold_sec = quiet_threshold_sec
        self.check_interval_sec = check_interval_sec
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        
        # Ingestion trackers: agent_id -> state
        # state: {"last_seen": int, "name": str, "ip": str, "history": deque, "lag_ms": float, "quiet_alerted": bool}
        self.sources: Dict[str, Dict[str, Any]] = {}
        self.worker_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self.worker_thread is None or not self.worker_thread.is_alive():
            self.stop_event.clear()
            self.worker_thread = threading.Thread(target=self._run_monitor_loop, daemon=True, name="QuietSourceMonitor")
            self.worker_thread.start()

    def stop(self) -> None:
        self.stop_event.set()

    def record_heartbeat(self, agent_id: str, name: str, ip: str) -> None:
        """Records agent presence from keepalive heartbeats."""
        now = int(time.time())
        with self.lock:
            if agent_id not in self.sources:
                self.sources[agent_id] = {
                    "agent_id": agent_id,
                    "name": name,
                    "ip": ip,
                    "last_seen": now,
                    "events_total": 0,
                    "history": collections.deque(maxlen=1000),
                    "lag_history": collections.deque(maxlen=50),
                    "quiet_alerted": False
                }
            else:
                self.sources[agent_id]["last_seen"] = now
                self.sources[agent_id]["name"] = name
                self.sources[agent_id]["ip"] = ip
                if self.sources[agent_id]["quiet_alerted"]:
                    self.sources[agent_id]["quiet_alerted"] = False

    def record_event_batch(self, agent_id: str, events: List[Dict[str, Any]]) -> None:
        """Updates EPS and lag calculations from ingested events."""
        now = time.time()
        now_int = int(now)
        count = len(events)
        with self.lock:
            if agent_id not in self.sources:
                self.sources[agent_id] = {
                    "agent_id": agent_id,
                    "name": agent_id,
                    "ip": "127.0.0.1",
                    "last_seen": now_int,
                    "events_total": 0,
                    "history": collections.deque(maxlen=1000),
                    "lag_history": collections.deque(maxlen=50),
                    "quiet_alerted": False
                }

            src = self.sources[agent_id]
            src["last_seen"] = now_int
            src["events_total"] += count
            if src["quiet_alerted"]:
                src["quiet_alerted"] = False

            # Record timestamps for EPS
            for _ in range(count):
                src["history"].append(now)

            # Compute ingestion lag
            for ev in events[-10:]:
                ev_ts = ev.get("ts")
                if isinstance(ev_ts, (int, float)) and ev_ts > 0:
                    lag = max(0.0, (now - ev_ts) * 1000.0)
                    src["lag_history"].append(lag)

    def _run_monitor_loop(self) -> None:
        while not self.stop_event.is_set():
            time.sleep(self.check_interval_sec)
            now = int(time.time())
            with self.lock:
                for agent_id, info in list(self.sources.items()):
                    elapsed = now - info["last_seen"]
                    if elapsed >= self.quiet_threshold_sec and not info["quiet_alerted"]:
                        info["quiet_alerted"] = True
                        elapsed_mins = max(1, elapsed // 60)
                        alert = {
                            "rule_id": 100800,
                            "level": 10,
                            "name": "Log Source Went Quiet",
                            "description": f"Log source '{info['name']}' ({info['ip']}) stopped transmitting telemetry {elapsed_mins} minutes ago (possible log tampering or host disconnect).",
                            "source_ip": info["ip"],
                            "agent_id": agent_id,
                            "host": info["name"],
                            "mitre_id": "T1562.002",
                            "mitre_tactic": "Defense Evasion",
                            "mitre_name": "Disable Windows Event Logging / Syslog",
                            "timestamp": now,
                            "channels": ["quiet_monitor"],
                            "reasons": [f"Host {info['name']} inactive for {elapsed} seconds (threshold: {self.quiet_threshold_sec}s)"]
                        }
                        if self.alert_callback:
                            try:
                                self.alert_callback(alert)
                            except Exception:
                                pass

    def get_telemetry(self) -> Dict[str, Any]:
        """Calculates current EPS, lag, and quiet status for all registered sources."""
        now = time.time()
        window_10s = now - 10.0
        window_60s = now - 60.0

        with self.lock:
            sources_telemetry = []
            total_10s_events = 0
            all_lags = []

            for agent_id, info in self.sources.items():
                h = info["history"]
                c_10s = sum(1 for t in h if t >= window_10s)
                c_60s = sum(1 for t in h if t >= window_60s)
                eps_10s = round(c_10s / 10.0, 2)
                eps_60s = round(c_60s / 60.0, 2)
                total_10s_events += c_10s

                lags = info["lag_history"]
                avg_lag = round(sum(lags) / len(lags), 2) if lags else 0.0
                if lags:
                    all_lags.extend(lags)

                elapsed = int(now) - info["last_seen"]
                is_quiet = elapsed >= self.quiet_threshold_sec

                sources_telemetry.append({
                    "agent_id": agent_id,
                    "name": info["name"],
                    "ip": info["ip"],
                    "last_seen": info["last_seen"],
                    "seconds_since_last_seen": elapsed,
                    "is_quiet": is_quiet,
                    "eps_10s": eps_10s,
                    "eps_60s": eps_60s,
                    "events_total": info["events_total"],
                    "ingest_lag_ms": avg_lag
                })

            aggregate_eps = round(total_10s_events / 10.0, 2)
            fleet_lag = round(sum(all_lags) / len(all_lags), 2) if all_lags else 0.0

            return {
                "aggregate_eps": aggregate_eps,
                "fleet_ingest_lag_ms": fleet_lag,
                "active_sources_count": len([s for s in sources_telemetry if not s["is_quiet"]]),
                "quiet_sources_count": len([s for s in sources_telemetry if s["is_quiet"]]),
                "sources": sources_telemetry
            }

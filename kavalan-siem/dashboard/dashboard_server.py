#!/usr/bin/env python3
"""
dashboard_server.py - Kavalan SOC Console (Tier 4)

Provides the presentation tier for the 4-tier SIEM architecture:
  - Agents Fleet Management (Active, Disconnected, IPs, OS)
  - MITRE ATT&CK Matrix & Cross-Source Alerts
  - Indexer Search & Discovery Console (Histograms & Aggregations)
  - Real-time SOC Incident Investigation
"""

import argparse
import json
import os
import random
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
import uvicorn

CURRENT_DIR = Path(__file__).resolve().parent
HTML_PATH = CURRENT_DIR / "static" / "index.html"
STATIC_DIR = CURRENT_DIR / "static"


class DashboardBackend:
    def __init__(self, manager_url: str = "http://127.0.0.1:8910", indexer_url: str = "http://127.0.0.1:8920"):
        self.manager_url = manager_url.rstrip("/")
        self.indexer_url = indexer_url.rstrip("/")

    def get_manager_state(self) -> Dict[str, Any]:
        try:
            with urllib.request.urlopen(f"{self.manager_url}/api/state", timeout=2.0) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception:
            return {"counts": {}, "sources": [], "alerts": [], "active_agents": 0, "total_agents": 0, "status": "manager_offline"}

    def get_agents(self) -> Dict[str, Any]:
        try:
            with urllib.request.urlopen(f"{self.manager_url}/api/agents", timeout=2.0) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception:
            return {"agents": []}

    def delete_agent(self, agent_id: str) -> Dict[str, Any]:
        try:
            req = urllib.request.Request(
                f"{self.manager_url}/api/agents/{agent_id}",
                method="DELETE"
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            try:
                return json.loads(e.read().decode("utf-8"))
            except Exception:
                return {"error": str(e)}
        except Exception as e:
            return {"error": str(e)}

    def search_indexer_events(self, query: Dict[str, Any]) -> Dict[str, Any]:
        try:
            req = urllib.request.Request(
                f"{self.indexer_url}/api/search/events",
                data=json.dumps(query).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception:
            return {"total": 0, "hits": []}

    def search_indexer_alerts(self, query: Dict[str, Any]) -> Dict[str, Any]:
        try:
            req = urllib.request.Request(
                f"{self.indexer_url}/api/search/alerts",
                data=json.dumps(query).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception:
            return {"total": 0, "hits": []}

    def aggregate_indexer(self, query: Dict[str, Any]) -> Dict[str, Any]:
        try:
            req = urllib.request.Request(
                f"{self.indexer_url}/api/aggregate",
                data=json.dumps(query).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception:
            return {"date_histogram": []}

    def get_indexer_stats(self) -> Dict[str, Any]:
        try:
            with urllib.request.urlopen(f"{self.indexer_url}/api/stats", timeout=2.0) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception:
            return {"total_events": 0, "total_alerts": 0, "db_size_mb": 0}

    def get_indexer(self, path: str) -> Dict[str, Any]:
        try:
            with urllib.request.urlopen(f"{self.indexer_url}{path}", timeout=5.0) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            return {"error": str(e)}

    def post_indexer(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            req = urllib.request.Request(
                f"{self.indexer_url}{path}",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            return {"error": str(e)}

    def get_manager(self, path: str) -> Dict[str, Any]:
        try:
            with urllib.request.urlopen(f"{self.manager_url}{path}", timeout=5.0) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            return {"error": str(e)}

    def post_manager(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            req = urllib.request.Request(
                f"{self.manager_url}{path}",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            try:
                return json.loads(e.read().decode("utf-8"))
            except Exception:
                return {"error": str(e)}
        except Exception as e:
            return {"error": f"Manager communication error: {e}"}

    def patch_manager(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            req = urllib.request.Request(
                f"{self.manager_url}{path}",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="PATCH"
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            try:
                return json.loads(e.read().decode("utf-8"))
            except Exception:
                return {"error": str(e)}
        except Exception as e:
            return {"error": f"Manager communication error: {e}"}

    def delete_manager(self, path: str) -> Dict[str, Any]:
        try:
            req = urllib.request.Request(
                f"{self.manager_url}{path}",
                method="DELETE"
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            try:
                return json.loads(e.read().decode("utf-8"))
            except Exception:
                return {"error": str(e)}
        except Exception as e:
            return {"error": f"Manager communication error: {e}"}

    def simulate_scenario(self, scenario: str, host: str = "server", agent_id: str = "005", target_ip: str = "172.16.10.134") -> Dict[str, Any]:
        now = int(time.time())
        events = []

        if scenario == "live_vm_web_attack":
            vm_ip = target_ip or "172.16.10.134"
            probes = [
                ("GET", "/rest/products/search?q=1'%20UNION%20SELECT%201,2,3--", "SQL Injection union probe"),
                ("GET", "/ftp?file=../../../../etc/passwd", "Path traversal probe"),
                ("GET", "/redirect?url=http://169.254.169.254/latest/meta-data/", "SSRF Cloud metadata probe"),
                ("GET", "/.env", "Sensitive file discovery probe"),
                ("GET", "/.git/config", "Source repository discovery probe"),
                ("POST", "/api/v1/admin/login", "Admin interface probe"),
                ("GET", "/shell.php?cmd=id", "Web shell command injection probe"),
                ("GET", "/admin", "Protected management endpoint probe")
            ]
            probe_results = []
            for m, path, desc in probes:
                url = f"http://{vm_ip}{path}"
                try:
                    req = urllib.request.Request(
                        url,
                        data=b"{}" if m == "POST" else None,
                        headers={"User-Agent": "Mozilla/5.0 (Kali Linux / Kavalan RedTeam Probe)", "Content-Type": "application/json"},
                        method=m
                    )
                    with urllib.request.urlopen(req, timeout=2.5) as resp:
                        probe_results.append({"url": path, "status": resp.status, "desc": desc})
                except urllib.error.HTTPError as e:
                    probe_results.append({"url": path, "status": e.code, "desc": desc})
                except Exception as e:
                    probe_results.append({"url": path, "status": 0, "error": str(e), "desc": desc})

            return {
                "scenario": scenario,
                "target_vm": vm_ip,
                "probes_dispatched": len(probe_results),
                "probe_results": probe_results,
                "message": f"Dispatched {len(probe_results)} real HTTP exploit probes to {vm_ip}. Agent 005 will tail access logs and forward telemetry."
            }

        elif scenario in ("cross_source", "cross_source_killchain"):
            actor_ip = f"203.0.113.{random.randint(150, 199)}"
            web_attacks = [
                ("GET", "/admin", 401, "denied"),
                ("GET", "/api/v1/admin/tokens", 403, "denied"),
                ("GET", "/page?file=../../../../etc/passwd", 404, "fail"),
                ("POST", "/rest/products/search?q=1' OR '1'='1", 500, "error"),
                ("GET", "/.env", 404, "fail"),
                ("GET", "/.git/config", 404, "fail"),
                ("GET", "/redirect?url=http://169.254.169.254/", 403, "denied"),
                ("POST", "/cmd?x=;id", 403, "denied"),
            ]
            t = now - 50
            for _ in range(60):
                method, path, status_code, outcome = random.choice(web_attacks)
                events.append({
                    "ts": t,
                    "host": host,
                    "source_ip": actor_ip,
                    "log_type": "web",
                    "action": f"{method} {path}",
                    "target": path.split("?", 1)[0],
                    "outcome": outcome,
                    "status": status_code,
                    "user": None,
                    "raw": f'{actor_ip} - - [{datetime.fromtimestamp(t, timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {path} HTTP/1.1" {status_code} 512',
                    "meta": {"method": method, "path": path},
                })
                t += 1

            users = ["root", "admin", "ubuntu", "msfadmin", "deploy"]
            t = now - 45
            for _ in range(25):
                u = random.choice(users)
                events.append({
                    "ts": t,
                    "host": host,
                    "source_ip": actor_ip,
                    "log_type": "auth",
                    "action": "ssh_fail",
                    "target": "sshd",
                    "outcome": "fail",
                    "status": 1,
                    "user": u,
                    "raw": f'{datetime.fromtimestamp(t, timezone.utc).strftime("%b %d %H:%M:%S")} {host} sshd[1234]: Failed password for {u} from {actor_ip} port 54321 ssh2',
                    "meta": {"service": "sshd"},
                })
                t += 1
            # Breach event
            events.append({
                "ts": now - 5,
                "host": host,
                "source_ip": actor_ip,
                "log_type": "auth",
                "action": "ssh_ok",
                "target": "sshd",
                "outcome": "ok",
                "status": 0,
                "user": "msfadmin",
                "raw": f'{datetime.fromtimestamp(now - 5, timezone.utc).strftime("%b %d %H:%M:%S")} {host} sshd[1235]: Accepted password for msfadmin from {actor_ip} port 54400 ssh2',
                "meta": {"service": "sshd"},
            })

        elif scenario == "web_scan":
            actor_ip = f"198.51.100.{random.randint(150, 199)}"
            scan_paths = ["/.env", "/.git/config", "/admin", "/backup.zip", "/config.json", "/phpinfo.php", "/api/v1/admin/users"]
            t = now - 40
            for _ in range(75):
                p = random.choice(scan_paths) + f"/{random.randint(1, 99)}"
                events.append({
                    "ts": t,
                    "host": host,
                    "source_ip": actor_ip,
                    "log_type": "web",
                    "action": f"GET {p}",
                    "target": p,
                    "outcome": "fail",
                    "status": 404,
                    "user": None,
                    "raw": f'{actor_ip} - - [{datetime.fromtimestamp(t, timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {p} HTTP/1.1" 404 512',
                    "meta": {"method": "GET", "path": p},
                })
                t += 1

        elif scenario == "ssh_brute":
            actor_ip = f"198.51.100.{random.randint(200, 250)}"
            users = ["root", "admin", "oracle", "postgres", "test", "git"]
            t = now - 35
            for _ in range(40):
                u = random.choice(users)
                events.append({
                    "ts": t,
                    "host": host,
                    "source_ip": actor_ip,
                    "log_type": "auth",
                    "action": "ssh_fail",
                    "target": "sshd",
                    "outcome": "fail",
                    "status": 1,
                    "user": u,
                    "raw": f'{datetime.fromtimestamp(t, timezone.utc).strftime("%b %d %H:%M:%S")} {host} sshd[1236]: Failed password for invalid user {u} from {actor_ip} port 43210 ssh2',
                    "meta": {"service": "sshd"},
                })
                t += 1

        elif scenario == "fim_ransomware":
            actor_ip = f"203.0.113.{random.randint(210, 240)}"
            fim_files = [
                ("/etc/shadow", "file_modified", ["hash", "size", "permissions"], "d41d8cd98f00b204e9800998ecf8427e"),
                ("/etc/sudoers", "file_modified", ["hash", "content"], "9e107d9d372bb6826bd81d3542a419d6"),
                ("/usr/bin/sudo", "permissions_changed", ["permissions_777"], "e4d909c290d0fb1ca068ffaddf22cbd0"),
                ("/var/www/html/wp-config.php", "file_modified", ["hash", "injected_backdoor"], "c4ca4238a0b923820dcc509a6f75849b"),
                ("/tmp/.crypto_locker.sh", "file_created", ["new_executable"], "8b1a9953c4611296a827abf8c47804d7"),
            ]
            t = now - 20
            for path, act, diffs, new_hash in fim_files:
                events.append({
                    "ts": t,
                    "host": host,
                    "source_ip": actor_ip,
                    "log_type": "fim",
                    "action": act,
                    "target": path,
                    "outcome": "error",
                    "status": 1,
                    "user": "root",
                    "raw": f"FIM: {act}: {path} (diffs={','.join(diffs)})",
                    "meta": {"diffs": diffs, "new_sha256": new_hash, "change_type": act}
                })
                t += 2

        elif scenario == "ssh_distributed_brute":
            actor_ip = f"198.51.100.{random.randint(200, 250)}"
            targets = [
                (f"198.51.100.{random.randint(10, 40)}", "root"),
                (f"198.51.100.{random.randint(50, 80)}", "admin"),
                (f"198.51.100.{random.randint(90, 120)}", "deploy"),
                (f"198.51.100.{random.randint(130, 160)}", "postgres")
            ]
            t = now - 30
            for src, u in targets:
                for _ in range(12):
                    events.append({
                        "ts": t,
                        "host": host,
                        "source_ip": src,
                        "log_type": "auth",
                        "action": "ssh_fail",
                        "target": "sshd",
                        "outcome": "fail",
                        "status": 1,
                        "user": u,
                        "raw": f'{datetime.fromtimestamp(t, timezone.utc).strftime("%b %d %H:%M:%S")} {host} sshd[14520]: Failed password for {u} from {src} port 41230 ssh2',
                        "meta": {"service": "sshd"}
                    })
                    t += 1

        else:  # benign_burst
            actor_ip = f"192.0.2.{random.randint(50, 80)}"
            pages = ["/", "/products", "/about", "/cart", "/rest/products/search?q=shoes"]
            t = now - 20
            for _ in range(15):
                p = random.choice(pages)
                events.append({
                    "ts": t,
                    "host": host,
                    "source_ip": actor_ip,
                    "log_type": "web",
                    "action": f"GET {p}",
                    "target": p,
                    "outcome": "ok",
                    "status": 200,
                    "user": None,
                    "raw": f'{actor_ip} - - [{datetime.fromtimestamp(t, timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {p} HTTP/1.1" 200 1024',
                    "meta": {"method": "GET", "path": p},
                })
                t += 1

        ingest_res = self.post_manager("/api/agent/events", {
            "agent_id": agent_id,
            "events": events
        })
        self.post_manager("/api/scan", {})
        return {
            "scenario": scenario,
            "generated_events": len(events),
            "actor_ip": actor_ip,
            "ingest_result": ingest_res
        }


def create_dashboard_app(backend: DashboardBackend) -> FastAPI:
    app = FastAPI(title="Kavalan SOC Console (Tier 4)")

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.api_route("/favicon.ico", methods=["GET", "HEAD"])
    async def favicon_route(request: Request):
        if request.method == "HEAD":
            return Response(status_code=200, media_type="image/svg+xml")
        svg_fav = STATIC_DIR / "kavalan_logo_mark.svg"
        if svg_fav.exists():
            return Response(content=svg_fav.read_bytes(), media_type="image/svg+xml")
        png_fav = STATIC_DIR / "kavalan_logo.png"
        if png_fav.exists():
            return FileResponse(str(png_fav), media_type="image/png")
        return Response(status_code=204)

    @app.get("/")
    async def index_page():
        if not HTML_PATH.exists():
            return HTMLResponse(content="<h1>Dashboard file not found</h1>", status_code=404)
        resp = HTMLResponse(content=HTML_PATH.read_text(encoding="utf-8"))
        resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    @app.get("/api/state")
    async def state_api():
        mgr_state = backend.get_manager_state()
        idx_stats = backend.get_indexer_stats()
        agents_data = backend.get_agents()
        return JSONResponse(content={
            **mgr_state,
            "indexer": idx_stats,
            "agents": agents_data.get("agents", []),
        })

    @app.get("/api/agents")
    async def agents_api():
        return JSONResponse(content=backend.get_agents())

    @app.delete("/api/agents/{agent_id}")
    async def delete_agent_proxy(agent_id: str):
        res = backend.delete_agent(agent_id)
        return JSONResponse(content=res)

    @app.post("/api/agents/{agent_id}/delete")
    async def delete_agent_proxy_post(agent_id: str):
        res = backend.delete_agent(agent_id)
        return JSONResponse(content=res)

    @app.post("/api/search")
    async def search_api(request: Request):
        query = await request.json()
        return JSONResponse(content=backend.search_indexer_events(query))

    @app.post("/api/simulate")
    async def simulate_api(request: Request):
        body = {}
        try:
            body = await request.json()
        except Exception:
            pass
        scenario = body.get("scenario", "cross_source")
        host = body.get("host", "server")
        agent_id = body.get("agent_id", "005")
        target_ip = body.get("target_ip", "172.16.10.134")
        res = backend.simulate_scenario(scenario, host=host, agent_id=agent_id, target_ip=target_ip)
        return JSONResponse(content=res)

    @app.get("/api/graph/attack-topology")
    async def attack_graph_proxy(window: int = 3600, ip: str = None):
        param_str = f"?window={window}"
        if ip:
            param_str += f"&ip={ip}"
        return JSONResponse(content=backend.get_indexer(f"/api/graph/attack-topology{param_str}"))

    @app.post("/api/search/alerts")
    async def search_alerts_proxy(request: Request):
        query = await request.json()
        return JSONResponse(content=backend.search_indexer_alerts(query))

    @app.get("/api/active_response/actions")
    async def active_response_proxy():
        try:
            with urllib.request.urlopen(f"{backend.manager_url}/api/active_response/actions", timeout=2.0) as resp:
                return JSONResponse(content=json.loads(resp.read().decode("utf-8")))
        except Exception:
            return JSONResponse(content={"actions": []})

    @app.post("/api/logtest")
    async def logtest_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager("/api/logtest", body))

    @app.post("/api/aggregate")
    async def aggregate_api(request: Request):
        query = await request.json()
        return JSONResponse(content=backend.aggregate_indexer(query))

    @app.post("/api/ai/analyze")
    async def ai_analyze_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager("/api/ai/analyze", body))

    @app.post("/api/ai/chat")
    async def ai_chat_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager("/api/ai/chat", body))

    @app.get("/api/gemini/model-info")
    @app.get("/api/sec-llm/model-info")
    async def gemini_model_info_proxy():
        try:
            with urllib.request.urlopen(f"{backend.manager_url}/api/gemini/model-info", timeout=3.0) as resp:
                return JSONResponse(content=json.loads(resp.read().decode("utf-8")))
        except Exception as e:
            return JSONResponse(content={"error": str(e)}, status_code=500)

    @app.get("/api/gemini/config")
    async def gemini_config_get_proxy():
        return JSONResponse(content=backend.get_manager("/api/gemini/config"))

    @app.post("/api/gemini/config")
    async def gemini_config_post_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager("/api/gemini/config", body))

    @app.post("/api/gemini/generate")
    @app.post("/api/sec-llm/generate")
    async def gemini_generate_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager("/api/gemini/generate", body))

    @app.post("/api/gemini/explain")
    @app.post("/api/sec-llm/explain")
    async def gemini_explain_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager("/api/gemini/explain", body))

    @app.get("/api/agents/{agent_id}/config")
    async def get_agent_config_proxy(agent_id: str):
        return JSONResponse(content=backend.get_manager(f"/api/agent/{agent_id}/config"))

    @app.post("/api/agents/{agent_id}/config")
    async def set_agent_config_proxy(agent_id: str, request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager(f"/api/agent/{agent_id}/config", body))

    @app.get("/api/active_response/actions")
    async def active_response_actions_proxy():
        return JSONResponse(content=backend.get_manager("/api/active_response/actions"))

    @app.post("/api/active_response/trigger")
    async def trigger_active_response_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager("/api/active_response/trigger", body))

    @app.post("/api/active_response/unblock")
    async def unblock_active_response_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager("/api/active_response/unblock", body))

    @app.get("/api/sca/summary")
    async def sca_summary_proxy():
        return JSONResponse(content=backend.get_manager("/api/sca/summary"))

    @app.get("/api/sca/agent/{agent_id}")
    async def sca_agent_proxy(agent_id: str):
        return JSONResponse(content=backend.get_manager(f"/api/sca/agent/{agent_id}"))

    @app.get("/api/vuln/all")
    async def vuln_all_proxy():
        return JSONResponse(content=backend.get_manager("/api/vuln/all"))

    @app.get("/api/events/{event_id}/context")
    async def get_event_context_proxy(event_id: int, window: int = 5):
        return JSONResponse(content=backend.get_indexer(f"/api/events/{event_id}/context?window={window}"))

    @app.post("/api/fields/stats")
    async def get_field_stats_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_indexer("/api/fields/stats", body))

    @app.get("/api/entity/ip/{ip}")
    async def get_ip_dossier_proxy(ip: str):
        dossier = backend.get_indexer(f"/api/entity/ip/{ip}")
        # Enrich with live Active Response status from Manager
        try:
            ar_resp = backend.get_manager("/api/active_response/actions")
            actions = ar_resp.get("actions", [])
            active_block = any(a.get("actor_ip") == ip and a.get("status") in ("pending", "executed") for a in actions)
            dossier["is_contained"] = active_block
        except Exception:
            dossier["is_contained"] = False
        return JSONResponse(content=dossier)

    # --- SOAR Incident Cases Proxies ---

    @app.get("/api/cases")
    async def list_cases_proxy(status: str = None, severity: str = None):
        params = []
        if status: params.append(f"status={status}")
        if severity: params.append(f"severity={severity}")
        query_str = "?" + "&".join(params) if params else ""
        return JSONResponse(content=backend.get_manager(f"/api/cases{query_str}"))

    @app.post("/api/cases")
    async def create_case_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager("/api/cases", body))

    @app.get("/api/cases/{case_id}")
    async def get_case_proxy(case_id: str):
        return JSONResponse(content=backend.get_manager(f"/api/cases/{case_id}"))

    @app.patch("/api/cases/{case_id}/status")
    async def update_case_status_proxy(case_id: str, request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.patch_manager(f"/api/cases/{case_id}/status", body))

    @app.post("/api/cases/{case_id}/notes")
    async def add_case_note_proxy(case_id: str, request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager(f"/api/cases/{case_id}/notes", body))

    @app.post("/api/cases/{case_id}/playbook")
    async def run_case_playbook_proxy(case_id: str, request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager(f"/api/cases/{case_id}/playbook", body))

    # --- Outbound Webhook Proxies ---

    @app.get("/api/webhooks")
    async def list_webhooks_proxy():
        return JSONResponse(content=backend.get_manager("/api/webhooks"))

    @app.post("/api/webhooks")
    async def save_webhook_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager("/api/webhooks", body))

    @app.delete("/api/webhooks/{webhook_id}")
    async def delete_webhook_proxy(webhook_id: str):
        return JSONResponse(content=backend.delete_manager(f"/api/webhooks/{webhook_id}"))

    @app.post("/api/webhooks/test")
    async def test_webhook_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager("/api/webhooks/test", body))

    # --- Threat Intelligence Proxies ---

    @app.get("/api/threat-intel/lookup/{ioc}")
    async def threat_intel_lookup_proxy(ioc: str):
        return JSONResponse(content=backend.get_indexer(f"/api/threat-intel/lookup/{ioc}"))

    @app.get("/api/threat-intel/summary")
    async def threat_intel_summary_proxy():
        return JSONResponse(content=backend.get_indexer("/api/threat-intel/summary"))

    @app.post("/api/threat-intel/iocs")
    async def threat_intel_add_ioc_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_indexer("/api/threat-intel/iocs", body))

    # --- Autonomous SOAR Playbook Proxies ---

    @app.get("/api/soar/playbooks")
    async def list_soar_playbooks_proxy():
        return JSONResponse(content=backend.get_manager("/api/soar/playbooks"))

    @app.post("/api/soar/playbooks/{playbook_id}/toggle")
    async def toggle_soar_playbook_proxy(playbook_id: str, request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager(f"/api/soar/playbooks/{playbook_id}/toggle", body))

    @app.post("/api/soar/playbooks/{playbook_id}/run")
    async def run_soar_playbook_proxy(playbook_id: str, request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager(f"/api/soar/playbooks/{playbook_id}/run", body))

    @app.get("/api/soar/playbook-runs")
    async def list_soar_playbook_runs_proxy(limit: int = 20):
        return JSONResponse(content=backend.get_manager(f"/api/soar/playbook-runs?limit={limit}"))

    # Detection Rules & Sigma Studio Proxies
    @app.get("/api/rules")
    async def list_rules_proxy():
        return JSONResponse(content=backend.get_manager("/api/rules"))

    @app.get("/api/rules/templates")
    async def get_rule_templates_proxy():
        return JSONResponse(content=backend.get_manager("/api/rules/templates"))

    @app.post("/api/rules/sigma/convert")
    async def convert_sigma_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager("/api/rules/sigma/convert", body))

    @app.post("/api/rules")
    async def save_rule_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager("/api/rules", body))

    @app.delete("/api/rules/{rule_id}")
    async def delete_rule_proxy(rule_id: int):
        return JSONResponse(content=backend.delete_manager(f"/api/rules/{rule_id}"))

    @app.post("/api/rules/{rule_id}/toggle")
    async def toggle_rule_proxy(rule_id: int, request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager(f"/api/rules/{rule_id}/toggle", body))

    @app.post("/api/rules/test")
    async def test_rule_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager("/api/rules/test", body))

    @app.get("/install.sh")
    async def serve_installer():
        sh_path = CURRENT_DIR.parent / "agent" / "install.sh"
        if not sh_path.exists():
            return PlainTextResponse("#!/bin/bash\necho 'Installer not found'\nexit 1", status_code=404)
        return PlainTextResponse(sh_path.read_text(encoding="utf-8"), media_type="text/x-shellscript")

    @app.get("/agent/agent.py")
    async def serve_agent():
        py_path = CURRENT_DIR.parent / "agent" / "agent.py"
        if not py_path.exists():
            return PlainTextResponse("# Agent script not found", status_code=404)
        return PlainTextResponse(py_path.read_text(encoding="utf-8"), media_type="text/x-python")

    @app.get("/agent/{filename}")
    async def serve_agent_module(filename: str):
        safe_file = Path(filename).name
        target = CURRENT_DIR.parent / "agent" / safe_file
        if not target.exists() or not target.is_file():
            return PlainTextResponse(f"# File not found: {safe_file}", status_code=404)
        media_type = "text/x-python" if safe_file.endswith(".py") else "application/json"
        return PlainTextResponse(target.read_text(encoding="utf-8"), media_type=media_type)

    # ------------------------------------------------------------- Phase 1 SOC Proxy Routes

    # --- Authentication & Users ---
    @app.post("/api/auth/login")
    async def login_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager("/api/auth/login", body))

    @app.get("/api/auth/me")
    async def get_auth_me_proxy(request: Request):
        auth_h = request.headers.get("Authorization")
        req = urllib.request.Request(f"{backend.manager_url}/api/auth/me")
        if auth_h:
            req.add_header("Authorization", auth_h)
        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                return JSONResponse(content=json.loads(resp.read().decode("utf-8")))
        except Exception:
            return JSONResponse(content={"username": "admin", "role": "admin", "permissions": ["all"]})

    @app.post("/api/auth/logout")
    async def logout_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager("/api/auth/logout", body))

    @app.get("/api/users")
    async def list_users_proxy():
        return JSONResponse(content=backend.get_manager("/api/users"))

    @app.post("/api/users")
    async def create_user_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager("/api/users", body))

    @app.delete("/api/users/{username}")
    async def delete_user_proxy(username: str):
        return JSONResponse(content=backend.delete_manager(f"/api/users/{username}"))

    # --- Audit Trail ---
    @app.get("/api/audit")
    async def list_audit_proxy(request: Request):
        query = str(request.query_params)
        path = "/api/audit" + (f"?{query}" if query else "")
        return JSONResponse(content=backend.get_manager(path))

    @app.post("/api/audit")
    async def record_audit_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager("/api/audit", body))

    # --- Key Rotation & Fleet Telemetry ---
    @app.post("/api/agents/{agent_id}/rotate-key")
    async def rotate_agent_key_proxy(agent_id: str):
        return JSONResponse(content=backend.post_manager(f"/api/agents/{agent_id}/rotate-key", {}))

    @app.get("/api/fleet/telemetry")
    async def fleet_telemetry_proxy():
        return JSONResponse(content=backend.get_manager("/api/fleet/telemetry"))

    # --- Searches (Saved & Piped) ---
    @app.get("/api/searches")
    async def list_saved_searches_proxy():
        return JSONResponse(content=backend.get_manager("/api/searches"))

    @app.post("/api/searches")
    async def create_saved_search_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager("/api/searches", body))

    @app.delete("/api/searches/{search_id}")
    async def delete_saved_search_proxy(search_id: str):
        return JSONResponse(content=backend.delete_manager(f"/api/searches/{search_id}"))

    @app.post("/api/searches/{search_id}/run")
    async def run_saved_search_proxy(search_id: str):
        return JSONResponse(content=backend.post_manager(f"/api/searches/{search_id}/run", {}))

    @app.post("/api/search/piped")
    async def run_piped_search_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_indexer("/api/search/piped", body))

    # --- Retention & Tamper Evidence ---
    @app.post("/api/storage/verify-integrity")
    async def verify_storage_integrity_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_indexer("/api/storage/verify-integrity", body))

    @app.get("/api/retention/status")
    async def get_retention_status_proxy():
        return JSONResponse(content=backend.get_indexer("/api/retention/status"))

    @app.post("/api/retention/archive")
    async def run_retention_archive_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_indexer("/api/retention/archive", body))

    @app.post("/api/retention/backup")
    async def run_retention_backup_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_indexer("/api/retention/backup", body))

    # --- CERT-In Incident Report ---
    @app.get("/api/cases/{case_id}/cert-in-report")
    async def get_cert_in_report_proxy(case_id: str, request: Request):
        query = str(request.query_params)
        path = f"/api/cases/{case_id}/cert-in-report" + (f"?{query}" if query else "")
        fmt = request.query_params.get("format", "json").lower()
        if fmt in ("markdown", "md"):
            try:
                with urllib.request.urlopen(f"{backend.manager_url}{path}", timeout=5.0) as resp:
                    return PlainTextResponse(resp.read().decode("utf-8"), media_type="text/markdown")
            except Exception as e:
                return PlainTextResponse(f"Error generating report: {e}", status_code=500)
        return JSONResponse(content=backend.get_manager(path))

    # --- Schema Mapping Export & Generic Ingestion ---
    @app.post("/api/events/export")
    async def export_events_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager("/api/events/export", body))

    @app.post("/api/ingest")
    async def ingest_generic_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return JSONResponse(content=backend.post_manager("/api/ingest", body))

    return app


def main():
    parser = argparse.ArgumentParser(description="Kavalan SOC Dashboard (Tier 4)")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8900, help="Dashboard port (default: 8900)")
    parser.add_argument("--manager", default="http://127.0.0.1:8910", help="Manager URL")
    parser.add_argument("--indexer", default="http://127.0.0.1:8920", help="Indexer URL")
    args = parser.parse_args()

    backend = DashboardBackend(manager_url=args.manager, indexer_url=args.indexer)
    app = create_dashboard_app(backend)
    print(f"[*] Kavalan SOC Dashboard (Tier 4) live on http://{args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()

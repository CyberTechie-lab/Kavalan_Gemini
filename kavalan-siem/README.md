<div align="center">
  <img src="dashboard/static/kavalan_logo_mark.svg" width="110" alt="Kavalan Sentinel Emblem"/>
  <h1>Kavalan Enterprise SIEM &amp; SOAR</h1>
  <p><b>Autonomous AI Threat Defense &middot; Distributed 4-Tier SOC &middot; Sub-150MB Total Footprint</b></p>
</div>

A lightweight, distributed enterprise SIEM (Security Information & Event Management) and SOAR (Security Orchestration, Automation, and Response) platform built around Kavalan's deterministic behavioral detection core. 

Built with a modular **4-Tier Architecture** (**Agent → Manager → Indexer → Dashboard**), ultra-lightweight (<150 MB total RAM, pure Python standard library for agents, zero Java/Elasticsearch bloat, and fast startup).

---

## 4-Tier Distributed Architecture

```
                                  ┌──────────────────────────┐
                                  │   Tier 4: Dashboard      │
                                  │   Port 8900 (SOC Console)│
                                  └─────────────▲────────────┘
                                                │
                 ┌──────────────────────────────┴──────────────────────────────┐
                 │                                                             │
   ┌─────────────┴────────────┐                                  ┌─────────────┴────────────┐
   │    Tier 2: Manager       │◄── Heartbeats & Event Batches ───│    Tier 1: Agent Fleet   │
   │    Port 8910 (Decoders,  │                                  │    Ubuntu / Linux Server │
   │    Ruleset, ATT&CK, AR)  │                                  │    (/var/log/auth.log,   │
   └─────────────┬────────────┘                                  │    /var/log/nginx/...)   │
                 │                                               └──────────────────────────┘
                 │ Forward Normalized Documents
                 ▼
   ┌──────────────────────────┐
   │    Tier 3: Indexer       │
   │    Port 8920 (WAL SQLite,│
   │    Discovery & Histogram)│
   └──────────────────────────┘
```

| Tier | Component | Responsibilities | Memory Footprint |
| :--- | :--- | :--- | :--- |
| **Tier 1** | **Agent (`agent.py`)** | Auto-enrollment, 10s keepalives, log tailing, disk/memory spooling, Ubuntu log discovery | **< 12 MB RAM** |
| **Tier 2** | **Manager (`manager.py`)** | Decoders, AI agent rules (100100–100400), MITRE ATT&CK mapping, Active Response, Fleet tracking | **< 45 MB RAM** |
| **Tier 3** | **Indexer (`indexer.py`)** | High-speed SQLite WAL store, OpenSearch-style query API, aggregations & histograms | **< 40 MB RAM** |
| **Tier 4** | **Dashboard (`dashboard_server.py`)** | Fleet manager, MITRE ATT&CK matrix, Indexer discovery, SOC alert console | **< 40 MB RAM** |

---

## Deploying Kavalan Agent to Ubuntu Linux

You can deploy the Kavalan Endpoint Agent to any Ubuntu / Debian server in two simple ways.

### Option 1: One-Line Automatic Install (Recommended)

Run this single command on your Ubuntu server (replaces `<MANAGER_IP>` with your Kavalan Manager's address):

```bash
curl -sSL http://<MANAGER_IP>:8910/install.sh | sudo bash -s -- --manager http://<MANAGER_IP>:8910 --name $(hostname)
```

**What the installer does automatically:**
1. Verifies Python 3 (installs `python3` via `apt-get` if missing).
2. Sets up `/opt/kavalan-agent` and downloads `agent.py`.
3. Auto-detects standard Ubuntu log files:
   - `/var/log/auth.log` (SSH brute-force, privilege escalation, invalid users)
   - `/var/log/nginx/access.log` (Web probing, SQLi, SSRF, rapid tactic switching)
   - `/var/log/apache2/access.log` (Apache web access logs)
   - `/var/log/syslog` (System events)
4. Generates `/etc/kavalan-agent/agent.conf`.
5. Installs and enables the `kavalan-agent.service` systemd unit.
6. Enrolls the agent with the Manager and starts streaming telemetry.

### Option 2: Remote Deployment via SSH (`deployer.py`)

From your SIEM controller or workstation, deploy to a remote Ubuntu server over SSH:

```bash
# Direct SSH deployment:
python3 kavalan-siem/deployer.py --target ubuntu@192.168.1.50 --manager http://192.168.1.10:8910 --name ubuntu-web-01

# With custom SSH key:
python3 kavalan-siem/deployer.py --target root@10.0.0.15 --key ~/.ssh/id_rsa --manager http://10.0.0.1:8910

# Generate customized copy-paste command:
python3 kavalan-siem/deployer.py --generate-cmd --manager http://192.168.1.10:8910 --name ubuntu-01
```

---

## Agent Management on Ubuntu

```bash
# Check agent status
sudo systemctl status kavalan-agent

# View live streaming agent logs
sudo journalctl -u kavalan-agent -f

# Restart agent
sudo systemctl restart kavalan-agent

# Completely uninstall agent
sudo bash /opt/kavalan-agent/install.sh --uninstall
```

---

## Google Gemini AI · Frontier Cybersecurity Intelligence

Kavalan integrates **Google Gemini** (Gemini 1.5 Flash / Gemini 2.0 Flash / Pro) as its core cognitive AI layer, designed exclusively for autonomous AI-agent threat attribution, MITRE ATT&CK reasoning, natural language SOC Copilot assistance, and automated playbook generation:

- **Frontier Multimodal AI:** Powered by Google DeepMind's Gemini models with massive 1,000,000-token context windows for complex multi-stage attack trajectory reconstruction.
- **Domain Security Reasoning:** In-depth attribution of autonomous AI-agent bot behaviors (e.g. Strix, PentestGPT), differentiating superhuman tool execution tempos from human operators.
- **Interactive SOC Copilot:** Natural language security chat assistant directly grounded in live SIEM event telemetry, active alerts, and host state.
- **Explainability & Attribution:** Token-level salience weights and attribution breakdown highlighting critical IPs, MITRE techniques, and attack tactics.
- **Zero-Dependency Integration:** Communicates directly with Google Gemini REST API using pure Python standard library (`urllib.request`), respecting Kavalan's ultra-lightweight footprint.
- **Gemini AI Studio:** Interactive model workbench in the SIEM Dashboard at `http://127.0.0.1:8900` under the **Gemini AI Studio** tab, with live API key configuration and prompt experimentation.

---

## Operating the 4-Tier SOC Stack

```bash
# Start all 4 tiers (Indexer, Manager, Dashboard, persistent Agents)
python3 kavalan-siem/kavalan_soc.py start

# Check real-time fleet health, active threats, and indexed event count
python3 kavalan-siem/kavalan_soc.py status

# Clean restart (stops all tiers & agents, flushes ports, restarts)
python3 kavalan-siem/kavalan_soc.py restart

# Stop all tiers
python3 kavalan-siem/kavalan_soc.py stop
```

---

## Verification & Automated Tests

Run the full pytest suite (all 22 unit & integration tests):

```bash
PYTHONPATH=kavalan-siem pytest kavalan-siem/tests -v
```

# CLAUDE.md · Comprehensive Project Memory, Architectural Contract & Developer Guide

> **Project:** Kavalan (Autonomous AI-Agent Threat Defense & Ultra-Lightweight Distributed SIEM/SOAR)  
> **Status:** Active Startup & Research Prototype | Ready for Live SOC Demonstration  
> **Target Event:** H2S Buildathon (Hack2Skill Startup Track)  
> **Founder & Lead Systems Architect:** Shiyam Sundar S ([shiyamsundar.sec@gmail.com](mailto:shiyamsundar.sec@gmail.com))  
> **Academic Foundation:** Published IEEE Paper — *"Kavalan: Behavioural Detection of Autonomous AI-Agent Attacks on Web Applications"*  
> **Co-Authors & Founding Research Team (11 Members):** Shiyam Sundar S, Joshna Rose J N, Barath Kumar S, Pooja A D, Nivetha J, Kamalishreenethra S R, Shakthi Vikranth S N, Vigneshwaran S, Pragadeeshwaran S, Dharshana D, Sanju G.  
> **Total Footprint Invariant:** Entire 4-tier stack MUST strictly remain **< 150 MB total RAM**. Zero Java/JVM, zero Elasticsearch/Logstash, zero external pip dependencies for Tier 1 Agent.

---

## 1. Executive Summary & Core Value Proposition

Conventional SIEM platforms (Splunk, Microsoft Sentinel, Elastic, Wazuh) were architected decades ago for human attackers. They evaluate incoming telemetry on two foundational assumptions:
1. Attacks originate from a **single persistent IP address**.
2. Attacks repeat **static, well-known exploit signatures** (e.g., thousands of identical SQLi payloads).

Autonomous AI agents (such as Strix, PentestGPT, or autonomous multi-tool LLMs) break both assumptions:
- **Machine-Speed Execution Loops:** Agents execute tool-calling loops at superhuman velocities (1,200+ requests per 10-second burst).
- **Ephemeral & Disposable Cloud Infrastructure:** Agents shard probing across hundreds of short-lived cloud sandboxes, serverless functions, and rotating proxy pools—no single IP ever exceeds volumetric thresholds.
- **Dynamic Multi-Tactic Switching:** Agents adapt to server responses in milliseconds, oscillating rapidly across exploit classes (SQLi → SSRF → Directory Traversal → Credential Fuzzing → Auth Bypass) within sub-5-second intervals.
- **Punitive Cloud Ingestion Taxes:** Enterprise SIEMs require 16 GB to 64 GB of RAM and charge $150 to $500 per GB/month for log ingestion. When an AI agent unleashes 100,000 automated probes, the victim organization is penalized twice: once by the adversary, and once on their cloud SIEM bill.

### The Kavalan Breakthrough
- **Campaign-Level Behavioral Correlation:** Correlates multiple short-lived, rotating IP addresses into a single unified threat campaign based on 5 mathematical behavioral signals rather than static single-IP counters.
- **Ultra-Lightweight 4-Tier Distributed SOC (< 150 MB Total RAM):** Agent (<12MB) → Manager (<45MB) → Indexer (<40MB) → Dashboard (<40MB).
- **Google Gemini Threat Intelligence Integration:** Integrated Google Gemini (Gemini 1.5 Flash / Gemini 2.0 Flash) frontier intelligence with a 1,000,000-token context window for multi-vector threat attribution, interactive SOC Copilot chat, and automated containment playbooks. Uses pure Python `urllib` with zero external dependencies.
- **Empirically Proven & IEEE Published:** Validated against the live open-source Strix AI agent attacking OWASP Juice Shop: flagged 16,997 actions at HIGH severity with **zero false positives** on 80 real human users and web crawlers.

---

## 2. Immutable Architectural Invariants (DO NOT VIOLATE)

Any AI collaborator or developer working on Kavalan must strictly adhere to these non-negotiable rules:

1. **Ultra-Lean Resource Constraint (< 150 MB Total RAM):**
   - The entire distributed 4-tier stack (all 4 processes combined) must run comfortably within < 150 MB RAM.
   - **Tier 1 Agent (`agent/agent.py`) must remain < 12 MB RAM** and use **pure Python standard library ONLY**. Absolutely zero external pip dependencies (`urllib`, `re`, `socket`, `sqlite3`, `json`, `dataclasses`, `time`).
   - Never introduce Elasticsearch, Logstash, Kibana, OpenSearch daemons, JVM/Java runtimes, or heavy container dependencies into the core engine.
2. **Deterministic Detection Core + Air-Gapped Intelligence:**
   - Threat detection is 100% deterministic (5-signal behavioral correlation engine + character n-gram tactic classifier).
   - Never use an external cloud LLM (OpenAI, Anthropic, Gemini) for primary threat detection or pass customer log telemetry to external cloud endpoints.
   - `Kavalan-SecLLM-v1` runs locally on CPU in pure Python for MITRE ATT&CK reasoning, attention heatmap explainability, and SOAR playbooks.
3. **High-Speed SQLite Write-Ahead Logging (WAL):**
   - Tier 3 Indexer and Tier 2 Manager rely on embedded SQLite in `PRAGMA journal_mode=WAL` and `PRAGMA synchronous=NORMAL`.
   - Handles > 15,000 writes/sec on NVMe drives with sub-millisecond query latencies and zero distributed cluster overhead.
4. **Frozen Common Event Model (CEM):**
   - All agents, decoders, and storage layers conform strictly to the frozen CEM specification.

---

## 3. Distributed 4-Tier System Architecture

```
                               ┌────────────────────────────────┐
                               │   Tier 4: Dashboard Server     │
                               │   Port 8900 (SOC Console)      │
                               │   Memory: < 40 MB RAM          │
                               └───────────────▲────────────────┘
                                               │ HTTP / REST
               ┌───────────────────────────────┴───────────────────────────────┐
               │                                                               │
 ┌─────────────┴──────────────┐                                  ┌─────────────┴──────────────┐
 │    Tier 2: Manager         │◄── Heartbeats & Event Batches ───│    Tier 1: Agent Fleet     │
 │    Port 8910               │                                  │    Linux / Ubuntu Servers  │
 │    - CEM Decoders          │                                  │    - Log Tailing & Spooling│
 │    - Rule Engine (0-16)    │                                  │    - FIM (syscheck.py)     │
 │    - Stateful Accumulator  │                                  │    - Syscollector & SCA    │
 │    - Sec-LLM & SOAR Engine │                                  │    - Active Response Exec  │
 │    Memory: < 45 MB RAM     │                                  │    Memory: < 12 MB RAM     │
 └─────────────┬──────────────┘                                  └────────────────────────────┘
               │
               │ Forward Normalized Documents (CEM)
               ▼
 ┌────────────────────────────┐
 │    Tier 3: Indexer         │
 │    Port 8920               │
 │    - SQLite WAL Datastore  │
 │    - Time-Series Histograms│
 │    - OpenSearch REST API   │
 │    Memory: < 40 MB RAM     │
 └────────────────────────────┘
```

### Detailed Component Specifications

| Tier | Component File | Port / Daemon | Memory | Responsibilities & Technical Capabilities |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 1** | [`kavalan-siem/agent/agent.py`](file:///Users/shiyamsundars/Downloads/kavalan/kavalan-siem/agent/agent.py) | Daemon | **< 12 MB** | • Zero-dependency auto-enrollment with Manager.<br>• 10s keepalive heartbeats with CPU load & RAM telemetry.<br>• Log tailing with inode-tracking (logrotate-safe).<br>• Decodes RFC3164/5424 syslogs and Nginx/Apache combined formats.<br>• Three-stage spool buffer: NORMAL (<80%), WARNING (80-99%), FLOOD (100%).<br>• FIM (`syscheck.py`), system inventory (`syscollector.py`), CIS audit (`sca.py`), and Active Response execution (`executor.py`). |
| **Tier 2** | [`kavalan-siem/manager/manager.py`](file:///Users/shiyamsundars/Downloads/kavalan/kavalan-siem/manager/manager.py) | Port 8910 | **< 45 MB** | • Central brain: fleet tracking, keepalives, config sync.<br>• CEM normalizer and multi-agent event ingestion.<br>• Behavioral correlation engine & stateful rule accumulator.<br>• Hierarchical detection rules (100100–100700, Levels 0–16).<br>• Zero-dependency Sigma YAML/JSON rule compiler (`sigma_converter.py`).<br>• Local CVE vulnerability correlation & SCA benchmarks (`vuln_scanner.py`).<br>• Autonomous SOAR playbook engine & webhook dispatcher.<br>• `Kavalan-SecLLM-v1` and AI Threat Analyst cognitive engine. |
| **Tier 3** | [`kavalan-siem/indexer/indexer.py`](file:///Users/shiyamsundars/Downloads/kavalan/kavalan-siem/indexer/indexer.py) | Port 8920 | **< 40 MB** | • High-throughput SQLite WAL document store (>15k writes/sec).<br>• Composite indexing on `(agent_id, source_ip, timestamp)`.<br>• OpenSearch-compatible REST endpoints (`/api/search/events`, `/api/search/alerts`, `/api/aggregate`).<br>• Global Threat Intelligence IOC local B-Tree engine (`threat_intel.py`). |
| **Tier 4** | [`kavalan-siem/dashboard/dashboard_server.py`](file:///Users/shiyamsundars/Downloads/kavalan/kavalan-siem/dashboard/dashboard_server.py) | Port 8900 | **< 40 MB** | • Unified web console (pure HTML/vanilla JS, zero npm build).<br>• Real-time SOC Threat Radar & live Attack Topology Graph.<br>• Interactive MITRE ATT&CK Matrix heatmap.<br>• Sec-LLM Studio with token-level attention explainability heatmaps.<br>• Autonomous AI SOC Copilot chat assistant.<br>• Incident case management and one-click active response triage. |

---

## 4. Deep Tech: The 5 Behavioral Tells & Hybrid ML Pipeline

### The 5 Behavioral Tells of AI-Agent Attacks
When an autonomous AI agent attacks an application, it inevitably betrays itself across 5 distinct mathematical dimensions:

```
  1. BURST VELOCITY         2. ENDPOINT BREADTH         3. TACTIC SWITCHING
   1,246 reqs / 10s           15,300 distinct paths       SQLi ──► SSRF ──► CmdI
┌──────────────────────┐   ┌──────────────────────┐   ┌──────────────────────┐
│  ██████████████████  │   │  ▲ ▲ ▲ ▲ ▲ ▲ ▲ ▲ ▲   │   │  0.0s : SQL Injection│
│  Superhuman machine  │   │  Automated recursive │   │  1.5s : SSRF Probe   │
│  execution loops     │   │  surface enumeration │   │  3.2s : Auth Bypass  │
└──────────────────────┘   └──────────────────────┘   └──────────────────────┘

  4. RESOURCE PENETRATION   5. ERROR CLUSTERING
   Hits on sensitive files    25% - 40% 4xx/5xx responses
┌──────────────────────┐   ┌──────────────────────┐
│  /.env, /wp-admin,   │   │  High failure rate   │
│  /api/v1/admin/tokens│   │  induced by adaptive │
│  Privilege targeting │   │  payload fuzzing     │
└──────────────────────┘   └──────────────────────┘
```

1. **Burst Velocity:** Superhuman request speed (e.g. 1,200+ requests in a 10-second window) devoid of human cognitive think-time pauses.
2. **Endpoint Breadth:** Broad path entropy (probing 15,000+ distinct endpoints in minutes) as the agent recursively maps the target attack surface.
3. **Dynamic Tactic Switching:** Rapid pivoting between distinct attack vectors (SQLi → SSRF → Path Traversal → Command Injection) within sub-5-second intervals as tools fail and the agent adapts.
4. **Protected Resource Penetration:** Disproportionate targeting of privileged endpoints (`/.env`, `/.git/config`, `/admin`, `/api/v1/tokens`, cloud metadata `169.254.169.254`).
5. **Error Concentration:** A high cluster of 4xx and 5xx HTTP response statuses (25%–40%) triggered by mutated payload fuzzing and syntax guessing.

### Hybrid ML Classification Engine (`kavalan-ml/`)
Kavalan couples fast-path regular expressions with a compact character n-gram machine learning model:
- **Architecture:** Character n-gram TF-IDF (`analyzer="char_wb"`, n-grams 2–5, sublinear TF) + Class-Balanced Logistic Regression (`C=8.0`).
- **Disk Size:** ~6 MB joblib model file.
- **Dataset:** 33,859 labeled payloads (CSIC 2010, SecLists, PayloadsAllTheThings).
  - Classes: `benign` (19,855), `sqli` (10,852), `cmdi` (1,589), `xss` (638), `traversal` (600), `ssrf` (325).
- **Benchmark Evaluation Results:**
  - **In-Distribution Test (20% holdout):** **99.9% accuracy** across 6,772 test samples.
  - **Cross-Source Evaluation (Unseen tools & novel payloads):**
    - Regex Baseline alone: 96.3% accuracy (struggles with obfuscated XSS and SSRF).
    - ML Model alone: 75.6% accuracy.
    - **Hybrid Pipeline (Regex fast-path + ML fallback):** **99.3% accuracy**, with **0 False Positives** on 3,861 real benign parameters.

### Google Gemini Threat Intelligence Engine
Located in [`kavalan-siem/manager/gemini/`](file:///Users/shiyamsundars/Kavalan_Gemini/kavalan-siem/manager/gemini/):
- **Model:** Google Gemini (Gemini 1.5 Flash / Gemini 2.0 Flash / Pro) by Google DeepMind.
- **Context Window:** 1,000,000 tokens enabling deep historical correlation across multi-day campaigns.
- **Footprint:** 0.0 MB local RAM overhead, zero third-party pip dependencies (pure Python standard library REST client).
- **Specialized Domain Tokenizer:** Preserves intact IPv4 addresses (`203.0.113.66`), MITRE technique codes (`T1190`, `T1078`), status codes (`401`, `500`), and Linux terminal commands without subword fragmentation.
- **Explainability:** Generates a token-level salience and attribution heatmap visualizing exactly which telemetry indicators triggered the security verdict.
- **SOC Copilot Chat:** Interactive natural language security analyst powered by Gemini, grounded in live SIEM alerts, active threat actors, and host status.
- **Configurability:** Runtime API key and model selection directly via the SIEM Dashboard Gemini Studio or environment variable (`GEMINI_API_KEY`).

---

## 5. Threat Intelligence & Autonomous SOAR Engine

### Global Threat Intelligence Engine (`threat_intel.py`)
- High-speed local B-Tree SQLite cache located in `indexer.db`.
- Sub-millisecond IOC lookups for IP addresses, domains, and hashes.
- Pre-seeded with feeds from AbuseIPDB, AlienVault OTX, Tor Exit Nodes, and CISA Known Exploited Vulnerabilities (KEV).
- Evaluates Abuse Confidence Scores (0–100), reputation classes (`MALICIOUS`, `SUSPICIOUS`, `NEUTRAL`), Tor exit status, and ASN ownership.

### Autonomous SOAR Playbook Engine (`soar_playbook_engine.py`)
Implements an Event-Condition-Action (ECA) workflow orchestrator for zero-touch remediation:

| Playbook ID | Name | Trigger Condition | Automated Remediation Actions |
| :--- | :--- | :--- | :--- |
| **PB-AUTO-001** | Auto-Quarantine Malicious IOCs | Abuse Score >= 80% or Tor Exit Node detected | 1. Issue fleet-wide firewall drop (3600s).<br>2. Auto-create CRITICAL incident case.<br>3. Dispatch high-priority webhook. |
| **PB-AUTO-002** | Rapid Ransomware & FIM Containment | Level >= 12 and Impact / T1565 file tampering | 1. Quarantine modified file to `/tmp/kavalan_quarantine`.<br>2. Lock compromised user account.<br>3. Dispatch containment webhook. |
| **PB-AUTO-003** | Distributed SSH Brute Force Suppressor | Level >= 8 and Credential Access / T1110.001 | 1. Temporary firewall drop on auth gateway (1800s).<br>2. Dispatch rate-limiting alert webhook. |

---

## 6. Empirical Validation & Benchmark Metrics

Documented in the published IEEE research paper based on an isolated OWASP Juice Shop testbed attacked by the live open-source **Strix** AI agent:

| Traffic Class | Total Requests | Peak Rate (Reqs / 10s) | Distinct Endpoints Probed | Kavalan Score | Severity Verdict |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Autonomous AI Agent (Strix)** | **16,997** | **1,246 reqs** | **15,300 paths** | **70 / 100** | **HIGH (Alert Raised)** |
| **Human Attacker (Slow Fuzzing)** | 19 | 2 reqs | 4 paths | 5 / 100 | **OK (Monitored)** |
| **Normal Shoppers + Web Crawler** | 952 | 14 reqs | 82 paths | 7 / 100 | **OK (0 False Positives)** |

### Competitive Benchmark: Kavalan vs. Legacy SIEMs

| Metric / Dimension | **Kavalan** | **Splunk / Sentinel** | **Wazuh** |
| :--- | :--- | :--- | :--- |
| **Primary Target Threat** | **Autonomous AI Agents & Campaigns** | Static Signatures & Compliance | Host Vulnerability Baseline |
| **Total Stack RAM** | **< 150 MB Total RAM** | 16 GB – 64 GB RAM | 16 GB+ (Java/ES Stack) |
| **Endpoint Agent Footprint**| **< 12 MB (Pure Python Stdlib)** | 100 MB – 300 MB | 50 MB – 100 MB (C Agent) |
| **Data Ingestion Tax** | **$0 (Zero per-GB penalty)** | $150 – $500 per GB / mo | Self-hosted server compute |
| **Sec-LLM Reasoning** | **Built-in (<2MB CPU Transformer)** | Expensive Cloud Add-on | None |
| **Air-Gap Capable** | **100% Offline Native** | Cloud Dependent | Complex Multi-VM On-Prem |
| **Empirical Proof** | **Caught Strix (17k reqs, 0 FP)** | Undocumented for AI Agents | Rule tuning required |

---

## 7. Business Model & H2S Buildathon Pitch Deck

### Market Opportunity
- **TAM:** $14.2B Global SIEM & SOAR Market (14.5% CAGR).
- **SAM:** $3.8B Mid-Market Enterprises, Edge Computing, and Defense Enclaves priced out of Splunk.
- **SOM:** $180M Cloud-native SMBs, software engineering teams, and critical infrastructure.

### Revenue Model
1. **Community Edition (Open-Source):** Free forever, up to 5 agent nodes, embedded SQLite indexer.
2. **Professional Tier:** **$49 / node / month** (unlimited log ingestion, Sec-LLM triage, automated SOAR playbooks, zero per-GB penalty).
3. **Enterprise Air-Gapped Licensing:** **$25,000 to $100,000 / year** (sovereign on-premise deployments, custom decoders, eBPF probes, 24/7 mission-critical SLA).

### Pitch Assets in Workspace Root
- **PowerPoint Presentation:** [`Kavalan_H2S_Pitch_Deck.pptx`](file:///Users/shiyamsundars/Downloads/kavalan/Kavalan_H2S_Pitch_Deck.pptx) (12 widescreen 16:9 slides, cyber dark theme, stat cards, custom tables).
- **Interactive Browser Deck:** [`Kavalan_H2S_Pitch_Deck.html`](file:///Users/shiyamsundars/Downloads/kavalan/Kavalan_H2S_Pitch_Deck.html) (zero-dependency HTML/CSS presentation with keyboard controls `←`/`→` and fullscreen `F`).
- **Speaker Playbook & Judge Q&A:** [`PITCH_SCRIPT_AND_GUIDE.md`](file:///Users/shiyamsundars/Downloads/kavalan/PITCH_SCRIPT_AND_GUIDE.md) (word-for-word 3-min pitch script, 60-second live demo playbook, Top 10 tough judge Q&A).
- **Slide Generator Script:** [`generate_pitch_deck.py`](file:///Users/shiyamsundars/Downloads/kavalan/generate_pitch_deck.py) (`python-pptx` automated deck compiler).

---

## 8. Common Developer & Operational Commands

### Operating the 4-Tier SOC Stack
```bash
# Start all 4 tiers (Indexer :8920, Manager :8910, Dashboard :8900, persistent Agents)
python3 kavalan-siem/kavalan_soc.py start

# Inspect real-time status of all tiers, registered agents, and active threat counts
python3 kavalan-siem/kavalan_soc.py status

# Cleanly restart all tiers (flushes sockets and restarts daemons)
python3 kavalan-siem/kavalan_soc.py restart

# Stop all 4 tiers
python3 kavalan-siem/kavalan_soc.py stop
```

### Accessing Local Services
- **SOC Web Dashboard:** [http://127.0.0.1:8900](http://127.0.0.1:8900) *(Press `Cmd+Shift+R` or `Ctrl+F5` for a fresh browser reload)*
- **Manager REST API:** [http://127.0.0.1:8910](http://127.0.0.1:8910)
- **Indexer REST API:** [http://127.0.0.1:8920](http://127.0.0.1:8920)

### Deploying Endpoint Agent to Ubuntu/Debian Servers
```bash
# 1-Line auto-install on remote or local Ubuntu Linux:
curl -sSL http://<MANAGER_IP>:8910/install.sh | sudo bash -s -- --manager http://<MANAGER_IP>:8910 --name $(hostname)

# Check running agent status on Linux endpoint:
sudo systemctl status kavalan-agent

# View live agent telemetry stream:
sudo journalctl -u kavalan-agent -f
```

### Running the Test Suite (59 Tests, 18 Test Files)
```bash
# Execute the complete pytest test suite:
PYTHONPATH=kavalan-siem pytest kavalan-siem/tests -v
```

### Regenerating Pitch Assets
```bash
python3 generate_pitch_deck.py
```

---

## 9. Guidance for Future AI Collaborators

When assisting on this project:
1. **Preserve the < 150 MB RAM Invariant:** Never recommend adding heavy third-party daemons (Elasticsearch, Kafka, Redis, Logstash, Java).
2. **Preserve Agent Dependency-Free Purity:** Any additions to `kavalan-siem/agent/` must rely strictly on standard library Python modules.
3. **Keep Presentation Files in Sync:** If editing slides, update both `generate_pitch_deck.py` and `Kavalan_H2S_Pitch_Deck.html` simultaneously.
4. **Air-Gapped First:** All detection and intelligence capabilities must remain 100% operational offline.

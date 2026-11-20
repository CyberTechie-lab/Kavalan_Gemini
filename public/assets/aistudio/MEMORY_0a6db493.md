# KAVALAN · PROJECT MEMORY & ARCHITECTURE CONTEXT
> **Last Updated:** November 2026  
> **Status:** Active Startup & Research Prototype  
> **Target Event:** H2S Buildathon (Hack2Skill Startup Track)  
> **Founder & Lead Systems Architect:** Shiyam Sundar S  
> **Academic Foundation:** Published IEEE Paper — *"Kavalan: Behavioural Detection of Autonomous AI-Agent Attacks on Web Applications"*

---

## 1. Executive Summary & Value Proposition

**Kavalan** is the world's first autonomous AI-agent threat defense platform and ultra-lightweight distributed SIEM/SOAR (<150 MB total RAM footprint).

### The Core Problem
Conventional SIEMs (Splunk, Elastic, Sentinel, Wazuh) were designed for human attackers. They correlate logs by **single source IP** and **static attack signatures**. Autonomous AI agents break both assumptions:
1. **Machine-Speed Execution Loops:** Agents execute thousands of tool actions in minutes (e.g., 1,200+ requests/10s), far exceeding human response times.
2. **Ephemeral / Disposable Cloud IPs:** Agents distribute traffic across hundreds of short-lived cloud sandboxes and proxy pools so no individual IP crosses rate limits.
3. **Rapid Multi-Tactic Switching:** Agents cycle continuously (SQLi → XSS → SSRF → Auth Bypass) within seconds; single-signature rules never accumulate enough threshold.
4. **Bloated Ingestion Tax:** Enterprise SIEMs require 16GB–64GB RAM and charge $150–$500/GB/month for data ingestion, forcing organizations to drop security logs to control budget.

### The Kavalan Solution
- **Campaign-Level Behavioral Correlation:** Correlates multiple short-lived IPs into a single unified campaign based on 5 mathematical behavioral signals rather than static IP thresholds.
- **Sub-150MB Distributed 4-Tier Stack:** Fleet Agent (<12MB) → Cluster Manager (<45MB) → SQLite WAL Indexer (<40MB) → SOC Dashboard (<40MB). Zero Elasticsearch, zero JVM bloat.
- **On-Device Sec-LLM (< 2MB RAM):** Self-contained causal security transformer running pure CPU inference with zero cloud egress for threat attribution, MITRE ATT&CK mapping, and SOAR playbooks.
- **Empirical Validation:** Proven against the live **Strix** AI pentest agent attacking OWASP Juice Shop (16,997 actions detected, 0 False Positives on 80 human users).

---

## 2. Distributed 4-Tier System Architecture

```
                               ┌────────────────────────────────┐
                               │   Tier 4: Dashboard Server     │
                               │   Port 8900 (SOC Console)      │
                               │   Memory: < 40 MB RAM          │
                               └───────────────▲────────────────┘
                                               │
               ┌───────────────────────────────┴───────────────────────────────┐
               │                                                               │
 ┌─────────────┴──────────────┐                                  ┌─────────────┴──────────────┐
 │    Tier 2: Manager         │◄── Heartbeats & Event Batches ───│    Tier 1: Agent Fleet     │
 │    Port 8910 (Decoders,    │                                  │    Ubuntu / Linux Server   │
 │    Ruleset, Sec-LLM, SOAR) │                                  │    Memory: < 12 MB RAM     │
 │    Memory: < 45 MB RAM     │                                  │    Pure Python Stdlib      │
 └─────────────┬──────────────┘                                  └────────────────────────────┘
               │
               │ Forward Normalized Documents (CEM)
               ▼
 ┌────────────────────────────┐
 │    Tier 3: Indexer         │
 │    Port 8920 (SQLite WAL,  │
 │    Histograms & Aggs)      │
 │    Memory: < 40 MB RAM     │
 └────────────────────────────┘
```

### Component Details
| Tier | Component File | Role & Key Features | Memory Footprint |
| :--- | :--- | :--- | :--- |
| **Tier 1** | `kavalan-siem/agent/agent.py` | Auto-enrollment, 10s keepalive, log tailing, disk/RAM spooling, auto-discovers `/var/log/auth.log`, `nginx`, `apache`, `syslog`. Zero external dependencies. | **< 12 MB RAM** |
| **Tier 2** | `kavalan-siem/manager/manager.py` | Common Event Model (CEM) normalizer, AI rules (100100–100400), MITRE ATT&CK engine, Sec-LLM integration, Active Response SOAR dispatcher. | **< 45 MB RAM** |
| **Tier 3** | `kavalan-siem/indexer/indexer.py` | High-speed SQLite WAL store (>10k events/sec), OpenSearch-compatible REST query API, time-series aggregations, zero Lucene/JVM bloat. | **< 40 MB RAM** |
| **Tier 4** | `kavalan-siem/dashboard/dashboard_server.py` | Real-time SOC threat radar, MITRE ATT&CK matrix heatmap, fleet health tracking, Sec-LLM Studio workbench, 1-click active response triage. | **< 40 MB RAM** |

---

## 3. Deep Tech: The 5 Behavioral Tells & Hybrid AI

### The 5 Behavioral Tells of AI-Agent Attacks
1. **Burst Velocity:** Peak requests per 10s (e.g. 1,200+ req/10s) capturing automated execution loops devoid of human cognitive pauses.
2. **Endpoint Breadth:** High distinct path entropy (probing 15,000+ paths in minutes) to systematically enumerate attack surfaces.
3. **Tactic Switching:** Dynamic oscillation between injection types (SQLi → XSS → SSRF → Auth Bypass) within sub-5-second intervals.
4. **Protected Resource Penetration:** High ratio of hits against privileged endpoints (`/.env`, `/wp-admin`, internal actuators).
5. **Error Concentration:** High cluster of 4xx/5xx responses (25%–40%) induced by fuzzing mutations and malformed payloads.

### Detection Pipeline (Rules + ML)
1. **Fast-Path Regex Rules:** Sub-millisecond pattern heuristics.
2. **Character N-Gram Tactic Classifier:** TF-IDF + Logistic Regression (~6 MB model, CPU-only). Labels parameters across `benign, sqli, xss, cmdi, traversal, ssrf`.
   - Results: **99.3% accuracy** on cross-source evaluation with **0 False Positives** on 3,861 real benign parameters.

### Kavalan Sec-LLM (`Kavalan-SecLLM-v1`)
- **Type:** Causal Decoder-Only Security Transformer (RMSNorm, Multi-Head Self-Attention, Feed-Forward).
- **Size:** 141,440 parameters (~550 KB weights on disk).
- **RAM Footprint:** **< 2.0 MB RAM** running on CPU in pure Python standard library.
- **Domain Tokenizer:** Preserves intact IPv4 addresses (`203.0.113.66`), MITRE technique codes (`T1190`, `T1078`), status codes, and bash commands without subword fragmentation.
- **Explainability:** Token-level attention weight heatmap visualizes exact triggering tokens.
- **Air-Gapped Guarantee:** 100% offline; zero telemetry egress to external cloud APIs.

---

## 4. Empirical Validation & Benchmarks

From the IEEE paper parallel benchmark on an isolated OWASP Juice Shop lab:

| Traffic Class | Requests | Peak / 10s | Distinct Paths | Kavalan Score | Severity Outcome |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Autonomous AI Agent (Strix)** | 16,997 | 1,246 reqs | 15,300 paths | **70 / 100** | **HIGH (Alert Raised)** |
| **Human Attacker (Slow Fuzz)** | 19 | 2 reqs | 4 paths | **5 / 100** | **OK (Monitored)** |
| **Normal Users + Crawler (80 shoppers)** | 952 | 14 reqs | 82 paths | **7 / 100** | **OK (0 False Positives)** |

---

## 5. Startup & H2S Buildathon Pitch Assets

All presentation assets are generated and located in the workspace root:

| Asset | File Path | Description |
| :--- | :--- | :--- |
| **PowerPoint Deck** | [`Kavalan_H2S_Pitch_Deck.pptx`](file:///Users/shiyamsundars/Downloads/kavalan/Kavalan_H2S_Pitch_Deck.pptx) | 12-slide 16:9 widescreen presentation with dark cyber theme, native styled tables, stat cards, and embedded logo. |
| **Interactive HTML Deck** | [`Kavalan_H2S_Pitch_Deck.html`](file:///Users/shiyamsundars/Downloads/kavalan/Kavalan_H2S_Pitch_Deck.html) | Zero-dependency browser slide deck with keyboard navigation (`←`/`→`), fullscreen (`F`), and print support. |
| **Speaker Guide & Scripts** | [`PITCH_SCRIPT_AND_GUIDE.md`](file:///Users/shiyamsundars/Downloads/kavalan/PITCH_SCRIPT_AND_GUIDE.md) | Word-for-word 3-minute & 5-minute pitch scripts, 60-second live demo playbook, top 10 judge Q&A with answers. |
| **Generator Script** | [`generate_pitch_deck.py`](file:///Users/shiyamsundars/Downloads/kavalan/generate_pitch_deck.py) | Python script using `python-pptx` to build or modify the slide deck programmatically. |

---

## 6. Business Model & Market Metrics

- **TAM:** $14.2B Global SIEM & SOAR Market (14.5% CAGR).
- **SAM:** $3.8B Mid-Market Enterprises, Edge Computing, and Defense Enclaves priced out of Splunk.
- **SOM:** $180M Cloud-native SMBs, dev teams, and critical infrastructure.
- **Pricing Strategy:**
  - **Community Edition:** Free open-source (up to 5 agents, SQLite indexer).
  - **Professional Tier:** $49 / node / month (unlimited log ingestion, Sec-LLM triage, automated SOAR playbooks, zero per-GB penalty).
  - **Enterprise Air-Gapped:** $25,000–$100,000 / year (sovereign on-prem, custom decoders, eBPF probes, 24/7 SLA).

---

## 7. Developer & Operations Quick Reference

### Stack Management Commands
```bash
# Start all 4 tiers (Manager, Indexer, Dashboard, Agents)
python3 kavalan-siem/kavalan_soc.py start

# Check real-time stack health and active threats
python3 kavalan-siem/kavalan_soc.py status

# Restart the stack cleanly
python3 kavalan-siem/kavalan_soc.py restart

# Stop the stack
python3 kavalan-siem/kavalan_soc.py stop
```

### Agent Deployment
```bash
# 1-Line auto-install on Ubuntu/Debian:
curl -sSL http://<MANAGER_IP>:8910/install.sh | sudo bash -s -- --manager http://<MANAGER_IP>:8910 --name $(hostname)

# Check agent status:
sudo systemctl status kavalan-agent
```

### Test Suite
```bash
# Run all 22 unit & integration tests:
PYTHONPATH=kavalan-siem pytest kavalan-siem/tests -v
```

### Regenerate Pitch Deck
```bash
python3 generate_pitch_deck.py
```

---

## 8. Instructions for Claude / Future AI Collaborators

When the user asks Claude to review, update, or expand on this project:
1. **Respect Architectural Invariants:**
   - The fleet agent (`agent.py`) must remain pure Python standard library with zero external pip dependencies.
   - Total stack memory must stay strictly under 150 MB RAM.
   - Never introduce Elasticsearch, Logstash, Java, or heavy container runtimes into the core stack.
   - Core threat detection must remain deterministic and air-gapped without requiring cloud LLM API calls.
2. **Pitch Alignment:**
   - Emphasize the **campaign-level correlation** that beats ephemeral cloud IP hopping.
   - Highlight empirical validation: 16,997 actions detected, 0 False Positives on 80 human users, IEEE publication.
3. **When Modifying Presentation Slides:**
   - Update both `generate_pitch_deck.py` (for `.pptx`) and `Kavalan_H2S_Pitch_Deck.html` (for browser deck) to keep them in lockstep.

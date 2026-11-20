<div align="center">
  <img src="public/kavalan_logo_mark.svg" width="110" alt="Kavalan Sentinel Emblem"/>
  <h1>Kavalan Enterprise SIEM &amp; SOAR</h1>
  <p><b>Autonomous AI Threat Defense &middot; Distributed 4-Tier SOC &middot; Node.js Unified Platform</b></p>
</div>

A lightweight, distributed enterprise SIEM (Security Information & Event Management) and SOAR (Security Orchestration, Automation, and Response) platform built around Kavalan's deterministic behavioral detection core, migrated to run natively on Node.js 22 and TypeScript.

---

## Architecture

- **Tier 1 (Endpoint Agent Telemetry)**: Auto-enrollment, 10s keepalives, log ingestion, CIS SCA baseline checks, and package inventory reporting (`/api/agent/*`, `/install.sh`).
- **Tier 2 (Manager & Detection Engine)**: Multi-format decoder pipeline (`web`, `auth`, `fim`, `syscollector`, `syslog`, `json`), behavioral AI-agent attribution rules (`100100–100400`), Sigma Studio YAML rule converter, Active Response containment, and Autonomous SOAR playbooks (`src/detector.ts`, `src/sigma.ts`, `src/soar.ts`).
- **Tier 3 (Indexer & Attack Graph)**: Fast in-memory event & alert indexing, Discover log search with field term stats, 360° IP Entity Dossier, Threat Intel enrichment, and interactive Attack Topology Graph (`src/store.ts`).
- **Tier 4 (SOC Console & Gemini AI)**: Full-featured web console (`public/index.html`) served via Express on port `3000`, integrated with server-side `@google/genai` AI Analyst & Threat Copilot (`src/gemini.ts`).

---

## Running Locally

```bash
npm install
npm run dev
```

Set `GEMINI_API_KEY` in `.env` (optional — grounded cybersecurity heuristics operate automatically when unset).

## Verification

```bash
npm run build
npm run lint
```

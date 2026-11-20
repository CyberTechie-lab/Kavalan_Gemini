# Kavalan SIEM & SOC Platform — Project Memory & Session History

> **Last Updated:** 2026-11-21 00:36 IST  
> **Repository:** `https://github.com/CyberTechie-lab/Kavalan_Gemini.git`  
> **Active Branch:** `main` (synchronized with `origin/main`)  
> **Service Architecture:** Node.js + TypeScript Express Backend (`port 3000`) + Vanilla JS/CSS Enterprise Console + SQLite WAL Persistent Storage (`data/kavalan_siem.db`)

---

## 1. System Architecture & Tech Stack

- **Runtime & Backend:** Node.js (v20+) with `tsx` executing `server.ts` on port 3000.
- **Database Engine:** SQLite 3 with Write-Ahead Logging (`WAL`), Foreign Keys enabled, stored in `data/kavalan_siem.db` (initialized and managed via `src/db.ts`).
- **Frontend:** Single-Page Enterprise Application (`public/index.html`) using pure semantic HTML5, CSS custom properties (variables), and vanilla JavaScript (no heavy build-step dependencies required for frontend serving).
- **AI Integration:** Google Gemini API integrated into `src/gemini.ts` for automated security root-cause analysis, alert enrichment, and natural-language incident summarization.
- **Standards & Compliance:** 
  - MITRE ATT&CK Matrix mapping.
  - OCSF / Elastic Common Schema (ECS) normalization.
  - CERT-In 6-hour cybersecurity reporting compliance.
  - Role-Based Access Control (RBAC): `admin`, `engineer`, `analyst`.

---

## 2. Chronological Log of Work Completed So Far

### Milestone 1: Dependency & Environment Initialization
- Executed `git pull`, `npm install`, and resolved missing TypeScript types.
- Configured local development scripts via `npm run dev` (`tsx server.ts`) and `npm run build` (`tsc --noEmit`).
- Ensured daemon persistence for background server execution on port 3000.

### Milestone 2: SQLite Database Extraction & Integration
- **Source:** Extracted production SQLite DB and threat intelligence schemas from `/Users/shiyamsundars/Downloads/Kavalan/kavalan-siem/kavalan_siem.db`.
- **Target:** Persistent database located at `data/kavalan_siem.db` managed by `src/db.ts`.
- **Schema & Seeding:**
  - `agents`: Live fleet endpoint telemetry and status (e.g., `prod-web-01`, `prod-db-01`, `corp-dc-01`).
  - `alerts`: Ingested security alerts with MITRE ATT&CK tactics, severity ratings (`critical`, `high`, `medium`, `low`).
  - `incidents`: Escalated security cases with assigned SOC analysts and containment statuses.
  - `rules`: Detection logic including Sigma rules and behavioral heuristics.
  - `users`: Enterprise SOC credentials with bcrypt password hashing and RBAC designations.
  - `audit_log`: Hash-chained tamper-evident CERT-In compliant audit records.
- **Server Integration:** Updated `server.ts` to seamlessly query and persist telemetry to SQLite while falling back to in-memory defaults when necessary.

### Milestone 3: Authentication, RBAC & JavaScript Stability Fixes
- Identified and resolved client-side boot-time crashes caused by missing helper functions.
- Implemented in `public/index.html`:
  - `showLoginOverlay(show)`: Controls visibility of the enterprise authentication modal.
  - `quickFillLogin(username, password)`: Pre-fills quick-test credentials (`admin`, `engineer`, `analyst`) for testing.
  - `applyRbacUiPermissions(role)`: Selectively enables/disables privileged actions and tabs based on the authenticated operator's role.
- Fixed token and session lifecycle management in localStorage (`kavalan_soc_token`, `kavalan_soc_user`).

### Milestone 4: Multi-Location Logout & Profile Management
- **Enterprise Profile Dropdown:** Added `.user-profile-wrapper` in `.top-header-right` displaying operator avatar initials, role badge, username, and dropdown menu (Role Switcher, RBAC navigation, and CERT-In audit links).
- **Direct Quick Logout Button:** Added dedicated `.btn-header-logout` button directly visible in the top header with a red hover state.
- **Sidebar Logout Integration:** Added direct logout action in the navigation sidebar with session confirmation modal.
- Handled state transitions: logging out clears session tokens, hides the profile and quick logout buttons, and displays the direct "Sign In" button.

### Milestone 5: Adaptive Theme Synchronization (Dark & Light Mode)
- Fixed issue where the enterprise header remained dark when light mode was selected.
- Extracted dynamic CSS variables for both `:root[data-theme="dark"]` and `:root[data-theme="light"]`:
  - `--header-bg`: `rgba(15, 23, 42, 0.88)` (Dark) / `rgba(255, 255, 255, 0.94)` (Light).
  - `--header-card-bg`: `rgba(255, 255, 255, 0.03)` (Dark) / `#f87171` or `#f8fafc` (Light).
  - `--header-card-border`: `#1e293b` (Dark) / `#e2e8f0` (Light).
  - Dynamic button hover styling for Red Team lab, quick logout, and shortcuts.

### Milestone 6: Official Branding & Favicon Pipeline
- Extracted official Kavalan Cyber Shield SVG, PNG, and ICO brand assets from `/Users/shiyamsundars/Downloads/Kavalan/kavalan-siem/dashboard/static/` into `public/`.
- Configured dedicated Express routes in `server.ts` serving genuine MIME types:
  - `/favicon.ico` -> `image/x-icon`
  - `/favicon.svg` -> `image/svg+xml`
- Updated breadcrumb header to display the official Kavalan Cyber Shield logo mark next to `Kavalan Sentinel`.

### Milestone 7: Responsive Top Header Overhaul
- **Layout Streamlining:**
  - Resolved horizontal overflow on laptops and compact viewports caused by combined width of left, center, and right controls exceeding workspace bounds.
  - Bounded breadcrumb trail (`max-width: 360px`, `min-width: 0`) with text ellipsis.
  - Responsive breakpoints:
    - `@media (max-width: 1360px)`: Hides center pipeline telemetry capsule (`.top-header-center`).
    - `@media (max-width: 1100px)`: Compacts button text labels (`Red Team`, `Keys`) and reduces padding.
    - `@media (max-width: 860px)`: Hides live telemetry pill and breadcrumb root.
    - `@media (max-width: 680px)`: Preserves core header actions while hiding secondary utilities.
- **Unauthenticated State ("Sign In" Button):**
  - Added `#btn-header-signin` in `.top-header-right`.
  - When logged out, the user avatar and logout buttons cleanly swap for the "Sign In" action.

### Milestone 8: 1-Click Multi-IP Rotating AI Agent Campaign (Strix Benchmark)
- **Engine Simulation (`src/store.ts`):**
  - Added full multi-stage autonomous AI agent killchain rotating across 6 ephemeral cloud IPs:
    - **Node 1 (185.220.101.41):** Reconnaissance sweep (`/.env`, `/.git/config`, `/tokens`, `/backup.zip`).
    - **Node 2 (45.155.205.88):** SQL Injection UNION & login bypass payloads.
    - **Node 3 (91.214.124.19):** Directory & Path Traversal (`/etc/passwd`, `/etc/shadow`, `/proc/self/environ`).
    - **Node 4 (198.51.100.142):** Cloud Metadata SSRF queries targeting AWS IMDS (`169.254.169.254`).
    - **Node 5 (203.0.113.177):** AWS CloudTrail API Evasion (`ListBuckets`, `GetCallerIdentity`, `StopLogging`).
    - **Node 6 (172.64.155.33):** Kubernetes Privileged Pod creation (`privileged: true`) + MCP Tool-Call prompt injection (`execute_sql`).
  - Concurrently injected 30 benign normal human shopper events (`192.0.2.50-54` hitting `/products`, `/cart`, `/checkout`).
- **Correlation & Collapse Engine:**
  - Automatically correlates all 6 rotating cloud IPs into **1 Unified Critical Campaign Alert (`Rule 100400`)**.
  - Automatically folds/suppresses individual per-IP sub-alerts into the master campaign alert to eliminate alert fatigue.
  - Verifies that concurrent human shopper transactions score **0 False Positives (100% Precision)**.
- **Console UI Integration (`public/index.html`):**
  - Added top header button `#btn-strix-hdr` ("Strix Benchmark").
  - Added Overview HUD Hero Callout Card with 1-click trigger button.
  - Added primary Red Team simulation card in `tab-graph`.
  - Added dedicated Strix Benchmark campaign banner in `tab-sec` (Security Alerts queue).
  - Implemented `triggerStrixBenchmark()` with live stage-by-stage terminal logging and automatic triage selection.

---

## 3. Key Files & Directory Structure

| File / Directory | Description |
|---|---|
| [`server.ts`](file:///Users/shiyamsundars/Kavalan_Gemini/server.ts) | Primary Express backend server (APIs for state, agents, alerts, auth, SQLite integration, and static routing). |
| [`public/index.html`](file:///Users/shiyamsundars/Kavalan_Gemini/public/index.html) | Complete Enterprise SOC single-page frontend console (HUD, tabs, top header, styling, and JavaScript logic). |
| [`src/db.ts`](file:///Users/shiyamsundars/Kavalan_Gemini/src/db.ts) | SQLite database manager, migrations, foreign key constraints, and query functions. |
| [`data/kavalan_siem.db`](file:///Users/shiyamsundars/Kavalan_Gemini/data/kavalan_siem.db) | Production SQLite WAL database containing alerts, fleet endpoints, incidents, rules, and audit trails. |
| [`public/favicon.svg`](file:///Users/shiyamsundars/Kavalan_Gemini/public/favicon.svg) | Official Kavalan Cyber Shield vector asset. |
| [`public/favicon.ico`](file:///Users/shiyamsundars/Kavalan_Gemini/public/favicon.ico) | Standard browser favicon binary. |
| [`src/gemini.ts`](file:///Users/shiyamsundars/Kavalan_Gemini/src/gemini.ts) | Google Gemini AI pipeline for SOC alert attribution and threat intelligence analysis. |

---

## 4. Git Commit History Reference

| Commit Hash | Commit Message Summary |
|---|---|
| `66ea0b1` | `fix(ui): optimize top header layout, responsive breakpoints, and sign-in state` |
| `c915730` | `feat(ui): add Kavalan logo mark favicon assets and update favicon routes` |
| `ac84012` | `fix(auth): define showLoginOverlay, quickFillLogin, and applyRbacUiPermissions` |
| `532ca04` | `feat(ui): add direct quick logout button to top header bar` |
| `be884ad` | `feat(db): integrate SQLite database for persistent SIEM state and load production data` |
| `97084a8` | `fix(ui): dynamic theme support for enterprise header and profile dropdown in light mode` |
| `f6d3149` | `feat(ui): redesign enterprise SOC top header and user profile widget` |
| `87f3375` | `feat(rbac): add dedicated Identity & RBAC tab and enforce strict sidebar role-based visibility` |
| `b195e9e` | `feat(auth): add enterprise login & logout portal with RBAC and UI enforcement` |
| `5d8c6c1` | `feat(phase-1): enterprise SOC foundation - RBAC auth, audit trail, agent HMAC, CERT-In reporting` |
| `4a5002b` | `feat: Integrate Google Gemini AI, remove self-made LLM, and update SIEM architecture` |

---

## 5. Operations & Development Cheat Sheet

```bash
# Install dependencies
npm install

# Run development server with live reload on Port 3000
npm run dev

# Run TypeScript compile validation
npm run build

# Verify server health and state API
curl -sI http://localhost:3000/
curl -s http://localhost:3000/api/state | jq .

# Verify favicon endpoints
curl -sI http://localhost:3000/favicon.ico
curl -sI http://localhost:3000/favicon.svg
```

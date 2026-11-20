import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import {
  ActiveResponseOrder,
  Agent,
  CaseNote,
  CustomRule,
  IncidentCase,
  IndexedEvent,
  SCACheck,
  SCAReport,
  SoarPlaybook,
  SoarPlaybookRun,
  ThreatIntelIOC,
  VulnerabilityFinding,
} from './types.js';
import type { AlertRecord } from './store.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.resolve(__dirname, '..', 'data');

export interface DatabaseStats {
  indexer_db_size_bytes: number;
  manager_db_size_bytes: number;
  kavalan_db_size_bytes: number;
  total_events: number;
  total_alerts: number;
  total_cases: number;
  total_active_responses: number;
  total_playbook_runs: number;
  total_threat_intel_iocs: number;
  total_vulnerabilities: number;
  total_agents: number;
}

export class KavalanDatabase {
  private indexerDb: DatabaseSync;
  private managerDb: DatabaseSync;
  private indexerPath: string;
  private managerPath: string;
  private kavalanPath: string;

  constructor() {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }

    this.indexerPath = path.join(DATA_DIR, 'indexer.db');
    this.managerPath = path.join(DATA_DIR, 'manager.db');
    this.kavalanPath = path.join(DATA_DIR, 'kavalan_siem.db');

    this.indexerDb = new DatabaseSync(this.indexerPath);
    this.managerDb = new DatabaseSync(this.managerPath);

    this.indexerDb.exec('PRAGMA journal_mode = WAL;');
    this.indexerDb.exec('PRAGMA synchronous = NORMAL;');
    this.managerDb.exec('PRAGMA journal_mode = WAL;');
    this.managerDb.exec('PRAGMA synchronous = NORMAL;');

    this.ensureTables();
  }

  private ensureTables(): void {
    this.indexerDb.exec(`
      CREATE TABLE IF NOT EXISTS events_index (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER NOT NULL,
        agent_id TEXT NOT NULL,
        host TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        log_type TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT NOT NULL,
        outcome TEXT NOT NULL,
        status INTEGER,
        user TEXT,
        tactics_json TEXT,
        raw TEXT,
        meta_json TEXT
      );
      CREATE TABLE IF NOT EXISTS alerts_index (
        id TEXT PRIMARY KEY,
        timestamp INTEGER NOT NULL,
        level TEXT NOT NULL,
        type TEXT NOT NULL,
        agent_id TEXT,
        source_ip TEXT,
        summary TEXT NOT NULL,
        mitre_tactics TEXT,
        detail_json TEXT NOT NULL,
        status TEXT DEFAULT 'new'
      );
      CREATE TABLE IF NOT EXISTS threat_intel_iocs (
        ioc TEXT PRIMARY KEY,
        ioc_type TEXT NOT NULL DEFAULT 'ip',
        threat_score INTEGER NOT NULL DEFAULT 0,
        threat_level TEXT NOT NULL DEFAULT 'LOW',
        reputation TEXT NOT NULL DEFAULT 'NEUTRAL',
        feed TEXT NOT NULL DEFAULT 'Kavalan Threat Cloud',
        categories_json TEXT NOT NULL DEFAULT '[]',
        country TEXT NOT NULL DEFAULT 'XX',
        country_name TEXT NOT NULL DEFAULT 'Unknown Country',
        asn TEXT NOT NULL DEFAULT 'AS0 Unknown',
        is_tor_exit INTEGER NOT NULL DEFAULT 0,
        is_vpn_proxy INTEGER NOT NULL DEFAULT 0,
        description TEXT,
        reports_count INTEGER NOT NULL DEFAULT 1,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL
      );
    `);

    this.managerDb.exec(`
      CREATE TABLE IF NOT EXISTS agents (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        ip TEXT NOT NULL,
        os TEXT,
        registered_at INTEGER NOT NULL,
        last_keepalive INTEGER NOT NULL,
        status TEXT DEFAULT 'active',
        metrics_json TEXT
      );
      CREATE TABLE IF NOT EXISTS incident_cases (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        severity TEXT NOT NULL DEFAULT 'HIGH',
        status TEXT NOT NULL DEFAULT 'NEW',
        assignee TEXT DEFAULT 'Unassigned',
        entities_json TEXT DEFAULT '{}',
        playbooks_run_json TEXT DEFAULT '[]',
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS case_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT NOT NULL,
        author TEXT NOT NULL DEFAULT 'SOC Analyst',
        note TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS active_responses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER NOT NULL,
        command TEXT NOT NULL,
        actor_ip TEXT NOT NULL,
        rule_id INTEGER NOT NULL,
        rule_level INTEGER NOT NULL,
        reason TEXT NOT NULL,
        status TEXT DEFAULT 'executed',
        target_agent TEXT DEFAULT 'all',
        delivered INTEGER DEFAULT 0,
        details TEXT DEFAULT ''
      );
      CREATE TABLE IF NOT EXISTS soar_playbooks (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        trigger_type TEXT NOT NULL DEFAULT 'alert',
        condition_json TEXT NOT NULL,
        actions_json TEXT NOT NULL,
        is_enabled INTEGER NOT NULL DEFAULT 1,
        execution_count INTEGER NOT NULL DEFAULT 0,
        last_triggered_at INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS soar_playbook_runs (
        id TEXT PRIMARY KEY,
        playbook_id TEXT NOT NULL,
        playbook_name TEXT NOT NULL,
        trigger_source TEXT NOT NULL,
        trigger_entity TEXT,
        status TEXT NOT NULL,
        actions_taken_json TEXT NOT NULL,
        output_log TEXT,
        executed_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS custom_rules (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        level INTEGER NOT NULL DEFAULT 7,
        log_type TEXT NOT NULL DEFAULT '*',
        rule_json TEXT NOT NULL,
        raw_sigma TEXT,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS agent_sca_reports (
        agent_id TEXT PRIMARY KEY,
        host TEXT NOT NULL,
        score REAL NOT NULL,
        total_checks INTEGER NOT NULL,
        passed INTEGER NOT NULL,
        failed INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        checks_json TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS agent_vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id TEXT NOT NULL,
        host TEXT NOT NULL,
        cve_id TEXT NOT NULL,
        package TEXT NOT NULL,
        installed_version TEXT NOT NULL,
        fixed_version TEXT NOT NULL,
        severity TEXT NOT NULL,
        cvss REAL NOT NULL,
        title TEXT NOT NULL,
        remediation TEXT NOT NULL,
        mitre_id TEXT NOT NULL,
        discovered_at INTEGER NOT NULL,
        UNIQUE(agent_id, cve_id)
      );
    `);
  }

  // --- Statistics ---

  public getStats(): DatabaseStats {
    const evCount = (this.indexerDb.prepare('SELECT count(*) as c FROM events_index').get() as any)?.c || 0;
    const alCount = (this.indexerDb.prepare('SELECT count(*) as c FROM alerts_index').get() as any)?.c || 0;
    const csCount = (this.managerDb.prepare('SELECT count(*) as c FROM incident_cases').get() as any)?.c || 0;
    const arCount = (this.managerDb.prepare('SELECT count(*) as c FROM active_responses').get() as any)?.c || 0;
    const pbCount = (this.managerDb.prepare('SELECT count(*) as c FROM soar_playbook_runs').get() as any)?.c || 0;
    const tiCount = (this.indexerDb.prepare('SELECT count(*) as c FROM threat_intel_iocs').get() as any)?.c || 0;
    const vlCount = (this.managerDb.prepare('SELECT count(*) as c FROM agent_vulnerabilities').get() as any)?.c || 0;
    const agCount = (this.managerDb.prepare('SELECT count(*) as c FROM agents').get() as any)?.c || 0;

    return {
      indexer_db_size_bytes: fs.existsSync(this.indexerPath) ? fs.statSync(this.indexerPath).size : 0,
      manager_db_size_bytes: fs.existsSync(this.managerPath) ? fs.statSync(this.managerPath).size : 0,
      kavalan_db_size_bytes: fs.existsSync(this.kavalanPath) ? fs.statSync(this.kavalanPath).size : 0,
      total_events: Number(evCount),
      total_alerts: Number(alCount),
      total_cases: Number(csCount),
      total_active_responses: Number(arCount),
      total_playbook_runs: Number(pbCount),
      total_threat_intel_iocs: Number(tiCount),
      total_vulnerabilities: Number(vlCount),
      total_agents: Number(agCount),
    };
  }

  // --- Events ---

  public loadRecentEvents(limit = 15000): IndexedEvent[] {
    const rows = this.indexerDb
      .prepare('SELECT * FROM events_index ORDER BY timestamp DESC, id DESC LIMIT ?')
      .all(limit) as any[];

    return rows.reverse().map((r) => {
      let tactics: Record<string, number> = {};
      let meta: Record<string, any> = {};
      try {
        if (r.tactics_json) tactics = JSON.parse(r.tactics_json);
      } catch {
        /* ignore parse error */
      }
      try {
        if (r.meta_json) meta = JSON.parse(r.meta_json);
      } catch {
        /* ignore parse error */
      }

      return {
        id: Number(r.id),
        timestamp: Number(r.timestamp),
        ingest_timestamp: Number(r.timestamp),
        ingest_lag_ms: 22,
        agent_id: String(r.agent_id || '001'),
        host: String(r.host || 'web-01'),
        source_ip: String(r.source_ip || '127.0.0.1'),
        log_type: String(r.log_type || 'system'),
        action: String(r.action || 'activity'),
        target: String(r.target || '/'),
        outcome: String(r.outcome || 'ok'),
        status: r.status !== null && r.status !== undefined ? Number(r.status) : 200,
        user: r.user ? String(r.user) : null,
        tactics,
        raw: r.raw ? String(r.raw) : null,
        meta,
      };
    });
  }

  public insertEvent(ev: IndexedEvent): void {
    try {
      const stmt = this.indexerDb.prepare(`
        INSERT INTO events_index (
          timestamp, agent_id, host, source_ip, log_type, action, target, outcome, status, user, tactics_json, raw, meta_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      stmt.run(
        ev.timestamp,
        ev.agent_id,
        ev.host,
        ev.source_ip,
        ev.log_type,
        ev.action,
        ev.target,
        ev.outcome,
        ev.status ?? null,
        ev.user ?? null,
        JSON.stringify(ev.tactics || {}),
        ev.raw ?? null,
        JSON.stringify(ev.meta || {})
      );
    } catch (err) {
      console.error('[KavalanDatabase] Error inserting event:', err);
    }
  }

  // --- Alerts ---

  public loadAllAlerts(): AlertRecord[] {
    const rows = this.indexerDb
      .prepare('SELECT * FROM alerts_index ORDER BY timestamp DESC LIMIT 5000')
      .all() as any[];

    let currentNumericId = 1;

    return rows.map((row) => {
      let detail: any = {};
      try {
        if (row.detail_json) detail = JSON.parse(row.detail_json);
      } catch {
        /* ignore */
      }

      let levelStr = String(row.level || detail.level || 'MEDIUM').toUpperCase();
      if (levelStr === '15' || levelStr === '13' || Number(levelStr) >= 12) levelStr = 'CRITICAL';
      else if (levelStr === '10' || levelStr === '11' || Number(levelStr) >= 9) levelStr = 'HIGH';
      else if (levelStr === '7' || levelStr === '8' || Number(levelStr) >= 5) levelStr = 'MEDIUM';

      const summaryText =
        row.summary ||
        detail.description ||
        detail.summary ||
        detail.reason ||
        `Security Alert: ${row.type || 'Detection'}`;

      const alertRecord: AlertRecord = {
        id: currentNumericId++,
        campaign_key: String(row.id || detail.key || `alert:${row.source_ip || currentNumericId}`),
        timestamp: Number(row.timestamp || detail.timestamp || Math.floor(Date.now() / 1000)),
        first_seen: Number(detail.first_seen || row.timestamp),
        last_seen: Number(detail.last_seen || row.timestamp),
        event_time: Number(detail.event_time || row.timestamp),
        ingest_time: Number(detail.ingest_time || row.timestamp),
        ingest_lag_ms: Number(detail.ingest_lag_ms || 24),
        count: Number(
          detail.count ||
            (detail.tactics
              ? Object.values(detail.tactics).reduce((a: any, b: any) => a + Number(b), 0)
              : 1)
        ),
        level: levelStr,
        type: String(row.type || detail.type || 'security_alert'),
        agent_id: String(row.agent_id || detail.agent_id || '001'),
        host: String(detail.host || (detail.hosts && detail.hosts[0]) || 'web-01'),
        source_ip: String(row.source_ip || detail.source_ip || '10.0.0.1'),
        summary: summaryText,
        triage_status: row.status === 'closed' || row.status === 'suppressed' ? row.status : 'open',
        suppression_id: detail.suppression_id || null,
        feedback: detail.feedback || null,
        feedback_by: detail.feedback_by || null,
        feedback_at: detail.feedback_at || null,
        feedback_note: detail.feedback_note || null,
        rule_id: Number(
          detail.rule_id || (levelStr === 'CRITICAL' ? 100300 : levelStr === 'HIGH' ? 100200 : 100100)
        ),
        rule_level: Number(detail.rule_level || (levelStr === 'CRITICAL' ? 15 : levelStr === 'HIGH' ? 10 : 7)),
        rule_name: String(
          detail.rule_name || (detail.rule_matches && detail.rule_matches[0]?.name) || 'siem_security_alert'
        ),
        reasons: Array.isArray(detail.reasons) ? detail.reasons : [summaryText],
        score_breakdown: Array.isArray(detail.score_breakdown) ? detail.score_breakdown : [],
        outcome_verdict:
          detail.outcome_verdict || (levelStr === 'CRITICAL' ? 'COMPROMISED' : 'EXPLOIT ATTEMPTED'),
        asset_info: detail.asset_info || {
          agent_id: String(row.agent_id || '001'),
          host: String(detail.host || (detail.hosts && detail.hosts[0]) || 'web-01'),
          ip: String(row.source_ip || '10.0.0.1'),
          os: 'Linux Ubuntu 22.04 LTS',
          criticality: 'TIER-1 CORE',
          owner: 'Security Operations',
        },
        mitre_tactics: detail.mitre_tactics || {},
        attack_path: Array.isArray(detail.attack_path) ? detail.attack_path : [],
        raw_logs: Array.isArray(detail.raw_logs) ? detail.raw_logs : [],
        sample_event_ids: Array.isArray(detail.sample_event_ids) ? detail.sample_event_ids : [],
        linked_case_id: detail.linked_case_id || null,
        detail: detail,
      };

      return alertRecord;
    });
  }

  public saveAlert(alert: AlertRecord): void {
    try {
      const stmt = this.indexerDb.prepare(`
        INSERT INTO alerts_index (
          id, timestamp, level, type, agent_id, source_ip, summary, mitre_tactics, detail_json, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          timestamp=excluded.timestamp,
          level=excluded.level,
          summary=excluded.summary,
          detail_json=excluded.detail_json,
          status=excluded.status
      `);
      stmt.run(
        alert.campaign_key,
        alert.timestamp,
        alert.level,
        alert.type,
        alert.agent_id,
        alert.source_ip,
        alert.summary,
        JSON.stringify(alert.mitre_tactics || {}),
        JSON.stringify(alert),
        alert.triage_status
      );
    } catch (err) {
      console.error('[KavalanDatabase] Error saving alert:', err);
    }
  }

  public updateAlertStatus(campaignKey: string, status: 'open' | 'suppressed' | 'closed'): void {
    try {
      this.indexerDb
        .prepare('UPDATE alerts_index SET status = ? WHERE id = ?')
        .run(status, campaignKey);
    } catch (err) {
      console.error('[KavalanDatabase] Error updating alert status:', err);
    }
  }

  // --- Agents ---

  public loadAllAgents(): Agent[] {
    const rows = this.managerDb.prepare('SELECT * FROM agents').all() as any[];
    return rows.map((r) => {
      let metrics = undefined;
      try {
        if (r.metrics_json) metrics = JSON.parse(r.metrics_json);
      } catch {
        /* ignore */
      }
      return {
        id: String(r.id),
        name: String(r.name),
        ip: String(r.ip),
        os: r.os ? String(r.os) : 'Linux',
        registered_at: Number(r.registered_at),
        last_keepalive: Number(r.last_keepalive),
        status: (r.status === 'inactive' || r.status === 'offline' ? r.status : 'active') as Agent['status'],
        metrics,
        version: '1.4.2-enterprise',
        tamper_alert: false,
      };
    });
  }

  public saveAgent(agent: Agent): void {
    try {
      const stmt = this.managerDb.prepare(`
        INSERT INTO agents (id, name, ip, os, registered_at, last_keepalive, status, metrics_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          name=excluded.name,
          ip=excluded.ip,
          os=excluded.os,
          last_keepalive=excluded.last_keepalive,
          status=excluded.status,
          metrics_json=excluded.metrics_json
      `);
      stmt.run(
        agent.id,
        agent.name,
        agent.ip,
        agent.os || 'Linux',
        agent.registered_at,
        agent.last_keepalive,
        agent.status,
        JSON.stringify(agent.metrics || {})
      );
    } catch (err) {
      console.error('[KavalanDatabase] Error saving agent:', err);
    }
  }

  // --- Incident Cases & Notes ---

  public loadAllCases(): IncidentCase[] {
    const casesRows = this.managerDb.prepare('SELECT * FROM incident_cases ORDER BY created_at DESC').all() as any[];
    const notesRows = this.managerDb.prepare('SELECT * FROM case_notes ORDER BY created_at ASC').all() as any[];

    const notesByCase = new Map<string, CaseNote[]>();
    for (const nr of notesRows) {
      const cid = String(nr.case_id);
      if (!notesByCase.has(cid)) notesByCase.set(cid, []);
      notesByCase.get(cid)!.push({
        id: Number(nr.id),
        author: String(nr.author || 'SOC Analyst'),
        note: String(nr.note),
        created_at: Number(nr.created_at),
      });
    }

    return casesRows.map((cr) => {
      let entities = {};
      let playbooksRun = [];
      try {
        if (cr.entities_json) entities = JSON.parse(cr.entities_json);
      } catch {
        /* ignore */
      }
      try {
        if (cr.playbooks_run_json) playbooksRun = JSON.parse(cr.playbooks_run_json);
      } catch {
        /* ignore */
      }

      const caseId = String(cr.id);
      const notes = notesByCase.get(caseId) || [];

      return {
        id: caseId,
        title: String(cr.title),
        description: String(cr.description || ''),
        severity: String(cr.severity || 'HIGH').toUpperCase(),
        status: String(cr.status || 'NEW').toUpperCase(),
        assignee: String(cr.assignee || 'Unassigned'),
        sla_due_at: Number(cr.created_at) + 3600 * 4,
        linked_alert_ids: [],
        timeline: [],
        evidence: [],
        entities,
        playbooks_run: playbooksRun,
        notes,
        notes_count: notes.length,
        created_at: Number(cr.created_at),
        updated_at: Number(cr.updated_at),
      };
    });
  }

  public saveCase(c: IncidentCase): void {
    try {
      const stmt = this.managerDb.prepare(`
        INSERT INTO incident_cases (
          id, title, description, severity, status, assignee, entities_json, playbooks_run_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          title=excluded.title,
          description=excluded.description,
          severity=excluded.severity,
          status=excluded.status,
          assignee=excluded.assignee,
          entities_json=excluded.entities_json,
          playbooks_run_json=excluded.playbooks_run_json,
          updated_at=excluded.updated_at
      `);
      stmt.run(
        c.id,
        c.title,
        c.description || '',
        c.severity,
        c.status,
        c.assignee,
        JSON.stringify(c.entities || {}),
        JSON.stringify(c.playbooks_run || []),
        c.created_at,
        c.updated_at
      );
    } catch (err) {
      console.error('[KavalanDatabase] Error saving case:', err);
    }
  }

  public insertCaseNote(note: { case_id: string; author: string; note: string; created_at: number }): number {
    try {
      const stmt = this.managerDb.prepare(`
        INSERT INTO case_notes (case_id, author, note, created_at)
        VALUES (?, ?, ?, ?)
      `);
      const info = stmt.run(note.case_id, note.author, note.note, note.created_at);
      return Number(info.lastInsertRowid);
    } catch (err) {
      console.error('[KavalanDatabase] Error saving case note:', err);
      return 0;
    }
  }

  // --- Active Response History ---

  public loadAllActiveResponses(): ActiveResponseOrder[] {
    const rows = this.managerDb.prepare('SELECT * FROM active_responses ORDER BY timestamp DESC LIMIT 1000').all() as any[];

    return rows.map((r) => ({
      id: Number(r.id),
      timestamp: Number(r.timestamp),
      command: String(r.command),
      actor_ip: String(r.actor_ip),
      rule_id: Number(r.rule_id),
      rule_level: Number(r.rule_level),
      reason: String(r.reason),
      status: (r.status === 'recommended' || r.status === 'approved' || r.status === 'rejected'
        ? r.status
        : 'executed') as ActiveResponseOrder['status'],
      target_agent: String(r.target_agent || 'all'),
      delivered: Boolean(r.delivered),
      ttl_seconds: 3600,
      expires_at: Number(r.timestamp) + 3600,
      recommended_by: 'Autonomous SOAR Engine',
      approved_by: 'SOC Operator',
      approved_at: Number(r.timestamp),
      audit_trail: [
        {
          timestamp: Number(r.timestamp),
          actor: 'Kavalan Autonomous Defense',
          action: 'ACTION_EXECUTED',
          note: `Triggered by rule ${r.rule_id} (${r.reason})`,
        },
      ],
      details: String(r.details || ''),
    }));
  }

  public saveActiveResponse(order: ActiveResponseOrder): void {
    try {
      const stmt = this.managerDb.prepare(`
        INSERT INTO active_responses (
          id, timestamp, command, actor_ip, rule_id, rule_level, reason, status, target_agent, delivered, details
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          status=excluded.status,
          delivered=excluded.delivered,
          details=excluded.details
      `);
      stmt.run(
        order.id,
        order.timestamp,
        order.command,
        order.actor_ip,
        order.rule_id,
        order.rule_level,
        order.reason,
        order.status,
        order.target_agent || 'all',
        order.delivered ? 1 : 0,
        order.details || ''
      );
    } catch (err) {
      console.error('[KavalanDatabase] Error saving active response:', err);
    }
  }

  // --- SOAR Playbooks & Runs ---

  public loadAllPlaybooks(): SoarPlaybook[] {
    const rows = this.managerDb.prepare('SELECT * FROM soar_playbooks').all() as any[];
    return rows.map((r) => {
      let cond = {};
      let acts = [];
      try {
        if (r.condition_json) cond = JSON.parse(r.condition_json);
      } catch {
        /* ignore */
      }
      try {
        if (r.actions_json) acts = JSON.parse(r.actions_json);
      } catch {
        /* ignore */
      }
      return {
        id: String(r.id),
        name: String(r.name),
        description: String(r.description || ''),
        trigger_type: (r.trigger_type || 'alert') as any,
        condition: cond as any,
        actions: acts as any,
        is_enabled: Boolean(r.is_enabled),
        execution_count: Number(r.execution_count || 0),
        last_triggered_at: r.last_triggered_at ? Number(r.last_triggered_at) : null,
        created_at: Number(r.created_at),
        updated_at: Number(r.updated_at),
      };
    });
  }

  public loadAllPlaybookRuns(): SoarPlaybookRun[] {
    const rows = this.managerDb.prepare('SELECT * FROM soar_playbook_runs ORDER BY executed_at DESC LIMIT 200').all() as any[];
    return rows.map((r) => {
      let acts: string[] = [];
      try {
        if (r.actions_taken_json) acts = JSON.parse(r.actions_taken_json);
      } catch {
        /* ignore */
      }
      return {
        id: String(r.id),
        playbook_id: String(r.playbook_id),
        playbook_name: String(r.playbook_name),
        trigger_source: String(r.trigger_source),
        trigger_entity: String(r.trigger_entity || 'N/A'),
        status: String(r.status || 'SUCCESS'),
        actions_taken: acts,
        output_log: String(r.output_log || ''),
        executed_at: Number(r.executed_at),
      };
    });
  }

  public savePlaybookRun(run: SoarPlaybookRun): void {
    try {
      const stmt = this.managerDb.prepare(`
        INSERT INTO soar_playbook_runs (
          id, playbook_id, playbook_name, trigger_source, trigger_entity, status, actions_taken_json, output_log, executed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      stmt.run(
        run.id,
        run.playbook_id,
        run.playbook_name,
        run.trigger_source,
        run.trigger_entity || null,
        run.status,
        JSON.stringify(run.actions_taken || []),
        run.output_log || '',
        run.executed_at
      );
    } catch (err) {
      console.error('[KavalanDatabase] Error saving playbook run:', err);
    }
  }

  // --- Threat Intel IOCs ---

  public loadAllThreatIntel(): ThreatIntelIOC[] {
    const rows = this.indexerDb.prepare('SELECT * FROM threat_intel_iocs').all() as any[];
    return rows.map((r) => {
      let cats: string[] = [];
      try {
        if (r.categories_json) cats = JSON.parse(r.categories_json);
      } catch {
        /* ignore */
      }
      return {
        found: true,
        ioc: String(r.ioc),
        ioc_type: (r.ioc_type || 'ip') as any,
        threat_score: Number(r.threat_score || 0),
        threat_level: String(r.threat_level || 'LOW').toUpperCase() as any,
        reputation: String(r.reputation || 'NEUTRAL').toUpperCase() as any,
        feed: String(r.feed || 'Kavalan Threat Cloud'),
        categories: cats,
        country: String(r.country || 'XX'),
        country_name: String(r.country_name || 'Unknown'),
        asn: String(r.asn || 'AS0 Unknown'),
        is_tor_exit: Boolean(r.is_tor_exit),
        is_vpn_proxy: Boolean(r.is_vpn_proxy),
        description: String(r.description || ''),
        reports_count: Number(r.reports_count || 1),
      };
    });
  }

  // --- Custom Rules ---

  public loadAllCustomRules(): CustomRule[] {
    const rows = this.managerDb.prepare('SELECT * FROM custom_rules').all() as any[];
    return rows.map((r) => {
      let rj: any = {};
      try {
        if (r.rule_json) rj = JSON.parse(r.rule_json);
      } catch {
        /* ignore */
      }
      return {
        id: Number(r.id),
        name: String(r.name),
        title: String(r.title || r.name),
        description: String(r.description || ''),
        level: Number(r.level || 7),
        log_type: String(r.log_type || '*'),
        match: rj.match || { target: rj.pattern || '*' },
        frequency: Number(rj.frequency || 1),
        timeframe_sec: Number(rj.timeframe_sec || 60),
        mitre_id: rj.mitre_id || null,
        mitre_tactic: rj.mitre_tactic || null,
        groups: Array.isArray(rj.groups) ? rj.groups : ['custom'],
        active_response: Boolean(rj.active_response || rj.action === 'block'),
        enabled: Boolean(r.enabled),
        raw_sigma: r.raw_sigma ? String(r.raw_sigma) : undefined,
        created_at: Number(r.created_at || Math.floor(Date.now() / 1000)),
        updated_at: Number(r.updated_at || Math.floor(Date.now() / 1000)),
      };
    });
  }

  public saveCustomRule(rule: CustomRule): void {
    try {
      const stmt = this.managerDb.prepare(`
        INSERT INTO custom_rules (id, name, title, description, level, log_type, rule_json, raw_sigma, enabled, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          name=excluded.name,
          title=excluded.title,
          description=excluded.description,
          level=excluded.level,
          log_type=excluded.log_type,
          rule_json=excluded.rule_json,
          raw_sigma=excluded.raw_sigma,
          enabled=excluded.enabled,
          updated_at=excluded.updated_at
      `);
      stmt.run(
        rule.id,
        rule.name,
        rule.title,
        rule.description,
        rule.level,
        rule.log_type,
        JSON.stringify(rule),
        rule.raw_sigma || null,
        rule.enabled ? 1 : 0,
        rule.created_at ?? Math.floor(Date.now() / 1000),
        rule.updated_at ?? Math.floor(Date.now() / 1000)
      );
    } catch (err) {
      console.error('[KavalanDatabase] Error saving custom rule:', err);
    }
  }

  public deleteCustomRule(id: number): void {
    try {
      this.managerDb.prepare('DELETE FROM custom_rules WHERE id = ?').run(id);
    } catch (err) {
      console.error('[KavalanDatabase] Error deleting custom rule:', err);
    }
  }

  // --- Vulnerabilities & SCA ---

  public loadAllVulnerabilities(): VulnerabilityFinding[] {
    const rows = this.managerDb.prepare('SELECT * FROM agent_vulnerabilities').all() as any[];
    return rows.map((r) => ({
      agent_id: String(r.agent_id),
      host: String(r.host),
      cve_id: String(r.cve_id),
      package: String(r.package),
      installed_version: String(r.installed_version),
      fixed_version: String(r.fixed_version),
      severity: String(r.severity) as any,
      cvss: Number(r.cvss),
      title: String(r.title),
      remediation: String(r.remediation),
      mitre_id: String(r.mitre_id),
      discovered_at: Number(r.discovered_at),
    }));
  }

  public loadAllScaReports(): SCAReport[] {
    const rows = this.managerDb.prepare('SELECT * FROM agent_sca_reports').all() as any[];
    return rows.map((r) => {
      let checks: SCACheck[] = [];
      try {
        if (r.checks_json) checks = JSON.parse(r.checks_json);
      } catch {
        /* ignore */
      }
      return {
        agent_id: String(r.agent_id),
        host: String(r.host),
        score: Number(r.score),
        total_checks: Number(r.total_checks),
        passed: Number(r.passed),
        failed: Number(r.failed),
        updated_at: Number(r.updated_at),
        checks,
      };
    });
  }

  public saveScaReport(report: SCAReport): void {
    try {
      const stmt = this.managerDb.prepare(`
        INSERT INTO agent_sca_reports (agent_id, host, score, total_checks, passed, failed, updated_at, checks_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(agent_id) DO UPDATE SET
          host=excluded.host,
          score=excluded.score,
          total_checks=excluded.total_checks,
          passed=excluded.passed,
          failed=excluded.failed,
          updated_at=excluded.updated_at,
          checks_json=excluded.checks_json
      `);
      stmt.run(
        report.agent_id,
        report.host,
        report.score,
        report.total_checks,
        report.passed,
        report.failed,
        report.updated_at,
        JSON.stringify(report.checks || [])
      );
    } catch (err) {
      console.error('[KavalanDatabase] Error saving SCA report:', err);
    }
  }

  public saveVulnerability(v: VulnerabilityFinding): void {
    try {
      const stmt = this.managerDb.prepare(`
        INSERT INTO agent_vulnerabilities (
          agent_id, host, cve_id, package, installed_version, fixed_version, severity, cvss, title, remediation, mitre_id, discovered_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(agent_id, cve_id) DO UPDATE SET
          host=excluded.host,
          installed_version=excluded.installed_version,
          fixed_version=excluded.fixed_version,
          severity=excluded.severity,
          cvss=excluded.cvss,
          title=excluded.title,
          remediation=excluded.remediation,
          mitre_id=excluded.mitre_id,
          discovered_at=excluded.discovered_at
      `);
      stmt.run(
        v.agent_id,
        v.host,
        v.cve_id,
        v.package,
        v.installed_version,
        v.fixed_version,
        v.severity,
        v.cvss,
        v.title,
        v.remediation,
        v.mitre_id,
        v.discovered_at
      );
    } catch (err) {
      console.error('[KavalanDatabase] Error saving vulnerability finding:', err);
    }
  }
}

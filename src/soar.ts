import {
  ActiveResponseOrder,
  SCACheck,
  SCAReport,
  SoarPlaybook,
  SoarPlaybookRun,
  ThreatIntelIOC,
  VulnerabilityFinding,
} from './types.js';

export class ThreatIntelEngine {
  private iocs = new Map<string, ThreatIntelIOC>();

  constructor() {
    this.seedDefaults();
  }

  private isPrivateOrLoopback(ip: string): { isPrivate: boolean; isLoopback: boolean } {
    const isLoopback = ip === '127.0.0.1' || ip === '::1' || ip === 'localhost';
    const parts = ip.split('.');
    const isPrivate =
      ip.startsWith('10.') ||
      ip.startsWith('192.168.') ||
      (ip.startsWith('172.') && parts.length === 4 && /^\d+$/.test(parts[1]) && Number(parts[1]) >= 16 && Number(parts[1]) <= 31);
    return { isPrivate, isLoopback };
  }

  private seedDefaults(): void {
    const now = Math.floor(Date.now() / 1000);
    const seedList: ThreatIntelIOC[] = [
      {
        ioc: '203.0.113.154',
        ioc_type: 'ip',
        threat_score: 98,
        threat_level: 'CRITICAL',
        reputation: 'MALICIOUS',
        feed: 'Kavalan Global Telemetry',
        categories: ['Autonomous AI Red Team', 'SSH Brute Force', 'Exploit Scanner'],
        country: 'RU',
        country_name: 'Russia',
        asn: 'AS197695 Reg.ru Hosting',
        is_tor_exit: true,
        is_vpn_proxy: false,
        description: 'Confirmed autonomous LLM-orchestrated scanner conducting cross-vector SQLi, LFI, SSRF & SSH credential brute force.',
        reports_count: 142,
      },
      {
        ioc: '203.0.113.150',
        ioc_type: 'ip',
        threat_score: 94,
        threat_level: 'CRITICAL',
        reputation: 'MALICIOUS',
        feed: 'AlienVault OTX',
        categories: ['Tor Exit Node', 'Web Application Attack', 'Credential Stuffing'],
        country: 'NL',
        country_name: 'Netherlands',
        asn: 'AS60781 LeaseWeb Netherlands',
        is_tor_exit: true,
        is_vpn_proxy: true,
        description: 'Active Tor exit relay flagged for aggressive OWASP API enumeration and unauthorized admin probing.',
        reports_count: 89,
      },
      {
        ioc: '203.0.113.210',
        ioc_type: 'ip',
        threat_score: 99,
        threat_level: 'CRITICAL',
        reputation: 'MALICIOUS',
        feed: 'CISA Known Exploited Infrastructure',
        categories: ['Ransomware Dropper', 'FIM Tampering', 'C2 Node'],
        country: 'KP',
        country_name: 'North Korea',
        asn: 'AS131279 Ryugyong Network',
        is_tor_exit: false,
        is_vpn_proxy: true,
        description: 'Attributed APT ransomware staging server modifying critical system binaries and dropping crypto lockers.',
        reports_count: 315,
      },
      {
        ioc: '198.51.100.150',
        ioc_type: 'ip',
        threat_score: 85,
        threat_level: 'HIGH',
        reputation: 'MALICIOUS',
        feed: 'AbuseIPDB Top 100',
        categories: ['Vulnerability Scanner', 'Directory Discovery', 'Port Scan'],
        country: 'CN',
        country_name: 'China',
        asn: 'AS4134 Chinanet Backbone',
        is_tor_exit: false,
        is_vpn_proxy: false,
        description: 'High-volume automated vulnerability scanner enumerating .env, .git/config, and internal endpoints.',
        reports_count: 64,
      },
      {
        ioc: '198.51.100.200',
        ioc_type: 'ip',
        threat_score: 88,
        threat_level: 'HIGH',
        reputation: 'MALICIOUS',
        feed: 'Emerging Threats Open',
        categories: ['SSH Brute Force', 'Botnet Worker'],
        country: 'BR',
        country_name: 'Brazil',
        asn: 'AS28573 Claro S.A.',
        is_tor_exit: false,
        is_vpn_proxy: true,
        description: 'Compromised VPS participating in distributed SSH dictionary campaigns targeting Linux servers.',
        reports_count: 112,
      },
      {
        ioc: '198.51.100.201',
        ioc_type: 'ip',
        threat_score: 82,
        threat_level: 'HIGH',
        reputation: 'MALICIOUS',
        feed: 'Spamhaus DROP',
        categories: ['Distributed SSH', 'Credential Access'],
        country: 'US',
        country_name: 'United States',
        asn: 'AS14061 DigitalOcean LLC',
        is_tor_exit: false,
        is_vpn_proxy: true,
        description: 'Cloud infrastructure hosting automated SSH password spraying workers.',
        reports_count: 45,
      },
      {
        ioc: '185.220.101.45',
        ioc_type: 'ip',
        threat_score: 91,
        threat_level: 'CRITICAL',
        reputation: 'MALICIOUS',
        feed: 'Tor Exit Relay List',
        categories: ['Tor Exit Node', 'SQL Injection', 'Anonymizer'],
        country: 'DE',
        country_name: 'Germany',
        asn: 'AS205100 F3 Netze e.V.',
        is_tor_exit: true,
        is_vpn_proxy: false,
        description: 'High-bandwidth Tor exit node commonly abused for anonymous SQLi and SSRF exploitation.',
        reports_count: 520,
      },
      {
        ioc: '45.155.205.99',
        ioc_type: 'ip',
        threat_score: 96,
        threat_level: 'CRITICAL',
        reputation: 'MALICIOUS',
        feed: 'Feodo Tracker C2',
        categories: ['Botnet C2', 'Cobalt Strike', 'Malware'],
        country: 'UA',
        country_name: 'Ukraine',
        asn: 'AS49877 Petersburg Hosting',
        is_tor_exit: false,
        is_vpn_proxy: true,
        description: 'Command-and-control server linked to automated Linux backdoor implants.',
        reports_count: 78,
      },
      {
        ioc: '192.0.2.50',
        ioc_type: 'ip',
        threat_score: 5,
        threat_level: 'BENIGN',
        reputation: 'CLEAN',
        feed: 'Kavalan Allowlist',
        categories: ['Verified Corporate Traffic'],
        country: 'US',
        country_name: 'United States',
        asn: 'AS15169 Google LLC',
        is_tor_exit: false,
        is_vpn_proxy: false,
        description: 'Benign external baseline user telemetry.',
        reports_count: 0,
      },
      {
        ioc: '172.16.10.134',
        ioc_type: 'ip',
        threat_score: 0,
        threat_level: 'INTERNAL',
        reputation: 'INTERNAL_ASSET',
        feed: 'Enterprise Asset Registry',
        categories: ['Monitored Server Endpoint'],
        country: 'LAN',
        country_name: 'Internal Network (RFC 1918)',
        asn: 'AS64512 Enterprise LAN',
        is_tor_exit: false,
        is_vpn_proxy: false,
        description: 'Internal Ubuntu production web & SSH server protected by Kavalan Agent.',
        reports_count: 0,
      },
    ];

    for (const s of seedList) {
      this.iocs.set(s.ioc, { ...s, found: true, first_seen: now - 86400, last_seen: now });
    }
  }

  addIoc(data: Partial<ThreatIntelIOC> & { ioc: string }): ThreatIntelIOC {
    const now = Math.floor(Date.now() / 1000);
    const existing = this.iocs.get(data.ioc);
    const record: ThreatIntelIOC = {
      found: true,
      ioc: data.ioc,
      ioc_type: data.ioc_type || 'ip',
      threat_score: Number(data.threat_score ?? 50),
      threat_level: data.threat_level || 'HIGH',
      reputation: data.reputation || 'SUSPICIOUS',
      feed: data.feed || 'Custom Feed',
      categories: data.categories || ['Custom'],
      country: data.country || 'XX',
      country_name: data.country_name || 'Unknown',
      asn: data.asn || 'AS0 Unknown',
      is_tor_exit: Boolean(data.is_tor_exit),
      is_vpn_proxy: Boolean(data.is_vpn_proxy),
      description: data.description || 'Added manually via Threat Intelligence Manager.',
      reports_count: Number(data.reports_count ?? 1),
      first_seen: existing?.first_seen ?? now,
      last_seen: now,
    };
    this.iocs.set(record.ioc, record);
    return record;
  }

  lookup(ioc: string): ThreatIntelIOC {
    const { isPrivate, isLoopback } = this.isPrivateOrLoopback(ioc);
    const exact = this.iocs.get(ioc);
    if (exact) {
      return {
        ...exact,
        found: true,
        is_private: isPrivate || isLoopback,
        is_loopback: isLoopback,
      };
    }

    if (isPrivate || isLoopback) {
      return {
        found: false,
        ioc,
        ioc_type: 'ip',
        is_private: true,
        is_loopback: isLoopback,
        threat_score: 0,
        threat_level: 'INTERNAL',
        reputation: 'INTERNAL_ASSET',
        feed: 'RFC 1918 Private Network',
        categories: ['Internal LAN'],
        country: 'LAN',
        country_name: 'Internal Network (RFC 1918)',
        asn: 'AS64512 Internal Enterprise Network',
        is_tor_exit: false,
        is_vpn_proxy: false,
        description: 'Internal private network address (RFC 1918 / Loopback). Not exposed on public WAN threat feeds.',
        reports_count: 0,
      };
    }

    if (ioc.startsWith('203.0.113.') || ioc.startsWith('198.51.100.')) {
      const oct = Number(ioc.split('.').pop() || 0);
      const isCrit = oct >= 150;
      return {
        found: true,
        ioc,
        ioc_type: 'ip',
        is_private: false,
        is_loopback: false,
        threat_score: isCrit ? 90 : 75,
        threat_level: isCrit ? 'CRITICAL' : 'HIGH',
        reputation: 'MALICIOUS',
        feed: 'Kavalan Threat Intelligence Heuristic',
        categories: ['Red Team Simulation', 'Suspicious External Actor'],
        country: isCrit ? 'RU' : 'NL',
        country_name: isCrit ? 'Russia' : 'Netherlands',
        asn: isCrit ? 'AS49505 Selectel Hosting' : 'AS24940 Hetzner Online',
        is_tor_exit: oct > 180,
        is_vpn_proxy: true,
        description: 'Dynamic external threat actor IP observed on Kavalan honeypot sensors.',
        reports_count: 14 + (oct % 40),
      };
    }

    const geos: Array<[string, string, string]> = [
      ['US', 'United States', 'AS15169 Cloud Infrastructure'],
      ['DE', 'Germany', 'AS24940 Hetzner Online GmbH'],
      ['GB', 'United Kingdom', 'AS5089 Virgin Media'],
      ['SG', 'Singapore', 'AS16509 Amazon Data Services'],
      ['JP', 'Japan', 'AS2516 KDDI Corporation'],
    ];
    let hash = 0;
    for (let i = 0; i < ioc.length; i++) hash = (hash * 31 + ioc.charCodeAt(i)) >>> 0;
    const [cc, cn, asn] = geos[hash % geos.length];
    return {
      found: false,
      ioc,
      ioc_type: 'ip',
      is_private: false,
      is_loopback: false,
      threat_score: 12,
      threat_level: 'UNKNOWN',
      reputation: 'UNCATALOGED',
      feed: 'Global GeoIP Cache',
      categories: ['Public WAN'],
      country: cc,
      country_name: cn,
      asn,
      is_tor_exit: false,
      is_vpn_proxy: false,
      description: 'Public IP not currently flagged on major malicious Threat Intelligence blocklists.',
      reports_count: 0,
    };
  }

  getSummary(): Record<string, any> {
    const all = Array.from(this.iocs.values());
    const byLevel: Record<string, number> = {};
    let tor = 0;
    for (const item of all) {
      byLevel[item.threat_level] = (byLevel[item.threat_level] || 0) + 1;
      if (item.is_tor_exit) tor++;
    }
    return {
      total_iocs: all.length,
      by_threat_level: byLevel,
      tor_exits: tor,
      feeds_active: ['Kavalan Global Telemetry', 'AlienVault OTX', 'AbuseIPDB', 'Feodo Tracker', 'CISA KEV'],
    };
  }

  public loadFromDb(iocs: ThreatIntelIOC[]): void {
    for (const item of iocs) {
      this.iocs.set(item.ioc, item);
    }
  }
}

export class ActiveResponseEngine {
  private orders: ActiveResponseOrder[] = [];
  private nextId = 1;
  public onOrderChange?: (order: ActiveResponseOrder) => void;

  public loadFromDb(orders: ActiveResponseOrder[]): void {
    if (orders.length > 0) {
      this.orders = orders;
      const maxId = Math.max(0, ...orders.map((o) => o.id));
      this.nextId = maxId + 1;
    }
  }

  dryRunAction(params: {
    command: string;
    actor_ip: string;
    target_agent?: string;
    timeout_sec?: number;
  }): Record<string, any> {
    const cmd = params.command || 'firewall-drop';
    const target = params.actor_ip || '0.0.0.0';
    const targetAgent = params.target_agent || 'all';
    const ttl = Number(params.timeout_sec ?? 600);

    let shellPreview = `sudo iptables -I INPUT 1 -s ${target} -j DROP && sudo iptables -I OUTPUT 1 -d ${target} -j DROP`;
    let impact = `Drops inbound and outbound packets for ${target} on ${targetAgent === 'all' ? 'all active endpoints' : `agent ${targetAgent}`}.`;
    if (cmd === 'account-lock') {
      shellPreview = `sudo passwd -l ${target} && sudo pkill -u ${target}`;
      impact = `Locks user password and terminates active SSH/shell sessions for account '${target}'.`;
    } else if (cmd === 'account-unlock') {
      shellPreview = `sudo passwd -u ${target}`;
      impact = `Re-enables login capability for user '${target}'.`;
    } else if (cmd === 'isolate-host') {
      shellPreview = `sudo iptables -P INPUT DROP && sudo iptables -A INPUT -s <KAVALAN_MANAGER> -j ACCEPT`;
      impact = `Quarantines endpoint network interfaces while preserving Kavalan Manager control channel.`;
    } else if (cmd === 'quarantine-file') {
      shellPreview = `sudo chmod 000 ${target} && sudo mv ${target} /var/quarantine/`;
      impact = `Strips execution permissions and moves suspect artifact '${target}' into quarantine.`;
    } else if (cmd === 'kill-process') {
      shellPreview = `sudo kill -9 ${target}`;
      impact = `Terminates PID ${target} immediately.`;
    }

    return {
      dry_run: true,
      command: cmd,
      target,
      target_agent: targetAgent,
      ttl_seconds: ttl,
      reversible: cmd !== 'kill-process',
      shell_preview: shellPreview,
      estimated_impact: impact,
      rollback_command:
        cmd === 'firewall-drop'
          ? `sudo iptables -D INPUT -s ${target} -j DROP`
          : cmd === 'account-lock'
            ? `sudo passwd -u ${target}`
            : 'Manual restore from audit log',
    };
  }

  triggerAction(params: {
    command: string;
    actor_ip: string;
    rule_id?: number;
    rule_level?: number;
    reason?: string;
    target_agent?: string;
    timeout_sec?: number;
    mode?: 'recommend' | 'execute';
    actor?: string;
  }): ActiveResponseOrder {
    const now = Math.floor(Date.now() / 1000);
    const targetAgent = params.target_agent || 'all';
    const mode = params.mode || 'execute';
    const ttl = Number(params.timeout_sec ?? 600);
    const actor = params.actor || (mode === 'recommend' ? 'SOAR Recommendation' : 'Kavalan Automated Policy');

    const recent = this.orders.find(
      (o) =>
        o.actor_ip === params.actor_ip &&
        o.command === params.command &&
        o.target_agent === targetAgent &&
        o.status !== 'unblocked' &&
        o.status !== 'rejected' &&
        now - o.timestamp < 300
    );
    if (recent) return recent;

    const status: ActiveResponseOrder['status'] =
      mode === 'recommend' ? 'recommended' : targetAgent === 'all' ? 'executed' : 'pending';
    const expiresAt = ttl > 0 && status === 'executed' ? now + ttl : null;

    const order: ActiveResponseOrder = {
      id: this.nextId++,
      timestamp: now,
      command: params.command || 'firewall-drop',
      actor_ip: params.actor_ip,
      rule_id: params.rule_id ?? 0,
      rule_level: params.rule_level ?? 12,
      reason: params.reason || 'Automated SOC containment',
      status,
      target_agent: targetAgent,
      delivered: status === 'executed',
      ttl_seconds: ttl,
      expires_at: expiresAt,
      recommended_by: actor,
      approved_by: mode === 'execute' ? actor : null,
      approved_at: mode === 'execute' ? now : null,
      audit_trail: [
        {
          timestamp: now,
          actor,
          action: mode === 'recommend' ? 'RECOMMENDED' : 'EXECUTED',
          note: `${params.command || 'firewall-drop'} targeting ${params.actor_ip} (TTL ${ttl}s)`,
        },
      ],
      details: `Containment order ${params.command} targeting ${params.actor_ip} (TTL ${ttl}s)`,
    };
    this.orders.unshift(order);
    if (this.orders.length > 500) this.orders.length = 500;
    this.onOrderChange?.(order);
    return order;
  }

  approveAction(id: number, approver = 'SOC Analyst'): ActiveResponseOrder | null {
    const order = this.orders.find((o) => o.id === id);
    if (!order || order.status !== 'recommended') return null;
    const now = Math.floor(Date.now() / 1000);
    order.approved_by = approver;
    order.approved_at = now;
    order.status = order.target_agent === 'all' ? 'executed' : 'pending';
    order.delivered = order.target_agent === 'all';
    order.expires_at = order.ttl_seconds > 0 ? now + order.ttl_seconds : null;
    order.audit_trail.push({
      timestamp: now,
      actor: approver,
      action: 'APPROVED & DISPATCHED',
      note: `Approved by ${approver}; status=${order.status}`,
    });
    this.onOrderChange?.(order);
    return order;
  }

  rejectAction(id: number, actor = 'SOC Analyst', note = 'Rejected by analyst'): ActiveResponseOrder | null {
    const order = this.orders.find((o) => o.id === id);
    if (!order || order.status !== 'recommended') return null;
    const now = Math.floor(Date.now() / 1000);
    order.status = 'rejected';
    order.audit_trail.push({
      timestamp: now,
      actor,
      action: 'REJECTED',
      note,
    });
    this.onOrderChange?.(order);
    return order;
  }

  pollOrdersForAgent(agentId: string): ActiveResponseOrder[] {
    const pending: ActiveResponseOrder[] = [];
    const now = Math.floor(Date.now() / 1000);
    for (const o of this.orders) {
      if (o.status === 'pending' && !o.delivered && (o.target_agent === agentId || o.target_agent === 'all')) {
        o.delivered = true;
        o.status = 'executed';
        o.expires_at = o.ttl_seconds > 0 ? now + o.ttl_seconds : null;
        o.audit_trail.push({
          timestamp: now,
          actor: `agent-${agentId}`,
          action: 'AGENT_EXECUTED',
          note: `Endpoint ${agentId} confirmed local containment`,
        });
        pending.push(o);
        this.onOrderChange?.(o);
      }
    }
    return pending;
  }

  unblockAction(id: number, actor = 'SOC Analyst'): boolean {
    const order = this.orders.find((o) => o.id === id);
    if (!order) return false;
    const now = Math.floor(Date.now() / 1000);
    order.status = 'unblocked';
    order.expires_at = null;
    order.audit_trail.push({
      timestamp: now,
      actor,
      action: 'REVERSED / UNBLOCKED',
      note: `Containment reversed by ${actor}`,
    });
    order.details = `${order.details} | Released by ${actor} at ${new Date(now * 1000).toISOString()}`;
    this.onOrderChange?.(order);
    return true;
  }

  getAllActions(limit = 100): ActiveResponseOrder[] {
    const now = Math.floor(Date.now() / 1000);
    for (const o of this.orders) {
      if (o.status === 'executed' && o.expires_at && now >= o.expires_at) {
        o.status = 'unblocked';
        o.audit_trail.push({
          timestamp: now,
          actor: 'TTL Scheduler',
          action: 'TTL_EXPIRED',
          note: `Automatic TTL (${o.ttl_seconds}s) rollback completed`,
        });
      }
    }
    return this.orders.slice(0, limit);
  }
}

export interface SoarStoreHooks {
  executeContainment: (command: string, target: string, reason: string, targetAgent?: string) => void;
  createAutoCase: (params: {
    title: string;
    severity: string;
    description: string;
    entities: { ips: string[]; hosts: string[]; users: string[] };
  }) => string;
  dispatchWebhook: (eventType: string, payload: Record<string, any>) => number;
  onSaveRun?: (run: SoarPlaybookRun) => void;
}

export class AutonomousSoarPlaybookEngine {
  private playbooks = new Map<string, SoarPlaybook>();
  private runs: SoarPlaybookRun[] = [];
  private hooks: SoarStoreHooks;

  constructor(hooks: SoarStoreHooks) {
    this.hooks = hooks;
    this.seedDefaults();
  }

  public loadFromDb(playbooks: SoarPlaybook[], runs: SoarPlaybookRun[]): void {
    for (const pb of playbooks) {
      this.playbooks.set(pb.id, pb);
    }
    if (runs.length > 0) {
      this.runs = runs;
    }
  }

  private seedDefaults(): void {
    const now = Math.floor(Date.now() / 1000);
    const defaults: SoarPlaybook[] = [
      {
        id: 'PB-AUTO-001',
        name: 'Autonomous Critical Threat Containment & Case Escalation',
        description: 'Automatically drops malicious external IPs at firewall and opens CRITICAL Incident Case when threat rule level >= 12 fires.',
        trigger_type: 'alert',
        condition: { min_level: 12 },
        actions: [
          { action: 'active_response', cmd: 'firewall-drop', timeout: 3600 },
          { action: 'create_case', severity: 'CRITICAL', assignee: 'SOAR Autonomous Agent' },
          { action: 'webhook', event_type: 'critical_threat_contained' },
        ],
        is_enabled: true,
        execution_count: 0,
        last_triggered_at: null,
        created_at: now,
        updated_at: now,
      },
      {
        id: 'PB-AUTO-002',
        name: 'Ransomware / Critical FIM File Modification Lockout',
        description: 'Immediately isolates endpoint and dispatches urgent Slack/SIEM notification when critical system binaries (/etc/shadow, /etc/sudoers) are tampered.',
        trigger_type: 'alert',
        condition: { min_level: 10, keyword: 'fim' },
        actions: [
          { action: 'active_response', cmd: 'firewall-drop', timeout: 7200 },
          { action: 'create_case', severity: 'CRITICAL', assignee: 'DFIR Incident Lead' },
          { action: 'webhook', event_type: 'ransomware_fim_alert' },
        ],
        is_enabled: true,
        execution_count: 0,
        last_triggered_at: null,
        created_at: now,
        updated_at: now,
      },
      {
        id: 'PB-AUTO-003',
        name: 'High-Confidence Brute Force Mitigation',
        description: 'Automatically blocks source IP for 30 minutes when rapid SSH or Web credential brute force (Level >= 10) is attributed.',
        trigger_type: 'alert',
        condition: { min_level: 10, keyword: 'brute' },
        actions: [
          { action: 'active_response', cmd: 'firewall-drop', timeout: 1800 },
          { action: 'webhook', event_type: 'brute_force_mitigated' },
        ],
        is_enabled: true,
        execution_count: 0,
        last_triggered_at: null,
        created_at: now,
        updated_at: now,
      },
    ];
    for (const pb of defaults) {
      this.playbooks.set(pb.id, pb);
    }
  }

  listPlaybooks(): SoarPlaybook[] {
    return Array.from(this.playbooks.values());
  }

  togglePlaybook(id: string, enabled: boolean): boolean {
    const pb = this.playbooks.get(id);
    if (!pb) return false;
    pb.is_enabled = enabled;
    pb.updated_at = Math.floor(Date.now() / 1000);
    return true;
  }

  getRecentRuns(limit = 30): SoarPlaybookRun[] {
    return this.runs.slice(0, limit);
  }

  evaluateAlert(alertCtx: {
    level: number;
    actor_ip: string;
    host: string;
    target?: string;
    summary: string;
    rule_name?: string;
  }): SoarPlaybookRun[] {
    const executed: SoarPlaybookRun[] = [];
    const now = Math.floor(Date.now() / 1000);
    const hay = `${alertCtx.summary} ${alertCtx.rule_name || ''} ${alertCtx.target || ''}`.toLowerCase();

    for (const pb of this.playbooks.values()) {
      if (!pb.is_enabled) continue;
      const minLevel = Number(pb.condition.min_level ?? 10);
      if (alertCtx.level < minLevel) continue;
      const kw = pb.condition.keyword ? String(pb.condition.keyword).toLowerCase() : null;
      if (kw && !hay.includes(kw)) continue;

      if (pb.last_triggered_at && now - pb.last_triggered_at < 30 && this.runs[0]?.trigger_entity === alertCtx.actor_ip) {
        continue;
      }

      const run = this.executePlaybook(pb, 'auto-alert', alertCtx.actor_ip, alertCtx.host, alertCtx.summary);
      executed.push(run);
    }
    return executed;
  }

  runManual(id: string, target: string, host = 'server'): SoarPlaybookRun | null {
    const pb = this.playbooks.get(id);
    if (!pb) return null;
    return this.executePlaybook(pb, 'manual-trigger', target, host, `Manual SOC execution against ${target}`);
  }

  dryRunPlaybook(id: string, target: string, host = 'server'): Record<string, any> | null {
    const pb = this.playbooks.get(id);
    if (!pb) return null;
    const simulatedSteps = pb.actions.map((act, idx) => {
      if (act.action === 'active_response') {
        return {
          step: idx + 1,
          type: 'active_response',
          summary: `Would execute ${act.cmd || 'firewall-drop'} targeting ${target} (TTL ${act.timeout || 1800}s) across all active agents`,
          command: `sudo iptables -I INPUT 1 -s ${target} -j DROP`,
          reversible: true,
        };
      }
      if (act.action === 'create_case') {
        return {
          step: idx + 1,
          type: 'create_case',
          summary: `Would open ${act.severity || 'HIGH'} Incident Case assigned to ${act.assignee || 'SOAR Autonomous Agent'} linking host ${host} and ${target}`,
          reversible: true,
        };
      }
      return {
        step: idx + 1,
        type: 'webhook',
        summary: `Would dispatch '${act.event_type || 'soar_alert'}' notification respecting Quiet Hours policy`,
        reversible: false,
      };
    });
    return {
      dry_run: true,
      playbook_id: pb.id,
      playbook_name: pb.name,
      target,
      host,
      would_execute: simulatedSteps,
    };
  }

  private executePlaybook(
    pb: SoarPlaybook,
    triggerSource: string,
    target: string,
    host: string,
    summary: string
  ): SoarPlaybookRun {
    const now = Math.floor(Date.now() / 1000);
    const actionsTaken: string[] = [];

    for (const act of pb.actions) {
      if (act.action === 'active_response') {
        const cmd = String(act.cmd || 'firewall-drop');
        this.hooks.executeContainment(cmd, target, `SOAR [${pb.id}]: ${summary}`, 'all');
        actionsTaken.push(`Queued ${cmd} against ${target}`);
      } else if (act.action === 'create_case') {
        const cid = this.hooks.createAutoCase({
          title: `[SOAR Auto] ${summary.slice(0, 72)}`,
          severity: String(act.severity || 'CRITICAL'),
          description: `Automatically escalated by Autonomous SOAR Playbook ${pb.id} (${pb.name}).\nTrigger: ${summary}`,
          entities: { ips: target.includes('.') ? [target] : [], hosts: host ? [host] : [], users: [] },
        });
        actionsTaken.push(`Escalated to Incident Case #${cid}`);
      } else if (act.action === 'webhook') {
        const count = this.hooks.dispatchWebhook(String(act.event_type || 'soar_alert'), {
          playbook_id: pb.id,
          target,
          host,
          summary,
          timestamp: now,
        });
        actionsTaken.push(`Dispatched webhook notification (${count} endpoints)`);
      }
    }

    pb.execution_count += 1;
    pb.last_triggered_at = now;
    pb.updated_at = now;

    const run: SoarPlaybookRun = {
      id: `RUN-${String(this.runs.length + 1).padStart(4, '0')}`,
      playbook_id: pb.id,
      playbook_name: pb.name,
      trigger_source: triggerSource,
      trigger_entity: target,
      status: 'SUCCESS',
      actions_taken: actionsTaken,
      output_log: actionsTaken.join(' | '),
      executed_at: now,
    };
    this.runs.unshift(run);
    if (this.runs.length > 200) this.runs.length = 200;
    this.hooks.onSaveRun?.(run);
    return run;
  }
}

interface CveSignature {
  cve_id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  cvss: number;
  fixed_version: string;
  title: string;
  remediation: string;
  mitre_id: string;
}

const KNOWN_LINUX_CVES: Record<string, CveSignature[]> = {
  'openssh-server': [
    {
      cve_id: 'CVE-2024-6387',
      severity: 'CRITICAL',
      cvss: 8.1,
      fixed_version: '1:9.6p1-3ubuntu13.3',
      title: 'regreSSHion: Unauthenticated remote code execution in OpenSSH server (sshd) via signal handler race condition',
      remediation: 'sudo apt-get update && sudo apt-get install --only-upgrade openssh-server',
      mitre_id: 'T1190',
    },
  ],
  openssl: [
    {
      cve_id: 'CVE-2024-0727',
      severity: 'HIGH',
      cvss: 7.5,
      fixed_version: '3.0.13-0ubuntu3.1',
      title: 'OpenSSL PKCS12 decoding NULL pointer dereference DoS',
      remediation: 'sudo apt-get update && sudo apt-get install --only-upgrade openssl libssl3',
      mitre_id: 'T1499',
    },
  ],
  sudo: [
    {
      cve_id: 'CVE-2021-3156',
      severity: 'CRITICAL',
      cvss: 7.8,
      fixed_version: '1.9.5p2',
      title: 'Baron Samedit: Heap-based buffer overflow in Sudo allowing local privilege escalation to root',
      remediation: 'sudo apt-get update && sudo apt-get install --only-upgrade sudo',
      mitre_id: 'T1068',
    },
  ],
  nginx: [
    {
      cve_id: 'CVE-2022-41741',
      severity: 'HIGH',
      cvss: 7.8,
      fixed_version: '1.22.1',
      title: 'NGINX mp4 module memory corruption and worker process crash / potential code execution',
      remediation: 'sudo apt-get update && sudo apt-get install --only-upgrade nginx',
      mitre_id: 'T1190',
    },
  ],
  curl: [
    {
      cve_id: 'CVE-2023-38545',
      severity: 'CRITICAL',
      cvss: 9.8,
      fixed_version: '8.4.0',
      title: 'cURL SOCKS5 heap-based buffer overflow leading to remote code execution',
      remediation: 'sudo apt-get update && sudo apt-get install --only-upgrade curl libcurl4',
      mitre_id: 'T1210',
    },
  ],
  glibc: [
    {
      cve_id: 'CVE-2024-2961',
      severity: 'CRITICAL',
      cvss: 8.8,
      fixed_version: '2.39-0ubuntu8.2',
      title: 'GNU C Library iconv() ISO-2022-CN-EXT out-of-bounds write RCE',
      remediation: 'sudo apt-get update && sudo apt-get install --only-upgrade libc6',
      mitre_id: 'T1203',
    },
  ],
  libc6: [
    {
      cve_id: 'CVE-2024-2961',
      severity: 'CRITICAL',
      cvss: 8.8,
      fixed_version: '2.39-0ubuntu8.2',
      title: 'GNU C Library iconv() ISO-2022-CN-EXT out-of-bounds write RCE',
      remediation: 'sudo apt-get update && sudo apt-get install --only-upgrade libc6',
      mitre_id: 'T1203',
    },
  ],
  python3: [
    {
      cve_id: 'CVE-2023-24329',
      severity: 'HIGH',
      cvss: 7.5,
      fixed_version: '3.11.4',
      title: 'Python urllib.parse URL blocklist bypass via leading whitespace',
      remediation: 'sudo apt-get update && sudo apt-get install --only-upgrade python3',
      mitre_id: 'T1190',
    },
  ],
  'docker-ce': [
    {
      cve_id: 'CVE-2024-21626',
      severity: 'HIGH',
      cvss: 8.6,
      fixed_version: '25.0.2',
      title: 'Leaky Vessels: runc container breakout via leaked file descriptors',
      remediation: 'sudo apt-get update && sudo apt-get install --only-upgrade docker-ce containerd.io',
      mitre_id: 'T1611',
    },
  ],
  postgresql: [
    {
      cve_id: 'CVE-2023-5869',
      severity: 'HIGH',
      cvss: 8.8,
      fixed_version: '16.1',
      title: 'PostgreSQL buffer overflow in array modification allowing arbitrary SQL server code execution',
      remediation: 'sudo apt-get update && sudo apt-get install --only-upgrade postgresql',
      mitre_id: 'T1190',
    },
  ],
};

function parseVersionTokens(v: string): number[] {
  let clean = v.includes(':') ? v.split(':')[1] : v;
  clean = clean.split('-')[0].split('+')[0];
  return (clean.match(/\d+/g) || []).map((n) => parseInt(n, 10));
}

export function isVersionVulnerable(installed: string, fixed: string): boolean {
  const ins = parseVersionTokens(installed);
  const fix = parseVersionTokens(fixed);
  if (ins.length === 0 || fix.length === 0) return installed < fixed;
  const maxLen = Math.max(ins.length, fix.length);
  for (let i = 0; i < maxLen; i++) {
    const a = ins[i] ?? 0;
    const b = fix[i] ?? 0;
    if (a < b) return true;
    if (a > b) return false;
  }
  return false;
}

export class VulnerabilityEngine {
  private scaReports = new Map<string, SCAReport>();
  private vulnsByAgent = new Map<string, VulnerabilityFinding[]>();
  public onSaveReport?: (report: SCAReport) => void;
  public onSaveVuln?: (vuln: VulnerabilityFinding) => void;

  public loadFromDb(reports: SCAReport[], vulns: VulnerabilityFinding[]): void {
    for (const r of reports) {
      this.scaReports.set(r.agent_id, r);
    }
    for (const v of vulns) {
      let list = this.vulnsByAgent.get(v.agent_id);
      if (!list) {
        list = [];
        this.vulnsByAgent.set(v.agent_id, list);
      }
      list.push(v);
    }
  }

  saveScaReport(agentId: string, host: string, payload: { score?: number; checks: SCACheck[] }): SCAReport {
    const checks = payload.checks || [];
    const passed = checks.filter((c) => c.status === 'PASS').length;
    const failed = checks.length - passed;
    const score =
      payload.score !== undefined
        ? Number(payload.score)
        : checks.length > 0
          ? Math.round((passed / checks.length) * 1000) / 10
          : 100.0;

    const report: SCAReport = {
      agent_id: agentId,
      host,
      score,
      total_checks: checks.length,
      passed,
      failed,
      updated_at: Math.floor(Date.now() / 1000),
      checks,
    };
    this.scaReports.set(agentId, report);
    this.onSaveReport?.(report);
    return report;
  }

  correlatePackages(agentId: string, host: string, packages: Array<{ name: string; version: string }>): VulnerabilityFinding[] {
    const now = Math.floor(Date.now() / 1000);
    const found: VulnerabilityFinding[] = [];
    for (const pkg of packages) {
      const pname = (pkg.name || '').toLowerCase();
      const pver = pkg.version || '';
      if (!pname || !pver) continue;
      for (const [sigName, cveList] of Object.entries(KNOWN_LINUX_CVES)) {
        if (pname === sigName || pname.startsWith(`${sigName}-`)) {
          for (const cve of cveList) {
            if (isVersionVulnerable(pver, cve.fixed_version)) {
              found.push({
                agent_id: agentId,
                host,
                cve_id: cve.cve_id,
                package: pkg.name,
                installed_version: pver,
                fixed_version: cve.fixed_version,
                severity: cve.severity,
                cvss: cve.cvss,
                title: cve.title,
                remediation: cve.remediation,
                mitre_id: cve.mitre_id,
                discovered_at: now,
              });
            }
          }
        }
      }
    }
    this.vulnsByAgent.set(agentId, found);
    for (const v of found) {
      this.onSaveVuln?.(v);
    }
    return found;
  }

  getAgentSca(agentId: string): SCAReport | null {
    return this.scaReports.get(agentId) || null;
  }

  getAgentVulnerabilities(agentId: string): VulnerabilityFinding[] {
    return this.vulnsByAgent.get(agentId) || [];
  }

  getAllVulnerabilities(): VulnerabilityFinding[] {
    const all: VulnerabilityFinding[] = [];
    for (const list of this.vulnsByAgent.values()) {
      all.push(...list);
    }
    return all.sort((a, b) => b.cvss - a.cvss);
  }

  getFleetSummary(): {
    audited_endpoints: number;
    avg_sca_score: number;
    total_vulnerabilities: number;
    counts: { CRITICAL: number; HIGH: number; MEDIUM: number };
  } {
    const reports = Array.from(this.scaReports.values());
    const audited = reports.length;
    const avgScore =
      audited > 0
        ? Math.round((reports.reduce((acc, r) => acc + r.score, 0) / audited) * 10) / 10
        : 100.0;

    const allVulns = this.getAllVulnerabilities();
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0 };
    for (const v of allVulns) {
      if (v.severity === 'CRITICAL') counts.CRITICAL++;
      else if (v.severity === 'HIGH') counts.HIGH++;
      else counts.MEDIUM++;
    }

    return {
      audited_endpoints: audited,
      avg_sca_score: avgScore,
      total_vulnerabilities: allVulns.length,
      counts,
    };
  }
}

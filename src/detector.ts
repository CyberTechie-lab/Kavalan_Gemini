import { CEMEvent, CorrelatedSource, RuleMatch } from './types.js';

export const SENSITIVE_PREFIXES = [
  '/api/v1/datasets/internal',
  '/api/v1/admin',
  '/api/v1/tokens',
  '/admin',
];

export const HIGH_THRESHOLD = 70;
export const MEDIUM_THRESHOLD = 40;
const SPEED_LOW = 5;
const SWITCH_FULL = 4.0;
const BURST_MAX_LIFE = 180;
const BURST_MIN_REQUESTS = 20;
const ERR_FULL = 0.7;
const TACTIC_MIN_SHARE = 0.10;
const TACTIC_MIN_COUNT: Record<string, number> = { path_guessing: 10 };
const BUCKET = 5;

const STATIC_RE = /\.(css|js|png|jpe?g|gif|svg|ico|woff2?|map|json|woff|ttf|webp|mp3|wav)$/i;
const NOISE_RE = /^\/(socket\.io|sockjs|__webpack|_next|hot-update|rest\/continue-code|assets\/|\.well-known\/)/i;

const SSRF_RE = /=(https?:\/\/(169\.254\.169\.254|localhost|127\.0\.0\.1|metadata\.)|file:\/\/|gopher:\/\/)/i;
const TRAVERSAL_RE = /(\.\.\/|\.\.\\|\.\.\.\.\/\/|\/etc\/passwd|\/etc\/hosts)/i;
const SQLI_RE = /(union\s+select|'\s*or\s*'|'\s*and\s|sleep\(|;\s*--|information_schema)/i;
const CMDI_RE = /(;\s*(id|ls|cat|whoami)\b|\|\s*(id|ls|cat|whoami)\b|\$\(|`)/i;
const RECON_RE = /^\/(\.env|\.git|\.aws|\.ssh|server-status|backup|config\.json|phpinfo|\.well-known\/security)/i;
const API_ID_RE = /^\/api\/v\d+\/\w+\/\d+$/i;

export const MITRE_MAPPING: Record<string, { id: string; name: string; tactic: string }> = {
  recon_files: { id: 'T1595.002', name: 'Vulnerability Scanning', tactic: 'Reconnaissance' },
  path_guessing: { id: 'T1083', name: 'File and Directory Discovery', tactic: 'Discovery' },
  protected_resource_probing: { id: 'T1069', name: 'Permission Groups Discovery', tactic: 'Discovery' },
  sql_injection: { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
  command_injection: { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution' },
  path_traversal: { id: 'T1006', name: 'Direct Volume Access', tactic: 'Defense Evasion' },
  ssrf: { id: 'T1090', name: 'Proxy/Connection Proxy', tactic: 'Command and Control' },
  credential_guessing: { id: 'T1110.001', name: 'Password Guessing', tactic: 'Credential Access' },
  ssh_credential_guessing: { id: 'T1110.001', name: 'Password Guessing', tactic: 'Credential Access' },
  ssh_login_success: { id: 'T1078', name: 'Valid Accounts', tactic: 'Persistence' },
};

function safeDecodeUri(s: string): string {
  try {
    return decodeURIComponent(decodeURIComponent(s));
  } catch {
    try {
      return decodeURIComponent(s);
    } catch {
      return s;
    }
  }
}

export function isSensitive(path: string): boolean {
  return SENSITIVE_PREFIXES.some((p) => path.startsWith(p));
}

export function tacticOf(method: string, rawPath: string, status: number): string | null {
  const url = safeDecodeUri(rawPath).toLowerCase();
  const path = url.split('?')[0];
  if (SSRF_RE.test(url)) return 'ssrf';
  if (TRAVERSAL_RE.test(url)) return 'path_traversal';
  if (SQLI_RE.test(url)) return 'sql_injection';
  if (CMDI_RE.test(url)) return 'command_injection';
  if (RECON_RE.test(path)) return 'recon_files';
  if ((status === 401 || status === 429) && ((method === 'POST' && path.includes('login')) || path.includes('/tokens'))) {
    return 'credential_guessing';
  }
  if (isSensitive(path) && (status === 401 || status === 403)) {
    return 'protected_resource_probing';
  }
  if (API_ID_RE.test(path) && (status === 401 || status === 403 || status === 404)) {
    return 'api_enumeration';
  }
  if (status === 404) return 'path_guessing';
  return null;
}

export function scale(value: number, low: number, full: number): number {
  if (full <= low) return value >= full ? 1.0 : 0.0;
  return Math.max(0.0, Math.min(1.0, (value - low) / (full - low)));
}

export interface WebEventTuple {
  ts: number;
  method: string;
  path: string;
  status: number;
}

export interface WebSourceAnalysis {
  ip: string;
  score: number;
  first: number;
  last: number;
  life: number;
  requests: number;
  peak10: number;
  error_ratio: number;
  distinct_paths: number;
  tactics: Record<string, number>;
  present: string[];
  switches: number;
  sensitive_hits: number;
  parts: Record<string, number>;
  reasons: string[];
}

export function analyseWeb(ip: string, events: WebEventTuple[]): WebSourceAnalysis | null {
  events.sort((a, b) => a.ts - b.ts);
  const dyn = events.filter((e) => {
    const clean = e.path.split('?')[0];
    return !STATIC_RE.test(clean) && !NOISE_RE.test(clean);
  });
  if (dyn.length === 0) return null;

  const first = events[0].ts;
  const last = events[events.length - 1].ts;
  const life = last - first;

  let peak = 0;
  let lo = 0;
  for (let hi = 0; hi < dyn.length; hi++) {
    while (dyn[hi].ts - dyn[lo].ts >= 10) lo++;
    peak = Math.max(peak, hi - lo + 1);
  }

  const errCount = dyn.filter((e) => e.status >= 400).length;
  const err = errCount / dyn.length;

  const counts: Record<string, number> = {};
  const buckets = new Map<number, Record<string, number>>();
  let sensitiveHits = 0;

  for (const e of dyn) {
    const clean = safeDecodeUri(e.path).toLowerCase().split('?')[0];
    if (isSensitive(clean)) {
      sensitiveHits++;
    }
    const tactic = tacticOf(e.method, e.path, e.status);
    if (tactic) {
      counts[tactic] = (counts[tactic] || 0) + 1;
      const bKey = Math.floor(e.ts / BUCKET);
      let bMap = buckets.get(bKey);
      if (!bMap) {
        bMap = {};
        buckets.set(bKey, bMap);
      }
      bMap[tactic] = (bMap[tactic] || 0) + 1;
    }
  }

  const tagged = Object.values(counts).reduce((acc, v) => acc + v, 0);
  const present = Object.entries(counts)
    .filter(([t, c]) => c >= (TACTIC_MIN_COUNT[t] ?? 3) && tagged > 0 && c / tagged >= TACTIC_MIN_SHARE)
    .map(([t]) => t)
    .sort();

  const sortedBucketKeys = Array.from(buckets.keys()).sort((a, b) => a - b);
  const dominant = sortedBucketKeys.map((k) => {
    const b = buckets.get(k)!;
    return Object.entries(b).sort((x, y) => y[1] - x[1])[0][0];
  });
  let switches = 0;
  for (let i = 1; i < dominant.length; i++) {
    if (dominant[i] !== dominant[i - 1]) switches++;
  }
  const switchRate = switches / (Math.max(life, 15) / 60);

  const distinctPaths = new Set(dyn.map((e) => e.path.split('?')[0])).size;
  const automationRaw = Math.max(scale(dyn.length, 100, 1000), scale(distinctPaths, 50, 500));
  const attackContext = sensitiveHits > 0 || err >= 0.25 || present.length >= 2 || switches >= 4;
  const automation = 25 * automationRaw * (attackContext ? 1.0 : 0.2);

  const divMap: Record<number, number> = { 0: 0, 1: 6, 2: 12, 3: 16 };
  const parts: Record<string, number> = {
    speed: 15 * scale(peak, SPEED_LOW, 60),
    automation: Math.round(automation * 10) / 10,
    diversity: divMap[present.length] ?? 18,
    switching: 10 * scale(switchRate, 0, SWITCH_FULL),
    burst: life <= BURST_MAX_LIFE && dyn.length >= BURST_MIN_REQUESTS ? 5 : 0,
    errors: 12 * scale(err, 0.2, ERR_FULL),
    sensitive: 20 * scale(sensitiveHits, 0, 20),
  };

  const score = Math.min(100, Math.round(Object.values(parts).reduce((a, b) => a + b, 0)));

  const reasons: string[] = [];
  if (parts.speed > 0) reasons.push(`${peak} requests in its busiest 10 seconds`);
  if (parts.automation > 0 && attackContext) {
    reasons.push(`${dyn.length.toLocaleString()} requests across ${distinctPaths.toLocaleString()} distinct paths`);
  }
  if (present.length >= 2) reasons.push(`${present.length} tactics: ${present.join(', ')}`);
  else if (present.length === 1) reasons.push(`single tactic: ${present[0]}`);
  if (switches > 0) reasons.push(`changed tactic ${switches} times (${switchRate.toFixed(1)} per minute)`);
  if (parts.burst > 0) reasons.push(`${dyn.length} requests in a ${life}-second lifetime`);
  if (parts.errors > 0) reasons.push(`${Math.round(err * 100)}% of responses were refusals or errors`);
  if (sensitiveHits > 0) reasons.push(`${sensitiveHits} hits on protected paths`);

  const roundedParts: Record<string, number> = {};
  for (const [k, v] of Object.entries(parts)) roundedParts[k] = Math.round(v * 10) / 10;

  return {
    ip,
    score,
    first,
    last,
    life,
    requests: dyn.length,
    peak10: peak,
    error_ratio: Math.round(err * 100) / 100,
    distinct_paths: distinctPaths,
    tactics: counts,
    present,
    switches,
    sensitive_hits: sensitiveHits,
    parts: roundedParts,
    reasons,
  };
}

export interface AuthEventTuple {
  ts: number;
  outcome: 'fail' | 'ok';
  user: string;
}

export interface SshSourceAnalysis {
  ip: string;
  score: number;
  first: number;
  last: number;
  fails: number;
  oks: number;
  peak60: number;
  distinct_users: number;
  breached: boolean;
  tactics: Record<string, number>;
  parts: Record<string, number>;
  reasons: string[];
}

export function scoreSsh(ip: string, events: AuthEventTuple[]): SshSourceAnalysis | null {
  if (events.length === 0) return null;
  events.sort((a, b) => a.ts - b.ts);
  const fails = events.filter((e) => e.outcome === 'fail');
  const oks = events.filter((e) => e.outcome === 'ok');

  let peak = 0;
  let lo = 0;
  for (let hi = 0; hi < fails.length; hi++) {
    while (fails[hi].ts - fails[lo].ts >= 60) lo++;
    peak = Math.max(peak, hi - lo + 1);
  }

  const distinctUsers = new Set(events.map((e) => e.user)).size;
  const breached = oks.length > 0 && fails.length >= 5;

  const parts: Record<string, number> = {
    volume: 40 * scale(fails.length, 5, 100),
    rate: 20 * scale(peak, 5, 60),
    enumeration: 20 * scale(distinctUsers, 5, 50),
    breach: breached ? 40 : 0,
  };
  const score = Math.min(100, Math.round(Object.values(parts).reduce((a, b) => a + b, 0)));

  const reasons: string[] = [];
  if (fails.length > 0) reasons.push(`${fails.length} failed SSH logins`);
  if (peak > 0) reasons.push(`${peak} failed attempts in a 60-second burst`);
  if (distinctUsers >= 5) reasons.push(`${distinctUsers} distinct usernames tried (enumeration)`);
  if (breached) {
    const who = Array.from(new Set(oks.map((e) => e.user))).sort().join(', ');
    reasons.push(`SUCCESSFUL login after ${fails.length} failures - account(s): ${who}`);
  }

  const tactics: Record<string, number> = { ssh_credential_guessing: fails.length };
  if (oks.length > 0) tactics.ssh_login_success = oks.length;

  const roundedParts: Record<string, number> = {};
  for (const [k, v] of Object.entries(parts)) roundedParts[k] = Math.round(v * 10) / 10;

  return {
    ip,
    score,
    first: events[0].ts,
    last: events[events.length - 1].ts,
    fails: fails.length,
    oks: oks.length,
    peak60: peak,
    distinct_users: distinctUsers,
    breached,
    tactics,
    parts: roundedParts,
    reasons,
  };
}

function severityOf(score: number): 'HIGH' | 'MEDIUM' | 'none' {
  if (score >= HIGH_THRESHOLD) return 'HIGH';
  if (score >= MEDIUM_THRESHOLD) return 'MEDIUM';
  return 'none';
}

export function correlateSources(
  webSources: WebSourceAnalysis[],
  sshSources: SshSourceAnalysis[]
): CorrelatedSource[] {
  const webMap = new Map(webSources.map((s) => [s.ip, s]));
  const sshMap = new Map(sshSources.map((s) => [s.ip, s]));
  const allIps = Array.from(new Set([...webMap.keys(), ...sshMap.keys()])).sort();
  const rows: CorrelatedSource[] = [];

  for (const ip of allIps) {
    const w = webMap.get(ip);
    const s = sshMap.get(ip);
    const wScore = w ? w.score : 0;
    const sScore = s ? s.score : 0;
    const wSev = severityOf(wScore);
    const sSev = severityOf(sScore);
    const channels: string[] = [];
    if (wSev !== 'none') channels.push('web');
    if (sSev !== 'none') channels.push('ssh');
    const cross = channels.length === 2;

    let level: string;
    if (cross) level = 'CRITICAL';
    else if (wSev === 'HIGH' || sSev === 'HIGH') level = 'HIGH';
    else if (wSev === 'MEDIUM' || sSev === 'MEDIUM') level = 'MEDIUM';
    else continue;

    const tactics: Record<string, number> = {};
    if (w) Object.assign(tactics, w.tactics);
    if (s) Object.assign(tactics, s.tactics);

    const reasons = [...(w ? w.reasons : []), ...(s ? s.reasons : [])];
    rows.push({
      ip,
      level,
      cross_source: cross,
      channels,
      hosts: [],
      multi_host: false,
      web_score: wScore,
      ssh_score: sScore,
      tactics,
      mitre_tactics: {},
      reasons,
      parts: w?.parts ?? s?.parts ?? {},
      distinct_paths: w?.distinct_paths ?? 0,
      switches: w?.switches ?? 0,
      sensitive_hits: w?.sensitive_hits ?? 0,
      present: w?.present ?? [],
      breached: s?.breached ?? false,
    });
  }

  const order: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2 };
  rows.sort((a, b) => {
    const oDiff = (order[a.level] ?? 9) - (order[b.level] ?? 9);
    if (oDiff !== 0) return oDiff;
    return (b.web_score + b.ssh_score) - (a.web_score + a.ssh_score);
  });

  return rows;
}

export class AIAgentRuleEngine {
  evaluateSource(s: CorrelatedSource, cross = false, campaign = false): RuleMatch[] {
    const matches: RuleMatch[] = [];
    const tactics = s.tactics || {};
    const parts = s.parts || {};
    const host = s.hosts?.[0] || 'web-01';

    if ((tactics.recon_files ?? 0) >= 5) {
      matches.push({
        rule_id: 100100,
        level: 5,
        name: 'ai_agent_recon_sweep',
        description: 'AI Agent Reconnaissance: Automated sweep of sensitive file endpoints (.env, .git, admin, config)',
        groups: ['ai_agent', 'web', 'reconnaissance'],
        mitre_id: 'T1595.002',
        mitre_tactic: 'Reconnaissance',
        fired_reason: `Detected ${tactics.recon_files} reconnaissance probes`,
        actor_ip: s.ip,
        host,
        target: 'web-service',
      });
    }

    if ((s.distinct_paths ?? 0) >= 50 || (parts.automation ?? 0) >= 10) {
      matches.push({
        rule_id: 100110,
        level: 7,
        name: 'ai_agent_automation_breadth',
        description: 'AI Agent High Breadth: Automated sweep touching dozens to hundreds of distinct endpoints',
        groups: ['ai_agent', 'web', 'discovery'],
        mitre_id: 'T1083',
        mitre_tactic: 'Discovery',
        fired_reason: `Swept ${s.distinct_paths ?? 0} distinct paths`,
        actor_ip: s.ip,
        host,
        target: 'web-service',
      });
    }

    const present = s.present || [];
    if (present.length >= 2 || (parts.diversity ?? 0) >= 12) {
      matches.push({
        rule_id: 100120,
        level: 9,
        name: 'ai_agent_poly_tactic',
        description: 'AI Agent Multi-Tactic Offensive: Single actor deploying multiple distinct exploit tactics',
        groups: ['ai_agent', 'web', 'initial_access'],
        mitre_id: 'T1190',
        mitre_tactic: 'Initial Access',
        fired_reason: `Deployed ${present.length} concurrent tactics: ${present.join(', ')}`,
        actor_ip: s.ip,
        host,
        target: 'web-service',
      });
    }

    if ((s.switches ?? 0) >= 4 || (parts.switching ?? 0) >= 6) {
      matches.push({
        rule_id: 100130,
        level: 10,
        name: 'ai_agent_tactic_switching',
        description: 'AI Agent Rapid Strategy Switching: High-rate tactic pivoting indicative of autonomous LLM tool-calling loops',
        groups: ['ai_agent', 'execution', 'autonomous_agent'],
        mitre_id: 'T1059',
        mitre_tactic: 'Execution',
        fired_reason: `Changed exploit tactics ${s.switches ?? 0} times within active lifetime`,
        actor_ip: s.ip,
        host,
        target: 'web-service',
      });
    }

    if ((s.sensitive_hits ?? 0) >= 5 || (parts.sensitive ?? 0) >= 8) {
      matches.push({
        rule_id: 100140,
        level: 11,
        name: 'ai_agent_sensitive_probing',
        description: 'AI Agent Protected Resource Probing: Repeated attempts to hit internal APIs, datasets, or tokens',
        groups: ['ai_agent', 'credential_access', 'collection'],
        mitre_id: 'T1069',
        mitre_tactic: 'Discovery',
        fired_reason: `${s.sensitive_hits ?? 0} hits on protected internal resources`,
        actor_ip: s.ip,
        host,
        target: 'web-service',
      });
    }

    if ((tactics.ssh_credential_guessing ?? 0) >= 15) {
      matches.push({
        rule_id: 100200,
        level: 8,
        name: 'ssh_credential_guessing_burst',
        description: 'SSH High-Rate Dictionary Attack: Rapid authentication failures across multiple accounts',
        groups: ['authentication', 'credential_access'],
        mitre_id: 'T1110.001',
        mitre_tactic: 'Credential Access',
        fired_reason: `${tactics.ssh_credential_guessing} failed SSH login attempts`,
        actor_ip: s.ip,
        host,
        target: 'sshd',
      });
    }

    if (s.breached) {
      matches.push({
        rule_id: 100210,
        level: 13,
        name: 'ssh_credential_breach',
        description: 'SSH Successful Login Post-Brute-Force: Account compromised following guess burst',
        groups: ['authentication', 'persistence', 'privilege_escalation'],
        mitre_id: 'T1078',
        mitre_tactic: 'Persistence',
        fired_reason: 'SUCCESSFUL SSH login achieved following multiple failed attempts',
        actor_ip: s.ip,
        host,
        target: 'sshd',
      });
    }

    if (cross) {
      matches.push({
        rule_id: 100300,
        level: 15,
        name: 'ai_agent_cross_source_pivot',
        description: 'CRITICAL: Cross-Source AI Agent Intrusion: Single actor attacking web application and brute-forcing/breaching host SSH',
        groups: ['ai_agent', 'correlation', 'cross_source', 'compromise'],
        mitre_id: 'T1190,T1078',
        mitre_tactic: 'Initial Access & Persistence',
        fired_reason: `Actor concurrent attack on Web (Score: ${s.web_score}) and SSH (Score: ${s.ssh_score})`,
        actor_ip: s.ip,
        host,
        target: 'sshd',
      });
    }

    if (campaign) {
      matches.push({
        rule_id: 100400,
        level: 16,
        name: 'ai_agent_distributed_campaign',
        description: 'CRITICAL: Multi-IP AI Agent Distributed Campaign: Chained short-lived rotating sources executing coordinated sweep',
        groups: ['ai_agent', 'campaign', 'distributed'],
        mitre_id: 'T1584',
        mitre_tactic: 'Command and Control',
        fired_reason: 'Coordinated short-lived rotating sources chained across time gap',
        actor_ip: s.ip,
        host,
        target: 'web-service',
      });
    }

    matches.sort((a, b) => b.level - a.level);
    return matches;
  }
}

class RuleAccumulator {
  private windows = new Map<string, number[]>();

  recordAndCount(ruleId: number, actorIp: string, timeframeSec = 60): number {
    const now = Date.now() / 1000;
    const key = `${ruleId}:${actorIp}`;
    const arr = this.windows.get(key) ?? [];
    arr.push(now);
    const cutoff = now - timeframeSec;
    while (arr.length > 0 && arr[0] < cutoff) arr.shift();
    this.windows.set(key, arr);
    return arr.length;
  }
}

export class KavalanRuleEngine {
  private accumulator = new RuleAccumulator();
  private customRules: any[] = [];
  private readonly SUSPICIOUS_SHELL_PORTS = new Set([4444, 1337, 31337, 6667, 8888, 9999, 12345]);
  private readonly CRITICAL_SYSTEM_PATHS = [
    '/etc/shadow', '/etc/passwd', '/etc/sudoers', '/etc/pam.d',
    '/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/', '/lib/', '/lib64/',
  ];

  setCustomRules(rules: any[]): void {
    this.customRules = rules || [];
  }

  checkFieldMatch(event: Record<string, any>, key: string, expected: any): boolean {
    let field = key;
    let modifier: string | null = null;
    if (key.includes('|')) {
      const idx = key.indexOf('|');
      field = key.slice(0, idx);
      modifier = key.slice(idx + 1).toLowerCase();
    }

    let val = event[field];
    if (val === undefined || val === null) {
      if (event.ecs && event.ecs[field] !== undefined) val = event.ecs[field];
      else if (field === 'src_ip' || field === 'source.ip') val = event.source_ip;
      else if (field === 'EventID') val = event.meta?.event_id ?? event.meta?.json_data?.EventID;
      else if (field === 'CommandLine') val = event.meta?.CommandLine ?? event.meta?.json_data?.CommandLine ?? event.target;
      else if (field === 'Image') val = event.meta?.Image ?? event.meta?.process_name ?? event.meta?.json_data?.Image;
      else if (field === 'eventName') val = event.meta?.eventName ?? event.meta?.json_data?.eventName ?? event.action;
      else if (field === 'dns.question.name') val = event.meta?.query_name ?? event.target;
      else if (field.startsWith('ocsf.') && event.ocsf) {
        const sub = field.slice(5);
        val = (event.ocsf as any)[sub];
      } else if (event.meta && typeof event.meta === 'object') {
        val = event.meta[field] ?? event.meta.json_data?.[field];
      }
    }
    if ((val === undefined || val === null) && field === 'raw') {
      val = event.raw ?? '';
    }
    if (val === undefined || val === null) return false;

    const valStr = String(val).toLowerCase();
    const list = Array.isArray(expected) ? expected : [expected];

    if (modifier === 'contains') {
      return list.some((sub) => valStr.includes(String(sub).toLowerCase()));
    }
    if (modifier === 'startswith') {
      return list.some((sub) => valStr.startsWith(String(sub).toLowerCase()));
    }
    if (modifier === 'endswith') {
      return list.some((sub) => valStr.endsWith(String(sub).toLowerCase()));
    }
    if (modifier === 'regex') {
      try {
        return new RegExp(String(expected), 'i').test(String(val));
      } catch {
        return false;
      }
    }
    if (modifier === 'not') {
      return !list.some((sub) => valStr === String(sub).toLowerCase());
    }
    return list.some((sub) => valStr === String(sub).toLowerCase());
  }

  evaluateCustomRules(event: Record<string, any>): RuleMatch[] {
    const matches: RuleMatch[] = [];
    const eventLogType = String(event.log_type || '');
    const sourceIp = String(event.source_ip || '127.0.0.1');
    const host = String(event.host || 'unknown');
    const target = String(event.target || event.user || event.status || 'unknown');

    for (const rule of this.customRules) {
      if (rule.enabled === false) continue;
      const expectedType = rule.log_type || '*';
      if (expectedType && expectedType !== '*' && expectedType !== eventLogType) continue;

      const matchConds = rule.match || {};
      let allMatched = true;
      for (const [k, expected] of Object.entries(matchConds)) {
        if (!this.checkFieldMatch(event, k, expected)) {
          allMatched = false;
          break;
        }
      }
      if (!allMatched) continue;

      const freq = Number(rule.frequency || 1);
      const timeframeSec = Number(rule.timeframe_sec || 60);
      const ruleId = Number(rule.id || 200000);
      let firedReason: string;

      if (freq > 1) {
        const count = this.accumulator.recordAndCount(ruleId, sourceIp, timeframeSec);
        if (count < freq) continue;
        firedReason = `Custom Sigma rule '${rule.title}' threshold met: ${count} matches within ${timeframeSec}s (threshold: ${freq})`;
      } else {
        firedReason = `Custom Sigma rule triggered: ${rule.title || rule.name}`;
      }

      matches.push({
        rule_id: ruleId,
        level: Number(rule.level ?? 7),
        name: String(rule.name || `custom_rule_${ruleId}`),
        description: String(rule.description || rule.title || `Custom Rule ${ruleId}`),
        groups: Array.isArray(rule.groups) ? rule.groups : ['custom', 'sigma'],
        mitre_id: rule.mitre_id ?? null,
        mitre_tactic: rule.mitre_tactic ?? null,
        fired_reason: firedReason,
        actor_ip: sourceIp,
        host,
        target,
      });
    }
    return matches;
  }

  evaluateEvent(event: Record<string, any>): RuleMatch[] {
    const matches: RuleMatch[] = [];
    const logType = String(event.log_type || '');
    const action = String(event.action || '');
    const target = String(event.target || '');
    const sourceIp = String(event.source_ip || '127.0.0.1');
    const host = String(event.host || 'unknown');
    const outcome = String(event.outcome || '');
    const meta = (event.meta && typeof event.meta === 'object') ? event.meta : {};

    if (logType === 'fim' || logType === 'syscheck') {
      const changeType = String(meta.change_type || action.replace('file_', ''));
      if (changeType === 'modified') {
        const isCritical = this.CRITICAL_SYSTEM_PATHS.some((p) => target.startsWith(p) || target === p);
        if (isCritical) {
          matches.push({
            rule_id: 100501,
            level: 13,
            name: 'fim_critical_system_file_modified',
            description: `FIM: Critical system binary or configuration modified: ${target}`,
            groups: ['fim', 'syscheck', 'integrity_loss', 'critical'],
            mitre_id: 'T1565.001',
            mitre_tactic: 'Impact',
            fired_reason: `Cryptographic hash or metadata change detected on critical file ${target}`,
            actor_ip: sourceIp,
            host,
            target,
          });
        } else {
          matches.push({
            rule_id: 100500,
            level: 7,
            name: 'fim_file_modified',
            description: `FIM: File integrity change detected: ${target}`,
            groups: ['fim', 'syscheck', 'file_modified'],
            mitre_id: 'T1565',
            mitre_tactic: 'Impact',
            fired_reason: `File content or attributes modified: ${target}`,
            actor_ip: sourceIp,
            host,
            target,
          });
        }
      } else if (changeType === 'created') {
        const isSuspDir = ['/tmp', '/var/tmp', '/dev/shm'].some((p) => target.startsWith(p));
        matches.push({
          rule_id: 100502,
          level: isSuspDir ? 8 : 4,
          name: 'fim_file_created',
          description: `FIM: New file created: ${target}`,
          groups: ['fim', 'syscheck', 'file_created'],
          mitre_id: 'T1105',
          mitre_tactic: 'Ingress Tool Transfer',
          fired_reason: `New file created on disk: ${target}`,
          actor_ip: sourceIp,
          host,
          target,
        });
      } else if (changeType === 'deleted') {
        matches.push({
          rule_id: 100503,
          level: 6,
          name: 'fim_file_deleted',
          description: `FIM: Monitored file deleted: ${target}`,
          groups: ['fim', 'syscheck', 'file_deleted'],
          mitre_id: 'T1070.004',
          mitre_tactic: 'Defense Evasion',
          fired_reason: `Monitored file removed from disk: ${target}`,
          actor_ip: sourceIp,
          host,
          target,
        });
      }
    } else if (logType === 'syscollector' || logType === 'inventory') {
      if (action === 'port_opened') {
        const portNum = Number(meta.port ?? event.status ?? 0) || 0;
        if (this.SUSPICIOUS_SHELL_PORTS.has(portNum)) {
          matches.push({
            rule_id: 100601,
            level: 12,
            name: 'syscollector_suspicious_listening_port',
            description: `Syscollector: Suspicious reverse shell listening port opened: ${target}`,
            groups: ['syscollector', 'network', 'backdoor', 'command_and_control'],
            mitre_id: 'T1571',
            mitre_tactic: 'Command and Control',
            fired_reason: `New listening socket bound to known attack/backdoor port ${portNum}`,
            actor_ip: sourceIp,
            host,
            target,
          });
        } else {
          matches.push({
            rule_id: 100600,
            level: 5,
            name: 'syscollector_new_listening_port',
            description: `Syscollector: New listening network port opened: ${target}`,
            groups: ['syscollector', 'network', 'port_opened'],
            mitre_id: 'T1046',
            mitre_tactic: 'Discovery',
            fired_reason: `New network service started on ${target}`,
            actor_ip: sourceIp,
            host,
            target,
          });
        }
      }
    } else if (logType === 'auth') {
      if (outcome === 'fail' || action.includes('ssh_fail')) {
        matches.push({
          rule_id: 5710,
          level: 5,
          name: 'sshd_authentication_failed',
          description: `sshd: Authentication failed for user ${event.user || 'unknown'} from ${sourceIp}`,
          groups: ['sshd', 'authentication_failed'],
          mitre_id: 'T1078',
          mitre_tactic: 'Initial Access',
          fired_reason: `Invalid credentials submitted for user ${event.user}`,
          actor_ip: sourceIp,
          host,
          target: 'sshd',
        });
        const cnt = this.accumulator.recordAndCount(5712, sourceIp, 60);
        if (cnt >= 5) {
          matches.push({
            rule_id: 5712,
            level: 10,
            name: 'sshd_brute_force_attack',
            description: `sshd: High frequency authentication failure / brute force from ${sourceIp}`,
            groups: ['sshd', 'authentication_failed', 'brute_force'],
            mitre_id: 'T1110.001',
            mitre_tactic: 'Credential Access',
            fired_reason: `Observed ${cnt} failed authentication attempts within 60 seconds`,
            actor_ip: sourceIp,
            host,
            target: 'sshd',
          });
        }
      } else if (outcome === 'ok' && action.includes('ssh_ok')) {
        matches.push({
          rule_id: 5715,
          level: 3,
          name: 'sshd_authentication_success',
          description: `sshd: Successful login for ${event.user || 'unknown'} from ${sourceIp}`,
          groups: ['sshd', 'authentication_success'],
          mitre_id: 'T1078',
          mitre_tactic: 'Initial Access',
          fired_reason: `Accepted login for user ${event.user}`,
          actor_ip: sourceIp,
          host,
          target: 'sshd',
        });
      }
    } else if (logType === 'system') {
      if (meta.daemon === 'sudo' && outcome === 'fail') {
        matches.push({
          rule_id: 5402,
          level: 9,
          name: 'sudo_unauthorized_command_attempt',
          description: `sudo: Unauthorized privilege escalation attempt by ${event.user || 'unknown'}`,
          groups: ['sudo', 'privilege_escalation'],
          mitre_id: 'T1548.003',
          mitre_tactic: 'Privilege Escalation',
          fired_reason: `User ${event.user} attempted unauthorized sudo command`,
          actor_ip: sourceIp,
          host,
          target: 'sudo',
        });
      }
    } else if (logType === 'web') {
      if (['..', '%2e%2e', 'etc/passwd', 'win.ini'].some((p) => target.includes(p))) {
        matches.push({
          rule_id: 31101,
          level: 8,
          name: 'web_directory_traversal_attempt',
          description: `Web: Path traversal / file disclosure attempt: ${target}`,
          groups: ['web', 'traversal'],
          mitre_id: 'T1083',
          mitre_tactic: 'Discovery',
          fired_reason: `Dot-dot-slash sequence or sensitive path targeted: ${target}`,
          actor_ip: sourceIp,
          host,
          target,
        });
      }
      const lowerTarget = target.toLowerCase();
      if (['union select', "' or '1'='1", 'information_schema', 'sleep('].some((p) => lowerTarget.includes(p))) {
        matches.push({
          rule_id: 31102,
          level: 9,
          name: 'web_sql_injection_attempt',
          description: `Web: SQL Injection pattern detected: ${target}`,
          groups: ['web', 'sqli'],
          mitre_id: 'T1190',
          mitre_tactic: 'Initial Access',
          fired_reason: 'SQL syntax keywords identified in URL query parameters',
          actor_ip: sourceIp,
          host,
          target,
        });
      }
    } else if (logType === 'windows' || logType === 'sysmon') {
      const eid = Number(meta.event_id ?? 0);
      const cmdLine = String(meta.CommandLine || target || '').toLowerCase();
      if (eid === 4625) {
        matches.push({
          rule_id: 60122,
          level: 6,
          name: 'windows_failed_logon_4625',
          description: `Windows Security 4625: Failed logon for user ${event.user || 'unknown'} from ${sourceIp}`,
          groups: ['windows', 'authentication_failed'],
          mitre_id: 'T1110.001',
          mitre_tactic: 'Credential Access',
          fired_reason: `Event ID 4625 failure for ${event.user || 'account'}`,
          actor_ip: sourceIp,
          host,
          target,
        });
        const cnt = this.accumulator.recordAndCount(60123, sourceIp, 120);
        if (cnt >= 4) {
          matches.push({
            rule_id: 60123,
            level: 10,
            name: 'windows_brute_force_4625',
            description: `Windows Security: Multiple Event 4625 logon failures from ${sourceIp}`,
            groups: ['windows', 'brute_force'],
            mitre_id: 'T1110.001',
            mitre_tactic: 'Credential Access',
            fired_reason: `${cnt} failed Windows 4625 attempts within 120s`,
            actor_ip: sourceIp,
            host,
            target,
          });
        }
      } else if (eid === 4720) {
        matches.push({
          rule_id: 60109,
          level: 10,
          name: 'windows_new_user_created_4720',
          description: `Windows Security 4720: New local/domain user created: ${target || event.user || 'account'}`,
          groups: ['windows', 'account_creation', 'persistence'],
          mitre_id: 'T1136',
          mitre_tactic: 'Persistence',
          fired_reason: 'Windows Event ID 4720 new account provisioning observed',
          actor_ip: sourceIp,
          host,
          target,
        });
      } else if (eid === 4688 || eid === 1) {
        if (['powershell', '-enc', 'encodedcommand', 'mimikatz', 'certutil', 'whoami /priv', 'vssadmin delete'].some((k) => cmdLine.includes(k))) {
          matches.push({
            rule_id: 61603,
            level: 12,
            name: 'windows_sysmon_suspicious_process_exec',
            description: `Windows/Sysmon (${eid}): Suspicious process execution on ${host}: ${target}`,
            groups: ['windows', 'sysmon', 'execution'],
            mitre_id: 'T1059',
            mitre_tactic: 'Execution',
            fired_reason: `CommandLine matched living-off-the-land / execution pattern: ${cmdLine.slice(0, 80)}`,
            actor_ip: sourceIp,
            host,
            target,
          });
        }
      }
    } else if (logType === 'cloudtrail' || logType === 'entra_id' || logType === 'gcp_audit') {
      const actLower = action.toLowerCase();
      if (['stoplogging', 'deletetrail', 'createaccesskey', 'attachrolepolicy', 'setiam', 'consolelogin', 'disablemfa', 'updateconditionalaccess'].some((k) => actLower.includes(k)) || outcome === 'fail' || outcome === 'denied') {
        const isHigh = ['stoplogging', 'deletetrail', 'createaccesskey', 'disablemfa'].some((k) => actLower.includes(k));
        matches.push({
          rule_id: logType === 'cloudtrail' ? 100801 : logType === 'entra_id' ? 100802 : 100803,
          level: isHigh ? 13 : 9,
          name: `${logType}_privileged_or_risky_event`,
          description: `Cloud Audit (${logType}): ${action} by ${event.user || sourceIp} (${outcome})`,
          groups: ['cloud', logType, 'iam'],
          mitre_id: actLower.includes('stoplogging') ? 'T1562.001' : 'T1078',
          mitre_tactic: actLower.includes('stoplogging') ? 'Defense Evasion' : 'Privilege Escalation',
          fired_reason: `High-sensitivity cloud API operation '${action}' from ${sourceIp}`,
          actor_ip: sourceIp,
          host,
          target,
        });
      }
    } else if (logType === 'k8s_audit') {
      const verb = String(meta.verb || action || '').toLowerCase();
      const resource = String(meta.resource || target || '').toLowerCase();
      if (resource.includes('clusterrolebinding') || resource.includes('secrets') || verb === 'exec' || meta.privileged) {
        matches.push({
          rule_id: 100820,
          level: 11,
          name: 'kubernetes_privileged_audit_event',
          description: `Kubernetes Audit: '${verb}' on '${resource}' by ${event.user || sourceIp}`,
          groups: ['kubernetes', 'containers', 'privilege_escalation'],
          mitre_id: 'T1611',
          mitre_tactic: 'Privilege Escalation',
          fired_reason: `Sensitive K8s API verb=${verb} targeting resource=${resource}`,
          actor_ip: sourceIp,
          host,
          target,
        });
      }
    } else if (logType === 'dns') {
      const qname = String(meta.query_name || target || '');
      if (qname.length > 48 || ['.onion', '.top', 'c2.', 'exfil.', 'dnscat'].some((s) => qname.toLowerCase().includes(s))) {
        matches.push({
          rule_id: 100830,
          level: 10,
          name: 'dns_tunneling_or_malicious_domain',
          description: `DNS: Suspicious / high-entropy domain query (${qname}) from ${sourceIp}`,
          groups: ['dns', 'command_and_control', 'exfiltration'],
          mitre_id: 'T1071.004',
          mitre_tactic: 'Command and Control',
          fired_reason: `Long/high-entropy DNS query (${qname.length} chars) or suspicious TLD`,
          actor_ip: sourceIp,
          host,
          target: qname,
        });
      }
    } else if (logType === 'firewall') {
      if (outcome === 'denied' || action.includes('deny') || action.includes('drop')) {
        const cnt = this.accumulator.recordAndCount(100840, sourceIp, 120);
        if (cnt >= 3) {
          matches.push({
            rule_id: 100840,
            level: 8,
            name: 'firewall_blocked_probe_burst',
            description: `Firewall Syslog: Repeated blocked connections from ${sourceIp} (${cnt} drops)`,
            groups: ['firewall', 'network', 'recon'],
            mitre_id: 'T1046',
            mitre_tactic: 'Discovery',
            fired_reason: `${cnt} perimeter drops observed from ${sourceIp} inside 120s`,
            actor_ip: sourceIp,
            host,
            target,
          });
        }
      }
    } else if (logType === 'proxy') {
      if (outcome === 'denied' || Number(meta.bytes_out || 0) > 5000000) {
        matches.push({
          rule_id: 100850,
          level: 9,
          name: 'proxy_policy_violation_or_large_egress',
          description: `Web Proxy: ${action} -> ${target} from ${sourceIp}`,
          groups: ['proxy', 'egress', 'network'],
          mitre_id: 'T1041',
          mitre_tactic: 'Exfiltration',
          fired_reason: `Proxy blocked/high-volume egress to ${target}`,
          actor_ip: sourceIp,
          host,
          target,
        });
      }
    } else if (logType === 'mcp_agent') {
      const toolName = String(meta.tool_name || action || '').toLowerCase();
      const argsStr = String(meta.args || target || event.raw || '').toLowerCase();
      const injScore = Number(meta.prompt_injection_score || 0);
      const isRiskyTool = ['execute_sql', 'run_shell', 'bash', 'read_secret', 'export_keys', 'delete_', 'curl'].some((t) => toolName.includes(t));
      const hasPromptInj = injScore >= 0.7 || ['ignore previous', 'system prompt', 'override policy', 'exfiltrate', 'cat /etc/shadow', 'api_keys'].some((p) => argsStr.includes(p));
      if (isRiskyTool || hasPromptInj || outcome === 'denied') {
        matches.push({
          rule_id: 100860,
          level: hasPromptInj ? 14 : 11,
          name: 'mcp_prompt_injection_tool_abuse',
          description: `MCP AI-Agent Guard: High-risk tool invocation '${toolName || action}'${hasPromptInj ? ' with prompt-injection payload' : ''}`,
          groups: ['ai_agent', 'mcp_agent', 'prompt_injection', 'execution'],
          mitre_id: 'AML.T0051',
          mitre_tactic: 'Execution',
          fired_reason: `MCP tool '${toolName || action}' triggered guard (injection_score=${injScore.toFixed(2)}, args=${argsStr.slice(0, 80)})`,
          actor_ip: sourceIp,
          host,
          target,
        });
      }
    } else if (logType === 'canary') {
      matches.push({
        rule_id: 100900,
        level: 15,
        name: 'ai_agent_canary_tarpit_hit',
        description: `CRITICAL: Zero-FP Canary Tarpit Triggered on '${target}' by ${sourceIp}`,
        groups: ['ai_agent', 'canary', 'deception', 'reconnaissance'],
        mitre_id: 'T1595.002',
        mitre_tactic: 'Reconnaissance',
        fired_reason: `Actor probed hidden deception canary '${target}' (UA: ${String(meta.user_agent || 'unknown').slice(0, 60)})`,
        actor_ip: sourceIp,
        host,
        target,
      });
    }

    if (logType === 'cloudtrail' || logType === 'entra_id' || logType === 'k8s_audit' || logType === 'mcp_agent') {
      const chainKey = sourceIp !== '0.0.0.0' && sourceIp !== '127.0.0.1' ? sourceIp : (event.user || host);
      const chainCount = this.accumulator.recordAndCount(100870, String(chainKey), 300);
      if (chainCount >= 3 && (outcome !== 'ok' || action.toLowerCase().includes('stoplogging') || meta.privileged || logType === 'mcp_agent')) {
        matches.push({
          rule_id: 100870,
          level: 15,
          name: 'cloud_ai_agent_killchain',
          description: `CRITICAL: Autonomous Cloud/MCP Killchain Burst (${chainCount} privileged/enum operations in 300s by ${chainKey})`,
          groups: ['ai_agent', 'cloud', 'kubernetes', 'correlation'],
          mitre_id: 'T1562.001,T1611',
          mitre_tactic: 'Defense Evasion & Privilege Escalation',
          fired_reason: `${chainCount} correlated Cloud/K8s/MCP offensive actions observed inside 300s window`,
          actor_ip: sourceIp,
          host,
          target,
        });
      }
    }

    matches.push(...this.evaluateCustomRules(event));
    return matches;
  }
}

export class DecoderPipeline {
  private readonly FIM_RE = /^FIM:\s+File\s+(created|modified|deleted):\s+(\S+)(?:\s+\((.*)\))?/i;
  private readonly SYSCOL_RE = /^Syscollector:\s+(?:New listening port opened|Listening port closed):\s+(tcp|udp)\/(\d+)(?:\s+on\s+(\S+))?/i;
  private readonly WEB_RE = /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+(\S+)[^"]*"\s+(\d{3})\s+\S+(?:\s+"[^"]*"\s+"([^"]*)")?/;
  private readonly SSH_RE = /^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+(.*)$/;
  private readonly SSH_FAIL_RE = /Failed password for (?:invalid user )?(\S+) from (\S+)/;
  private readonly SSH_INVALID_RE = /Invalid user (\S+) from (\S+)/;
  private readonly SSH_OK_RE = /Accepted (?:password|publickey) for (\S+) from (\S+)/;
  private readonly RFC3164_RE = /^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([a-zA-Z0-9_\-.]+)(?:\[(\d+)\])?:\s+(.*)$/;
  private readonly RFC5424_RE = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+(\S+)\s+([a-zA-Z0-9_\-.]+)(?:\[(\d+)\])?:\s+(.*)$/;

  private parseNginxTimestamp(raw: string): number {
    // e.g. "05/Nov/2026:12:00:00 +0000"
    const normalized = raw.replace(/^(\d{2})\/([A-Za-z]{3})\/(\d{4}):/, '$2 $1 $3 ');
    const ms = Date.parse(normalized);
    return Number.isNaN(ms) ? Math.floor(Date.now() / 1000) : Math.floor(ms / 1000);
  }

  private parseSyslogTimestamp(raw: string): number {
    const year = new Date().getUTCFullYear();
    const ms = Date.parse(`${raw} ${year} UTC`);
    return Number.isNaN(ms) ? Math.floor(Date.now() / 1000) : Math.floor(ms / 1000);
  }

  decodeLine(line: string, host = 'unknown'): CEMEvent | null {
    const trimmed = line?.trim();
    if (!trimmed) return null;
    const now = Math.floor(Date.now() / 1000);

    // 1. FIM
    const fm = this.FIM_RE.exec(trimmed);
    if (fm) {
      const actionWord = fm[1].toLowerCase();
      const path = fm[2];
      const extra = fm[3] || '';
      return {
        ts: now,
        host,
        source_ip: '127.0.0.1',
        log_type: 'fim',
        action: `file_${actionWord}`,
        target: path,
        outcome: 'ok',
        status: 0,
        user: 'system',
        raw: trimmed,
        meta: { path, change_type: actionWord, extra, decoder: 'fim_decoder' },
      };
    }

    // 2. Syscollector
    const sm = this.SYSCOL_RE.exec(trimmed);
    if (sm) {
      const proto = sm[1].toLowerCase();
      const port = Number(sm[2]);
      const addr = sm[3] || '0.0.0.0';
      const action = trimmed.toLowerCase().includes('opened') ? 'port_opened' : 'port_closed';
      return {
        ts: now,
        host,
        source_ip: addr,
        log_type: 'syscollector',
        action,
        target: `${proto}:${port}`,
        outcome: 'ok',
        status: port,
        user: 'system',
        raw: trimmed,
        meta: { proto, port, address: addr, decoder: 'syscollector_decoder' },
      };
    }

    // 3. Structured JSON Logs (CloudTrail, Entra ID, GCP Audit, K8s Audit, Windows/Sysmon, Generic JSON)
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
      try {
        const d = JSON.parse(trimmed);
        if (d && typeof d === 'object' && !Array.isArray(d)) {
          let ts = now;
          for (const k of ['ts', 'timestamp', '@timestamp', 'time', 'eventTime', 'requestReceivedTimestamp']) {
            if (d[k] !== undefined) {
              if (typeof d[k] === 'number') ts = Math.floor(d[k]);
              else if (typeof d[k] === 'string') {
                const ms = Date.parse(d[k]);
                if (!Number.isNaN(ms)) ts = Math.floor(ms / 1000);
              }
              break;
            }
          }

          // 3a. AWS CloudTrail
          if (d.eventSource && d.eventName) {
            const err = Boolean(d.errorCode || d.errorMessage);
            const arn = d.userIdentity?.arn || d.userIdentity?.userName || 'aws-iam';
            return {
              ts,
              host: String(d.awsRegion ? `aws-${d.awsRegion}` : host),
              source_ip: String(d.sourceIPAddress || '0.0.0.0'),
              log_type: 'cloudtrail',
              action: String(d.eventName),
              target: String(d.eventSource),
              outcome: err ? 'denied' : 'ok',
              status: err ? 403 : 200,
              user: String(arn),
              raw: trimmed,
              meta: { eventName: d.eventName, eventSource: d.eventSource, region: d.awsRegion, json_data: d, decoder: 'aws_cloudtrail' },
            };
          }

          // 3b. Microsoft Entra ID / M365 Audit
          if (d.workload === 'AzureActiveDirectory' || d.conditionalAccessStatus || d.userPrincipalName) {
            const fail = String(d.status?.errorCode || d.resultType || '0') !== '0' || d.conditionalAccessStatus === 'failure';
            return {
              ts,
              host: 'entra-id-tenant',
              source_ip: String(d.ipAddress || d.clientIp || '0.0.0.0'),
              log_type: 'entra_id',
              action: String(d.operation || d.activityDisplayName || 'SignIn'),
              target: String(d.appDisplayName || d.resourceDisplayName || 'M365'),
              outcome: fail ? 'fail' : 'ok',
              status: fail ? 401 : 200,
              user: String(d.userPrincipalName || d.UserId || 'unknown'),
              raw: trimmed,
              meta: { app: d.appDisplayName, ca_status: d.conditionalAccessStatus, json_data: d, decoder: 'entra_id_audit' },
            };
          }

          // 3c. GCP Cloud Audit
          if (d.protoPayload && d.protoPayload.methodName) {
            const code = Number(d.protoPayload.status?.code || 0);
            return {
              ts,
              host: String(d.resource?.labels?.project_id || 'gcp-org'),
              source_ip: String(d.protoPayload.requestMetadata?.callerIp || '0.0.0.0'),
              log_type: 'gcp_audit',
              action: String(d.protoPayload.methodName),
              target: String(d.protoPayload.resourceName || d.resource?.type || 'gcp'),
              outcome: code !== 0 ? 'denied' : 'ok',
              status: code,
              user: String(d.protoPayload.authenticationInfo?.principalEmail || 'service-account'),
              raw: trimmed,
              meta: { method: d.protoPayload.methodName, json_data: d, decoder: 'gcp_cloud_audit' },
            };
          }

          // 3d. Kubernetes Audit
          if (d.kind === 'Event' && d.verb && d.objectRef) {
            const code = Number(d.responseStatus?.code || 200);
            return {
              ts,
              host: String(d.annotations?.['cluster-name'] || 'k8s-control-plane'),
              source_ip: String((Array.isArray(d.sourceIPs) ? d.sourceIPs[0] : d.sourceIPs) || '0.0.0.0'),
              log_type: 'k8s_audit',
              action: `${d.verb}:${d.objectRef.resource}`,
              target: String(d.objectRef.name ? `${d.objectRef.namespace || 'cluster'}/${d.objectRef.resource}/${d.objectRef.name}` : d.objectRef.resource),
              outcome: code >= 400 ? 'denied' : 'ok',
              status: code,
              user: String(d.user?.username || 'system:anonymous'),
              raw: trimmed,
              meta: { verb: d.verb, resource: d.objectRef.resource, namespace: d.objectRef.namespace, privileged: Boolean(d.requestObject?.spec?.containers?.some((c: any) => c.securityContext?.privileged)), json_data: d, decoder: 'k8s_audit_v1' },
            };
          }

          // 3d-bis. AI Agent / MCP Server Tool-Call Audit
          if (d.mcp_server || d.tool_name || d.agent_session) {
            const toolName = String(d.tool_name || d.action || 'tool_call');
            const injScore = Number(d.prompt_injection_score || 0);
            const blocked = Boolean(d.blocked || d.outcome === 'denied' || injScore >= 0.8);
            return {
              ts,
              host: String(d.mcp_server || d.host || 'mcp-gateway-01'),
              source_ip: String(d.source_ip || d.client_ip || '127.0.0.1'),
              log_type: 'mcp_agent',
              action: toolName,
              target: String(d.args || d.target || d.resource || toolName),
              outcome: blocked ? 'denied' : 'ok',
              status: blocked ? 403 : 200,
              user: String(d.agent_id || d.agent_session || d.user || 'ai-agent'),
              raw: trimmed,
              meta: {
                mcp_server: d.mcp_server || 'mcp-gateway-01',
                tool_name: toolName,
                args: typeof d.args === 'string' ? d.args : JSON.stringify(d.args || ''),
                prompt_injection_score: injScore,
                model: d.model || 'autonomous-agent',
                json_data: d,
                decoder: 'mcp_agent_audit',
              },
            };
          }

          // 3e. Windows Event Log / Sysmon JSON
          if (d.EventID !== undefined || d.event_id !== undefined) {
            const eid = Number(d.EventID ?? d.event_id);
            const isSysmon = String(d.Channel || d.channel || '').toLowerCase().includes('sysmon') || [1, 3, 11].includes(eid);
            const outcome = eid === 4625 || String(d.outcome || '').toLowerCase() === 'fail' ? 'fail' : 'ok';
            return {
              ts,
              host: String(d.Computer || d.host || host),
              source_ip: String(d.IpAddress || d.SourceIp || d.source_ip || '127.0.0.1'),
              log_type: isSysmon ? 'sysmon' : 'windows',
              action: `win_eid_${eid}`,
              target: String(d.CommandLine || d.TargetUserName || d.DestinationIp || d.Image || `EventID_${eid}`),
              outcome,
              status: eid,
              user: String(d.TargetUserName || d.SubjectUserName || d.User || 'SYSTEM'),
              raw: trimmed,
              meta: { event_id: eid, Image: d.Image, CommandLine: d.CommandLine, process_name: d.Image, json_data: d, decoder: isSysmon ? 'sysmon_json' : 'windows_event_json' },
            };
          }

          const srcIp = String(d.source_ip || d.src_ip || d.srcip || d.ip || '127.0.0.1');
          const outcomeRaw = String(d.outcome || (Number(d.status_code || 0) >= 400 ? 'fail' : 'ok'));
          return {
            ts,
            host: String(d.host || host),
            source_ip: srcIp,
            log_type: String(d.log_type || d.event_type || 'json'),
            action: String(d.action || d.event || 'json_event'),
            target: String(d.target || d.dest || d.url || 'unknown'),
            outcome: ['ok', 'fail', 'denied', 'error'].includes(outcomeRaw) ? outcomeRaw : 'ok',
            status: d.status ?? d.status_code ?? null,
            user: d.user ?? d.username ?? null,
            raw: trimmed,
            meta: { json_data: d, decoder: 'json_decoder' },
          };
        }
      } catch {
        // fall through
      }
    }

    // 4. Web access log
    const wm = this.WEB_RE.exec(trimmed);
    if (wm) {
      const ip = wm[1];
      const ts = this.parseNginxTimestamp(wm[2]);
      const method = wm[3];
      const path = wm[4];
      const statusCode = Number(wm[5]);
      const ua = wm[6] || '';
      const outcome = statusCode < 400
        ? 'ok'
        : (statusCode === 401 || statusCode === 403)
          ? 'denied'
          : statusCode < 500 ? 'fail' : 'error';

      return {
        ts,
        host,
        source_ip: ip,
        log_type: 'web',
        action: `${method} ${path}`,
        target: path,
        outcome,
        status: statusCode,
        user: null,
        raw: trimmed,
        meta: { method, path, ua, decoder: 'web_access_combined' },
      };
    }

    // 5. SSH Auth
    const shm = this.SSH_RE.exec(trimmed);
    if (shm) {
      const msg = shm[2];
      const failHit = this.SSH_FAIL_RE.exec(msg) || this.SSH_INVALID_RE.exec(msg);
      const okHit = this.SSH_OK_RE.exec(msg);
      const hit = failHit || okHit;
      if (hit) {
        const outcome = failHit ? 'fail' : 'ok';
        return {
          ts: this.parseSyslogTimestamp(shm[1]),
          host,
          source_ip: hit[2],
          log_type: 'auth',
          action: `ssh_${outcome}`,
          target: 'sshd',
          outcome,
          status: failHit ? 1 : 0,
          user: hit[1],
          raw: trimmed,
          meta: { service: 'sshd', decoder: 'sshd_syslog' },
        };
      }
    }

    // 5a. Firewall / Network Syslog (Cisco ASA, Palo Alto, Fortinet, iptables/UFW)
    if (/%(?:ASA|FTD)-\d+-\d+:|THREAT,|TRAFFIC,|\[UFW\s+(?:BLOCK|ALLOW)\]|devname=|SRC=\S+\s+DST=\S+/i.test(trimmed)) {
      const srcM = /(?:src=|SRC=|from\s+)(\d{1,3}(?:\.\d{1,3}){3})/.exec(trimmed);
      const dstM = /(?:dst=|DST=|to\s+\S+?:?)(\d{1,3}(?:\.\d{1,3}){3})/.exec(trimmed);
      const dptM = /(?:DPT=|dstport=|\/)(\d{1,5})\b/.exec(trimmed);
      const isDenied = /(?:Deny|DROP|BLOCK|deny|action=deny|reset-both)/i.test(trimmed);
      return {
        ts: now,
        host,
        source_ip: srcM ? srcM[1] : '0.0.0.0',
        log_type: 'firewall',
        action: isDenied ? 'firewall_deny' : 'firewall_allow',
        target: `${dstM ? dstM[1] : host}:${dptM ? dptM[1] : '0'}`,
        outcome: isDenied ? 'denied' : 'ok',
        status: dptM ? Number(dptM[1]) : 0,
        user: null,
        raw: trimmed,
        meta: { dest_port: dptM ? Number(dptM[1]) : undefined, decoder: 'firewall_syslog' },
      };
    }

    // 5b. DNS Query Logs (BIND / Unbound / CoreDNS)
    const dnsM = /client\s+(?:@\S+\s+)?(\d{1,3}(?:\.\d{1,3}){3})(?:#\d+)?[^:]*:\s+query:\s+(\S+)\s+IN\s+([A-Z0-9]+)(?:\s+\((NXDOMAIN|NOERROR|SERVFAIL)\))?/i.exec(trimmed);
    if (dnsM) {
      const rcode = (dnsM[4] || 'NOERROR').toUpperCase();
      return {
        ts: now,
        host,
        source_ip: dnsM[1],
        log_type: 'dns',
        action: `dns_query_${dnsM[3]}`,
        target: dnsM[2],
        outcome: rcode === 'NXDOMAIN' || rcode === 'SERVFAIL' ? 'fail' : 'ok',
        status: rcode === 'NXDOMAIN' ? 3 : 0,
        user: null,
        raw: trimmed,
        meta: { query_name: dnsM[2], qtype: dnsM[3], rcode, decoder: 'dns_query_log' },
      };
    }

    // 5c. Web Proxy Logs (Squid / Zscaler)
    const proxyM = /^\d+(?:\.\d+)?\s+\d+\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(TCP_[A-Z_]+)\/(\d{3})\s+(\d+)\s+([A-Z]+)\s+(\S+)\s+(\S+)/.exec(trimmed);
    if (proxyM) {
      const code = Number(proxyM[3]);
      return {
        ts: now,
        host,
        source_ip: proxyM[1],
        log_type: 'proxy',
        action: `proxy_${proxyM[5].toLowerCase()}`,
        target: proxyM[6],
        outcome: proxyM[2].includes('DENIED') || code >= 400 ? 'denied' : 'ok',
        status: code,
        user: proxyM[7] === '-' ? null : proxyM[7],
        raw: trimmed,
        meta: { squid_result: proxyM[2], bytes_out: Number(proxyM[4]), decoder: 'web_proxy_squid' },
      };
    }

    // 5d. Windows / Sysmon Key-Value Syslog Text
    const winEidM = /\bEventID[=:]\s*(4624|4625|4688|4720|1|3|11)\b/i.exec(trimmed);
    if (winEidM) {
      const eid = Number(winEidM[1]);
      const ipM = /\b(?:IpAddress|SourceIp|src)[=:]\s*(\d{1,3}(?:\.\d{1,3}){3})/i.exec(trimmed);
      const userM = /\b(?:TargetUserName|User|Account)[=:]\s*(\S+)/i.exec(trimmed);
      const cmdM = /\b(?:CommandLine|Process)[=:]\s*"?([^"\n]+)"?/i.exec(trimmed);
      const isSysmon = [1, 3, 11].includes(eid) || /sysmon/i.test(trimmed);
      return {
        ts: now,
        host,
        source_ip: ipM ? ipM[1] : '127.0.0.1',
        log_type: isSysmon ? 'sysmon' : 'windows',
        action: `win_eid_${eid}`,
        target: cmdM ? cmdM[1].trim() : `EventID_${eid}`,
        outcome: eid === 4625 ? 'fail' : 'ok',
        status: eid,
        user: userM ? userM[1] : 'SYSTEM',
        raw: trimmed,
        meta: { event_id: eid, CommandLine: cmdM ? cmdM[1].trim() : undefined, decoder: isSysmon ? 'sysmon_text' : 'windows_text' },
      };
    }

    // 6. Generic RFC5424 / RFC3164 Syslog (strips optional <PRI> header first)
    const strippedPri = trimmed.replace(/^<\d{1,3}>/, '');
    const s5424 = this.RFC5424_RE.exec(strippedPri);
    const s3164 = !s5424 ? this.RFC3164_RE.exec(strippedPri) : null;
    const gm = s5424 || s3164;
    if (gm) {
      let ts = now;
      if (s5424) {
        const ms = Date.parse(gm[1]);
        if (!Number.isNaN(ms)) ts = Math.floor(ms / 1000);
      } else {
        ts = this.parseSyslogTimestamp(gm[1]);
      }
      const logHost = gm[2] || host;
      const daemon = gm[3];
      const pid = gm[4] || null;
      const msg = gm[5];

      const userM = /\b(?:user[ =]|for\s+)([a-zA-Z0-9_-]+)/i.exec(msg);
      const user = userM ? userM[1] : null;
      const ipM = /\b(?:\d{1,3}\.){3}\d{1,3}\b/.exec(msg);
      const ip = ipM ? ipM[0] : '127.0.0.1';
      const lowerMsg = msg.toLowerCase();
      const outcome = ['fail', 'error', 'denied', 'invalid', 'unauthorized', 'not in sudoers'].some((t) =>
        lowerMsg.includes(t)
      )
        ? 'fail'
        : 'ok';

      return {
        ts,
        host: logHost,
        source_ip: ip,
        log_type: 'system',
        action: `${daemon}_event`,
        target: daemon,
        outcome,
        status: outcome === 'fail' ? 1 : 0,
        user,
        raw: trimmed,
        meta: { daemon, pid, decoder: 'syslog_generic' },
      };
    }

    return null;
  }
}

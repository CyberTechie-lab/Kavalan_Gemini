import { CustomRule } from './types.js';

export interface SigmaTemplate {
  id: string;
  name: string;
  title: string;
  category: string;
  level: number;
  yaml: string;
}

const SIGMA_TEMPLATES: SigmaTemplate[] = [
  {
    id: 'sigma_web_sqli_union',
    name: 'Web SQL Injection Probe',
    title: 'Web SQL Injection UNION SELECT / SQLMap Probe',
    category: 'web',
    level: 12,
    yaml: `title: Web SQL Injection UNION SELECT / SQLMap Probe
id: 200101
status: production
description: Detects SQL injection payloads targeting web API query parameters via UNION SELECT or OR tautologies.
tags:
  - attack.t1190
  - attack.initial_access
logsource:
  category: web
detection:
  selection:
    target|contains:
      - "union select"
      - "information_schema"
      - "' or '"
      - "sleep("
  condition: selection
level: high`,
  },
  {
    id: 'sigma_ssh_bruteforce',
    name: 'SSH Brute Force Authentication Burst',
    title: 'SSH Invalid User Brute Force Burst',
    category: 'auth',
    level: 11,
    yaml: `title: SSH Invalid User Brute Force Burst
id: 200102
status: production
description: Detects repeated SSH authentication failures from a single source IP within 60 seconds.
tags:
  - attack.t1110.001
  - attack.credential_access
logsource:
  category: auth
detection:
  selection:
    outcome: fail
    action|contains:
      - "ssh_failed"
      - "failed"
  condition: selection | count() >= 3
  timeframe: 60s
level: high`,
  },
  {
    id: 'sigma_fim_webshell',
    name: 'FIM PHP Web Shell Creation',
    title: 'FIM Unauthorized Web Shell Upload (.php/.jsp)',
    category: 'fim',
    level: 14,
    yaml: `title: FIM Unauthorized Web Shell Upload (.php/.jsp)
id: 200103
status: production
description: Triggers critical alert and Active Response when script web shells are dropped inside web roots.
tags:
  - attack.t1505.003
  - attack.persistence
logsource:
  category: fim
detection:
  selection:
    target|endswith:
      - ".php"
      - ".jsp"
      - ".aspx"
  condition: selection
level: critical`,
  },
  {
    id: 'sigma_syscollector_revshell',
    name: 'Reverse Shell Listener (Port 4444/1337)',
    title: 'Suspicious Backdoor Listening Port Opened',
    category: 'syscollector',
    level: 13,
    yaml: `title: Suspicious Backdoor Listening Port Opened
id: 200104
status: production
description: Detects unauthorized C2 or Metasploit reverse-shell listening sockets opened on monitored hosts.
tags:
  - attack.t1059
  - attack.execution
logsource:
  category: syscollector
detection:
  selection:
    target|contains:
      - "4444"
      - "1337"
      - "31337"
  condition: selection
level: critical`,
  },
  {
    id: 'sigma_windows_encoded_ps',
    name: 'Windows Encoded PowerShell Execution',
    title: 'Windows Process Creation Encoded PowerShell (EID 4688)',
    category: 'windows',
    level: 12,
    yaml: `title: Windows Process Creation Encoded PowerShell (EID 4688)
id: 200105
status: production
description: Detects obfuscated or Base64 encoded PowerShell command lines in Windows Security 4688 or Sysmon EID 1.
tags:
  - attack.t1059.001
  - attack.execution
logsource:
  category: windows
detection:
  selection:
    CommandLine|contains:
      - "-EncodedCommand"
      - "-enc "
      - "FromBase64String"
  condition: selection
level: high`,
  },
  {
    id: 'sigma_cloudtrail_stoplogging',
    name: 'AWS CloudTrail Defense Evasion',
    title: 'AWS CloudTrail Logging Disabled or Deleted',
    category: 'cloudtrail',
    level: 14,
    yaml: `title: AWS CloudTrail Logging Disabled or Deleted
id: 200106
status: production
description: Alerts immediately when an actor attempts to blind AWS CloudTrail audit logging.
tags:
  - attack.t1562.008
  - attack.defense_evasion
logsource:
  category: cloudtrail
detection:
  selection:
    eventName:
      - "StopLogging"
      - "DeleteTrail"
      - "UpdateTrail"
  condition: selection
level: critical`,
  },
  {
    id: 'sigma_mcp_prompt_injection',
    name: 'MCP AI-Agent Prompt Injection / Exfil',
    title: 'MCP AI-Agent Indirect Prompt Injection & Tool Abuse',
    category: 'mcp_agent',
    level: 13,
    yaml: `title: MCP AI-Agent Indirect Prompt Injection & Tool Abuse
id: 200107
status: production
description: Detects autonomous AI agent prompt injection payloads attempting credential theft or shell tool invocation.
tags:
  - attack.t1059
  - attack.execution
logsource:
  category: mcp_agent
detection:
  selection:
    target|contains:
      - "ignore previous"
      - "/etc/shadow"
      - "exfil"
      - "bash -c"
  condition: selection
level: critical`,
  },
];

function stripQuotes(s: string): string {
  const t = s.trim();
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
    return t.slice(1, -1);
  }
  return t;
}

function mapSigmaLevel(levelStr: string): number {
  const normalized = levelStr.trim().toLowerCase();
  const num = Number(normalized);
  if (!Number.isNaN(num) && num >= 1 && num <= 15) return Math.round(num);
  if (normalized === 'critical') return 14;
  if (normalized === 'high') return 11;
  if (normalized === 'medium') return 8;
  if (normalized === 'low') return 5;
  if (normalized === 'informational' || normalized === 'info') return 3;
  return 8;
}

function mapLogsourceToKavalan(category: string, product: string): string {
  const c = category.trim().toLowerCase();
  const p = product.trim().toLowerCase();
  if (c === 'webserver' || c === 'web' || p === 'nginx' || p === 'apache') return 'web';
  if (c === 'authentication' || c === 'auth' || p === 'sshd' || p === 'linux') return 'auth';
  if (c === 'file_event' || c === 'fim' || c === 'syscheck') return 'fim';
  if (c === 'process_creation' || p === 'windows') return 'windows';
  if (p === 'aws' || c === 'cloudtrail') return 'cloudtrail';
  if (c === 'kubernetes' || c === 'k8s_audit') return 'k8s_audit';
  if (c === 'dns' || c === 'dns_query') return 'dns';
  if (c === 'proxy') return 'proxy';
  if (c) return c;
  return '*';
}

function parseTimeframeSec(raw: string): number {
  const m = raw.trim().toLowerCase().match(/^(\d+)\s*([smhd]?)$/);
  if (!m) return 60;
  const val = Number(m[1]);
  const unit = m[2] || 's';
  if (unit === 'm') return val * 60;
  if (unit === 'h') return val * 3600;
  if (unit === 'd') return val * 86400;
  return val;
}

export class SigmaRuleConverter {
  static getTemplates(): SigmaTemplate[] {
    return SIGMA_TEMPLATES.map((t) => ({ ...t }));
  }

  static convert(rawSigma: string, fallbackId?: number): CustomRule {
    if (!rawSigma || !rawSigma.trim()) {
      throw new Error('Sigma YAML input is empty.');
    }

    const lines = rawSigma.replace(/\r\n/g, '\n').split('\n');
    let title = '';
    let idRaw: string | number = fallbackId || 200199;
    let description = '';
    let levelStr = 'medium';
    let category = '';
    let product = '';
    let condition = 'selection';
    let timeframe = '60s';
    const tags: string[] = [];
    const matchObj: Record<string, any> = {};

    let section = '';
    let subSection = '';
    let currentMatchKey: string | null = null;

    for (const rawLine of lines) {
      if (!rawLine.trim() || rawLine.trim().startsWith('#')) continue;
      const indent = rawLine.search(/\S/);
      const trimmed = rawLine.trim();

      if (indent === 0) {
        currentMatchKey = null;
        subSection = '';
        const colonIdx = trimmed.indexOf(':');
        if (colonIdx === -1) continue;
        const key = trimmed.slice(0, colonIdx).trim().toLowerCase();
        const val = trimmed.slice(colonIdx + 1).trim();
        section = key;
        if (key === 'title' && val) title = stripQuotes(val);
        else if (key === 'id' && val) idRaw = stripQuotes(val);
        else if (key === 'description' && val) description = stripQuotes(val);
        else if (key === 'level' && val) levelStr = stripQuotes(val);
        continue;
      }

      if (section === 'tags' && trimmed.startsWith('-')) {
        tags.push(stripQuotes(trimmed.slice(1)));
        continue;
      }

      if (section === 'logsource') {
        const colonIdx = trimmed.indexOf(':');
        if (colonIdx !== -1) {
          const k = trimmed.slice(0, colonIdx).trim().toLowerCase();
          const v = stripQuotes(trimmed.slice(colonIdx + 1));
          if (k === 'category') category = v;
          else if (k === 'product') product = v;
        }
        continue;
      }

      if (section === 'detection') {
        if (trimmed.startsWith('-') && currentMatchKey) {
          const item = stripQuotes(trimmed.slice(1));
          if (!Array.isArray(matchObj[currentMatchKey])) {
            matchObj[currentMatchKey] = [];
          }
          matchObj[currentMatchKey].push(item);
          continue;
        }

        const colonIdx = trimmed.indexOf(':');
        if (colonIdx === -1) continue;
        const k = trimmed.slice(0, colonIdx).trim();
        const v = trimmed.slice(colonIdx + 1).trim();

        if (indent <= 2) {
          currentMatchKey = null;
          const kl = k.toLowerCase();
          if (kl === 'condition') {
            condition = stripQuotes(v);
            subSection = '';
          } else if (kl === 'timeframe') {
            timeframe = stripQuotes(v);
            subSection = '';
          } else {
            subSection = k;
          }
        } else if (subSection && subSection !== 'condition' && subSection !== 'timeframe') {
          if (!v) {
            currentMatchKey = k;
            matchObj[k] = [];
          } else if (v.startsWith('[') && v.endsWith(']')) {
            currentMatchKey = null;
            matchObj[k] = v
              .slice(1, -1)
              .split(',')
              .map((p) => stripQuotes(p))
              .filter(Boolean);
          } else {
            currentMatchKey = null;
            matchObj[k] = stripQuotes(v);
          }
        }
      }
    }

    if (!title) {
      throw new Error('Sigma rule must specify a "title" field.');
    }

    let numericId = Number(idRaw);
    if (Number.isNaN(numericId) || numericId <= 0) {
      numericId = fallbackId || 200199;
    }

    let mitreId: string | null = null;
    let mitreTactic: string | null = null;
    for (const tag of tags) {
      const low = tag.toLowerCase();
      const tMatch = low.match(/attack\.(t\d{4}(?:\.\d{3})?)/);
      if (tMatch) {
        mitreId = tMatch[1].toUpperCase();
      } else if (low.startsWith('attack.')) {
        mitreTactic = low
          .slice(7)
          .replace(/_/g, ' ')
          .replace(/\b\w/g, (ch) => ch.toUpperCase());
      }
    }

    let frequency = 1;
    const freqMatch = condition.match(/count\(\)\s*>=\s*(\d+)/i);
    if (freqMatch) {
      frequency = Math.max(1, Number(freqMatch[1]));
    }

    const level = mapSigmaLevel(levelStr);
    const logType = mapLogsourceToKavalan(category, product);
    const timeframeSec = parseTimeframeSec(timeframe);
    const slug = title
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '_')
      .replace(/^_+|_+$/g, '')
      .slice(0, 64);

    return {
      id: numericId,
      name: slug || `sigma_rule_${numericId}`,
      title,
      description: description || title,
      level,
      log_type: logType,
      match: matchObj,
      frequency,
      timeframe_sec: timeframeSec,
      mitre_id: mitreId,
      mitre_tactic: mitreTactic,
      groups: ['custom', 'sigma', logType === '*' ? 'general' : logType],
      active_response: level >= 10,
      enabled: true,
      raw_sigma: rawSigma.trim(),
    };
  }

  static validateKavalanRule(payload: any): [boolean, string] {
    if (!payload || typeof payload !== 'object') {
      return [false, 'Rule payload must be a JSON object.'];
    }
    const title = String(payload.title || payload.name || '').trim();
    if (!title) {
      return [false, 'Rule requires a non-empty "title".'];
    }
    const level = Number(payload.level ?? 7);
    if (Number.isNaN(level) || level < 1 || level > 15) {
      return [false, 'Rule "level" must be an integer between 1 and 15.'];
    }
    if (payload.match !== undefined && (typeof payload.match !== 'object' || Array.isArray(payload.match))) {
      return [false, 'Rule "match" must be a key-value condition object.'];
    }
    return [true, 'ok'];
  }
}

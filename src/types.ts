export type ThreatLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'OK' | 'BENIGN';

export type UserRole = 'analyst' | 'engineer' | 'admin';

export interface UserAccount {
  id: string;
  username: string;
  display_name: string;
  email: string;
  role: UserRole;
  password_hash: string;
  salt: string;
  created_at: number;
  last_login_at: number | null;
  enabled: boolean;
}

export interface PublicUser {
  id: string;
  username: string;
  display_name: string;
  email: string;
  role: UserRole;
  created_at: number;
  last_login_at: number | null;
  enabled: boolean;
}

export interface AuditLogEntry {
  id: number;
  timestamp: number;
  actor: string;
  role: string;
  action: string;
  target_type: string;
  target_id: string;
  details: string;
  ip: string;
  prev_hash: string;
  entry_hash: string;
}

export interface AgentCertificate {
  agent_id: string;
  serial: string;
  fingerprint_sha256: string;
  subject_cn: string;
  key_version: number;
  api_key_hash: string;
  api_key_preview: string;
  cert_pem: string;
  issued_at: number;
  expires_at: number;
  revoked_serials: string[];
  tls_mode: 'mTLS_STRICT' | 'TLS_REQUIRED';
}

export interface OcsfEvent {
  version: '1.1.0';
  category_uid: number;
  category_name: string;
  class_uid: number;
  class_name: string;
  activity_id: number;
  activity_name: string;
  severity_id: number;
  severity: string;
  time: number;
  src_endpoint: { ip: string; hostname?: string; port?: number };
  dst_endpoint?: { hostname?: string; service?: string; path?: string; port?: number };
  actor: { user?: { name: string } | null; process?: { name: string; cmd_line?: string } | null };
  status: string;
}

export interface EcsEvent {
  '@timestamp': string;
  'ecs.version': '8.11';
  'event.category': string[];
  'event.action': string;
  'event.outcome': 'success' | 'failure' | 'unknown';
  'event.dataset': string;
  'source.ip': string;
  'host.name': string;
  'user.name'?: string;
  'url.path'?: string;
  'process.name'?: string;
  'process.command_line'?: string;
  'dns.question.name'?: string;
  'cloud.provider'?: string;
}

export interface CEMEvent {
  ts: number;
  ingest_ts?: number;
  host: string;
  source_ip: string;
  log_type: string;
  action: string;
  target: string;
  outcome: 'ok' | 'fail' | 'denied' | 'error' | string;
  status?: number | null;
  user?: string | null;
  raw?: string | null;
  meta?: Record<string, any>;
}

export interface IndexedEvent {
  id: number;
  timestamp: number;
  ingest_timestamp: number;
  ingest_lag_ms: number;
  agent_id: string;
  host: string;
  source_ip: string;
  log_type: string;
  action: string;
  target: string;
  outcome: string;
  status: number | null;
  user: string | null;
  tactics: Record<string, number>;
  raw: string | null;
  meta: Record<string, any>;
  ocsf?: OcsfEvent;
  ecs?: EcsEvent;
}

export interface AgentMetrics {
  cpu_pct?: number;
  mem_pct?: number;
  eps?: number;
  ip?: string;
  config_version?: number;
  [key: string]: any;
}

export interface Agent {
  id: string;
  name: string;
  ip: string;
  os: string;
  criticality?: 'CRITICAL' | 'HIGH' | 'STANDARD';
  owner?: string;
  registered_at: number;
  last_keepalive: number;
  last_event_at?: number;
  events_ingested?: number;
  parse_failures?: number;
  status: 'active' | 'disconnected';
  metrics: AgentMetrics;
  simulated?: boolean;
  tls_enabled?: boolean;
  cert_serial?: string;
  cert_fingerprint?: string;
  key_version?: number;
  binary_sha256?: string;
  tamper_status?: 'VERIFIED' | 'TAMPER_DETECTED';
  tamper_reason?: string | null;
}

export interface IncidentCase {
  id: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  assignee: string;
  waiting_on?: string;
  closure_reason?: ClosureReason | null;
  sla_due_at: number;
  cert_in_deadline_at?: number;
  cert_in_reported_at?: number | null;
  cert_in_category?: string | null;
  linked_alert_ids: number[];
  timeline: CaseTimelineEvent[];
  evidence: CaseEvidence[];
  entities: {
    ips?: string[];
    hosts?: string[];
    users?: string[];
  };
  playbooks_run: PlaybookRunHistoryItem[];
  notes: CaseNote[];
  notes_count?: number;
  created_at: number;
  updated_at: number;
}

export interface PipelineSourceHealth {
  source_id: string;
  agent_id: string;
  host: string;
  log_type: string;
  last_event_at: number;
  silent_seconds: number;
  silent_threshold_sec: number;
  is_silent: boolean;
  events_count: number;
  eps: number;
  avg_lag_ms: number;
  parse_failures: number;
  status: 'HEALTHY' | 'SILENT' | 'DEGRADED';
}

export interface LogReceiverStatus {
  id: string;
  name: string;
  protocol: 'UDP' | 'TCP' | 'TLS';
  configured_port: number;
  bound_port: number;
  listening: boolean;
  tls_cipher?: string | null;
  packets_received: number;
  events_decoded: number;
  bytes_received: number;
  last_packet_at: number | null;
  note?: string;
}

export interface ScheduledSearch {
  id: string;
  name: string;
  description: string;
  query: string;
  interval_sec: number;
  threshold_count: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  enabled: boolean;
  last_run_at: number | null;
  next_run_at: number;
  last_match_count: number;
  alerts_raised: number;
  owner: string;
  created_at: number;
}

export interface LogChainBlock {
  block_index: number;
  tier: 'HOT' | 'WARM' | 'COLD_GZIP';
  first_event_id: number;
  last_event_id: number;
  first_ts: number;
  last_ts: number;
  event_count: number;
  raw_bytes: number;
  compressed_bytes: number;
  archive_file: string | null;
  prev_block_hash: string;
  merkle_root: string;
  block_hash: string;
  sealed_at: number;
  tampered?: boolean;
}

export interface RetentionPolicy {
  hot_days: number;
  warm_days: number;
  cold_retention_days: number; // CERT-In minimum 180 days
  cert_in_mode: boolean;
  cert_in_reporting_hours: number; // 6 hours
  compress_cold_gzip: boolean;
  auto_hash_chain: boolean;
  ntp_server: string;
  ntp_offset_ms: number;
  updated_at: number;
}

export interface CertInReport {
  report_id: string;
  case_id: string;
  generated_at: number;
  generated_by: string;
  detected_at: number;
  deadline_at: number;
  within_6h_sla: boolean;
  incident_category: string;
  severity: string;
  affected_assets: string[];
  indicators_of_compromise: string[];
  summary: string;
  actions_taken: string[];
  log_retention_verified_180d: boolean;
  audit_chain_head_hash: string;
}

export interface RuleMatch {
  rule_id: number;
  level: number;
  name: string;
  description: string;
  groups: string[];
  mitre_id: string | null;
  mitre_tactic: string | null;
  fired_reason: string;
  actor_ip: string;
  host: string;
  target: string;
}

export interface CustomRule {
  id: number;
  name: string;
  title: string;
  description: string;
  level: number;
  log_type: string;
  match: Record<string, any>;
  frequency: number;
  timeframe_sec: number;
  mitre_id: string | null;
  mitre_tactic: string | null;
  groups: string[];
  active_response: boolean;
  enabled: boolean;
  raw_sigma?: string;
  created_at?: number;
  updated_at?: number;
}


export interface AgentConfigRecord {
  agent_id: string;
  version: number;
  updated_at: number;
  config: {
    localfiles: Array<{ location: string; format: string }>;
    syscheck: { directories: string[]; interval: number };
    syscollector: { interval: number; scan_on_start: boolean };
    active_response: { enabled: boolean };
  };
}

export interface CaseNote {
  id: number;
  author: string;
  note: string;
  created_at: number;
}

export interface CaseTimelineEvent {
  id: string;
  event_id?: number;
  timestamp: number;
  host: string;
  source_ip: string;
  log_type: string;
  action: string;
  outcome: string;
  raw?: string | null;
  added_by: string;
  added_at: number;
  note?: string;
}

export interface CaseEvidence {
  id: string;
  title: string;
  type: 'raw_log' | 'attachment' | 'ioc' | 'alert';
  content: string;
  added_by: string;
  added_at: number;
}

export interface PlaybookRunHistoryItem {
  playbook: string;
  executed_at: number;
  actions: string[];
}

export type ClosureReason = 'true_positive' | 'false_positive' | 'benign' | 'duplicate';


export interface WebhookConfig {
  id: string;
  name: string;
  url: string;
  type: string;
  min_level: string;
  enabled: boolean;
  created_at: number;
}

export interface NotificationSettings {
  quiet_hours_enabled: boolean;
  quiet_start: string; // HH:MM UTC or local
  quiet_end: string;
  critical_bypass: boolean;
  channels: {
    slack: boolean;
    email: boolean;
    phone_oncall: boolean;
  };
  updated_at: number;
}

export interface SoarPlaybook {
  id: string;
  name: string;
  description: string;
  trigger_type: string;
  condition: Record<string, any>;
  actions: Array<Record<string, any>>;
  is_enabled: boolean;
  execution_count: number;
  last_triggered_at: number | null;
  created_at: number;
  updated_at: number;
}

export interface SoarPlaybookRun {
  id: string;
  playbook_id: string;
  playbook_name: string;
  trigger_source: string;
  trigger_entity: string;
  status: string;
  actions_taken: string[];
  output_log: string;
  executed_at: number;
}

export interface ActiveResponseAuditEntry {
  timestamp: number;
  actor: string;
  action: string;
  note: string;
}

export interface ActiveResponseOrder {
  id: number;
  timestamp: number;
  command: string;
  actor_ip: string;
  rule_id: number;
  rule_level: number;
  reason: string;
  status: 'recommended' | 'approved' | 'pending' | 'executed' | 'unblocked' | 'rejected';
  target_agent: string;
  delivered: boolean;
  ttl_seconds: number;
  expires_at: number | null;
  recommended_by: string;
  approved_by: string | null;
  approved_at: number | null;
  audit_trail: ActiveResponseAuditEntry[];
  details: string;
}

export interface ThreatIntelIOC {
  found?: boolean;
  ioc: string;
  ioc_type: string;
  is_private?: boolean;
  is_loopback?: boolean;
  threat_score: number;
  threat_level: string;
  reputation: string;
  feed: string;
  categories: string[];
  country: string;
  country_name: string;
  asn: string;
  is_tor_exit: boolean;
  is_vpn_proxy: boolean;
  description: string;
  reports_count: number;
  first_seen?: number;
  last_seen?: number;
}

export interface SCACheck {
  id: string;
  title: string;
  status: 'PASS' | 'FAIL';
  severity: string;
  details: string;
  remediation: string;
}

export interface SCAReport {
  agent_id: string;
  host: string;
  score: number;
  total_checks: number;
  passed: number;
  failed: number;
  updated_at: number;
  checks: SCACheck[];
}

export interface VulnerabilityFinding {
  agent_id: string;
  host: string;
  cve_id: string;
  package: string;
  installed_version: string;
  fixed_version: string;
  severity: string;
  cvss: number;
  title: string;
  remediation: string;
  mitre_id: string;
  discovered_at: number;
}

export interface CorrelatedSource {
  ip: string;
  level: string;
  cross_source: boolean;
  channels: string[];
  hosts: string[];
  multi_host: boolean;
  web_score: number;
  ssh_score: number;
  tactics: Record<string, number>;
  mitre_tactics: Record<string, { id: string; name: string; tactic: string }>;
  reasons: string[];
  parts?: Record<string, number>;
  distinct_paths?: number;
  switches?: number;
  sensitive_hits?: number;
  present?: string[];
  breached?: boolean;
  top_rule?: { id: number; level: number; description: string };
  rule_matches?: Array<{
    id: number;
    level: number;
    name: string;
    desc: string;
    reason: string;
    mitre: string | null;
  }>;
  active_response?: Record<string, any> | null;
}

export interface SuppressionRule {
  id: string;
  name: string;
  rule_id: number | null;
  host: string | null;
  ip_cidr: string | null;
  time_window: string | null; // e.g. "00:00-04:00"
  reason: string;
  owner: string;
  created_at: number;
  expires_at: number | null;
  enabled: boolean;
  suppressed_hits: number;
}

export interface SavedSearch {
  id: string;
  name: string;
  description: string;
  category: 'hunt' | 'saved';
  query: {
    q?: string;
    source_ip?: string;
    log_type?: string;
    outcome?: string;
    window_sec?: number;
  };
  created_by: string;
  created_at: number;
}



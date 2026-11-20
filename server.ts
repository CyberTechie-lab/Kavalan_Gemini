import express, { NextFunction, Request, Response } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { AGENT_PY_STUB, INSTALL_SH_SCRIPT, SAMPLE_AGENT_CONF } from './src/agentAssets.js';
import { VerifiedSession } from './src/security.js';
import { SigmaRuleConverter } from './src/sigma.js';
import { KavalanPlatform } from './src/store.js';
import { UserRole } from './src/types.js';

interface AuthedRequest extends Request {
  socUser?: VerifiedSession;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PUBLIC_DIR = path.join(__dirname, 'public');

const platform = new KavalanPlatform();
const app = express();

app.use(express.json({ limit: '10mb' }));

// Global HTTP security headers & no-store caching on authenticated API telemetry
app.use((req: Request, res: Response, next: NextFunction) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (req.path.startsWith('/api/')) {
    res.setHeader('Cache-Control', 'no-store, max-age=0');
    res.setHeader('Pragma', 'no-cache');
  }
  next();
});

// Periodically evaluate scheduled searches (every 15 seconds)
setInterval(() => {
  try {
    platform.tickScheduledSearches();
  } catch {
    // non-fatal scheduler tick
  }
}, 15000);

// Static assets under /static matching original Tier 4 dashboard mount
app.use('/static', express.static(PUBLIC_DIR));

function parseSessionToken(req: Request): string | null {
  const authHdr = String(req.headers.authorization || '');
  if (authHdr.toLowerCase().startsWith('bearer ')) {
    return authHdr.slice(7).trim();
  }
  const cookieHdr = String(req.headers.cookie || '');
  for (const part of cookieHdr.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k === 'kavalan_session') {
      return decodeURIComponent(rest.join('='));
    }
  }
  return null;
}

function requireAuth(req: AuthedRequest, res: Response, next: NextFunction): void {
  const tok = parseSessionToken(req);
  const verified = platform.security.verifyToken(tok);
  if (!verified) {
    res.status(401).json({ error: 'Authentication required. Please sign in to Kavalan SOC.' });
    return;
  }
  req.socUser = verified;
  next();
}

function requireRole(...allowed: UserRole[]) {
  return (req: AuthedRequest, res: Response, next: NextFunction): void => {
    if (!req.socUser) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }
    if (!allowed.includes(req.socUser.role)) {
      const a = actorInfo(req);
      platform.security.recordAccessDenied(a.actor, a.role, req.method, req.originalUrl, allowed, a.ip);
      res.status(403).json({
        error: `Forbidden: requires role [${allowed.join(' | ')}], current role is '${req.socUser.role}'`,
        required_roles: allowed,
        current_role: req.socUser.role,
        audited: true,
      });
      return;
    }
    next();
  };
}

function actorInfo(req: AuthedRequest) {
  return {
    actor: req.socUser?.display_name || req.socUser?.username || 'SOC User',
    role: req.socUser?.role || 'analyst',
    ip: String(req.ip || req.socket.remoteAddress || '127.0.0.1').replace(/^::ffff:/, ''),
  };
}

// Root UI & Favicon
app.get('/', (_req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

app.head('/favicon.ico', (_req: Request, res: Response) => {
  res.status(200).type('image/x-icon').end();
});

app.head('/favicon.svg', (_req: Request, res: Response) => {
  res.status(200).type('image/svg+xml').end();
});

app.get('/favicon.ico', (_req: Request, res: Response) => {
  const icoPath = path.join(PUBLIC_DIR, 'favicon.ico');
  if (fs.existsSync(icoPath)) {
    res.type('image/x-icon').sendFile(icoPath);
  } else {
    res.type('image/svg+xml').sendFile(path.join(PUBLIC_DIR, 'kavalan_logo_mark.svg'));
  }
});

app.get('/favicon.svg', (_req: Request, res: Response) => {
  res.type('image/svg+xml').sendFile(path.join(PUBLIC_DIR, 'kavalan_logo_mark.svg'));
});

// --- Agent Deployment Scripts & Root CA ---

app.get('/install.sh', (_req: Request, res: Response) => {
  res.type('text/x-shellscript').send(INSTALL_SH_SCRIPT);
});

app.get('/agent/sample.conf', (_req: Request, res: Response) => {
  res.type('application/json').send(SAMPLE_AGENT_CONF);
});

app.get('/agent/agent.py', (_req: Request, res: Response) => {
  res.type('text/x-python').send(AGENT_PY_STUB);
});

app.get('/agent/:filename', (req: Request, res: Response) => {
  const fname = path.basename(String(req.params.filename || ''));
  if (fname === 'agent.conf' || fname === 'sample.conf') {
    res.type('application/json').send(SAMPLE_AGENT_CONF);
    return;
  }
  if (fname.endsWith('.py')) {
    res.type('text/x-python').send(AGENT_PY_STUB);
    return;
  }
  res.status(404).type('text/plain').send(`# Agent asset not found: ${fname}`);
});

app.get('/api/tls/ca', (_req: Request, res: Response) => {
  const creds = platform.security.getTlsServerCredentials();
  res.type('application/x-pem-file').send(creds.ca);
});

// --- Authentication, RBAC Directory & Audit Trail ---

app.post('/api/auth/login', (req: Request, res: Response) => {
  const body = req.body || {};
  const ip = String(req.ip || req.socket.remoteAddress || '127.0.0.1').replace(/^::ffff:/, '');
  const result = platform.security.authenticate(String(body.username || ''), String(body.password || ''), ip);
  if (!result.ok) {
    if (result.locked) {
      if (result.retry_after_sec) {
        res.setHeader('Retry-After', String(result.retry_after_sec));
      }
      res.status(429).json({
        error: result.error,
        locked: true,
        retry_after_sec: result.retry_after_sec || 60,
      });
      return;
    }
    res.status(401).json({ error: result.error });
    return;
  }
  res.setHeader('Set-Cookie', `kavalan_session=${encodeURIComponent(result.token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200`);
  res.json({ token: result.token, user: result.user });
});

app.get('/api/auth/session', (req: Request, res: Response) => {
  const tok = parseSessionToken(req);
  const verified = platform.security.verifyToken(tok);
  if (!verified) {
    res.status(401).json({ authenticated: false });
    return;
  }
  res.json({ authenticated: true, user: verified });
});

app.get('/api/auth/permissions', requireAuth, (req: AuthedRequest, res: Response) => {
  const role = req.socUser!.role;
  res.json({
    user: req.socUser,
    permissions: platform.security.getPermissionsForRole(role),
    matrix: platform.security.getRbacMatrix(),
  });
});

app.post('/api/auth/logout', (req: Request, res: Response) => {
  const tok = parseSessionToken(req);
  const verified = platform.security.verifyToken(tok);
  if (tok && verified) {
    platform.security.revokeToken(tok, verified.display_name, verified.role, String(req.ip || '127.0.0.1'));
  }
  res.setHeader('Set-Cookie', 'kavalan_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
  res.json({ success: true });
});

app.get('/api/auth/users', requireAuth, requireRole('admin'), (_req: AuthedRequest, res: Response) => {
  res.json({ users: platform.security.listUsers() });
});

app.post('/api/auth/users', requireAuth, requireRole('admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const out = platform.security.createUser(req.body || {}, a.actor, a.role, a.ip);
  if (!out.ok) {
    res.status(400).json({ error: out.error });
    return;
  }
  res.json({ user: out.user });
});

app.patch('/api/auth/users/:userId/role', requireAuth, requireRole('admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const result = platform.security.updateUserRole(
    String(req.params.userId),
    req.body || {},
    a.actor,
    a.role,
    a.ip,
    req.socUser?.user_id
  );
  if (!result.ok) {
    res.status(result.notFound ? 404 : 400).json({ error: result.error });
    return;
  }
  res.json({ user: result.user });
});

app.get('/api/audit', requireAuth, (req: AuthedRequest, res: Response) => {
  const items = platform.security.listAudit({
    actor: req.query.actor ? String(req.query.actor) : undefined,
    action: req.query.action ? String(req.query.action) : undefined,
    limit: Number(req.query.limit || 150),
  });
  const integrity = platform.security.verifyAuditChain();
  res.json({ entries: items, integrity });
});

app.get('/api/audit/verify', requireAuth, (_req: AuthedRequest, res: Response) => {
  res.json(platform.security.verifyAuditChain());
});

// --- Agent Transport Protocol (Per-Agent Key & mTLS Cert Verification) ---

function verifyAgentHeaders(req: Request, res: Response, agentId: string): boolean {
  const certFp = req.headers['x-agent-cert-fp'] ? String(req.headers['x-agent-cert-fp']) : undefined;
  const agentKey = req.headers['x-agent-key'] ? String(req.headers['x-agent-key']) : undefined;
  const binaryHash = req.headers['x-agent-binary-sha256'] ? String(req.headers['x-agent-binary-sha256']) : undefined;
  const check = platform.security.verifyAgentTransport(agentId, { certFp, agentKey, binaryHash });
  if (!check.ok) {
    platform.simulateAgentTamper(agentId, 'mTLS Transport Guard', 'system', false);
    res.status(403).json({ error: check.reason || 'Agent transport authentication / integrity check failed', tamper_detected: true });
    return false;
  }
  return true;
}

app.post('/api/agent/register', (req: Request, res: Response) => {
  const reg = platform.registerAgent(req.body || {});
  platform.security.recordAudit({
    actor: `agent-${reg.agent_id}`,
    role: 'agent',
    action: 'AGENT_MTLS_ENROLLED',
    target_type: 'agent',
    target_id: reg.agent_id,
    details: `Enrolled '${reg.name}' with X.509 serial=${reg.cert_serial}`,
    ip: String(req.ip || '127.0.0.1').replace(/^::ffff:/, ''),
  });
  res.json(reg);
});

app.post('/api/agent/heartbeat', (req: Request, res: Response) => {
  const body = req.body || {};
  const agentId = String(body.agent_id || '');
  if (!verifyAgentHeaders(req, res, agentId)) return;
  res.json(platform.heartbeatAgent(agentId, body.metrics || {}));
});

app.post('/api/agent/events', (req: Request, res: Response) => {
  const body = req.body || {};
  const agentId = String(body.agent_id || '001');
  if (!verifyAgentHeaders(req, res, agentId)) return;
  const events = Array.isArray(body.events) ? body.events : [];
  res.json(platform.ingestAgentEvents(agentId, events));
});

app.post('/api/agent/sca', (req: Request, res: Response) => {
  const body = req.body || {};
  const agentId = String(body.agent_id || '001');
  if (!verifyAgentHeaders(req, res, agentId)) return;
  const host = String(body.host || `agent-${agentId}`);
  const sca = platform.vulnEngine.saveScaReport(agentId, host, {
    score: body.score,
    checks: Array.isArray(body.checks) ? body.checks : [],
  });
  const vulns = Array.isArray(body.packages)
    ? platform.vulnEngine.correlatePackages(agentId, host, body.packages)
    : platform.vulnEngine.getAgentVulnerabilities(agentId);
  res.json({ status: 'ok', sca, vulnerabilities_found: vulns.length });
});

// --- Core Dashboard State & Agents Fleet ---

app.get('/api/state', requireAuth, (_req: AuthedRequest, res: Response) => {
  res.json(platform.getState());
});

app.get('/api/agents', requireAuth, (_req: AuthedRequest, res: Response) => {
  res.json({ agents: platform.listAgents() });
});

app.get('/api/agents/:agentId/cert', requireAuth, (req: AuthedRequest, res: Response) => {
  const id = String(req.params.agentId);
  const cert = platform.security.getAgentCert(id);
  if (!cert) {
    res.status(404).json({ error: 'Agent certificate not found' });
    return;
  }
  res.json({ certificate: cert, ca_fingerprint: platform.security.getTlsServerCredentials().ca_fingerprint });
});

app.post('/api/agents/:agentId/rotate-cert', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const rotated = platform.rotateAgentCertificate(String(req.params.agentId), a.actor, a.role, a.ip);
  if (!rotated) {
    res.status(404).json({ error: 'Agent not found' });
    return;
  }
  res.json({ success: true, ...rotated });
});

app.post('/api/agents/:agentId/simulate-tamper', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const restore = Boolean((req.body || {}).restore);
  const out = platform.simulateAgentTamper(String(req.params.agentId), a.actor, a.role, restore);
  if (!out) {
    res.status(404).json({ error: 'Agent not found' });
    return;
  }
  res.json(out);
});

app.delete('/api/agents/:agentId', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const id = String(req.params.agentId);
  platform.security.recordAudit({ actor: a.actor, role: a.role, action: 'AGENT_DELETED', target_type: 'agent', target_id: id, details: `Removed agent ${id}`, ip: a.ip });
  res.json(platform.deleteAgent(id));
});

app.post('/api/agents/:agentId/delete', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const id = String(req.params.agentId);
  platform.security.recordAudit({ actor: a.actor, role: a.role, action: 'AGENT_DELETED', target_type: 'agent', target_id: id, details: `Removed agent ${id}`, ip: a.ip });
  res.json(platform.deleteAgent(id));
});

app.get('/api/agents/:agentId/config', requireAuth, (req: AuthedRequest, res: Response) => {
  res.json(platform.getAgentConfig(String(req.params.agentId)));
});

app.post('/api/agents/:agentId/config', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const id = String(req.params.agentId);
  const cfg = platform.setAgentConfig(id, req.body || {});
  platform.security.recordAudit({ actor: a.actor, role: a.role, action: 'AGENT_CONFIG_UPDATED', target_type: 'agent', target_id: id, details: `Synced config v${cfg.version}`, ip: a.ip });
  res.json(cfg);
});

app.post('/api/scan', requireAuth, (_req: AuthedRequest, res: Response) => {
  res.json(platform.runDetectionPass());
});

// --- Syslog Receivers & Multi-Source Normalization Catalog ---

app.get('/api/receivers', requireAuth, (_req: AuthedRequest, res: Response) => {
  res.json({
    receivers: platform.receivers.listStatuses(),
    ca_fingerprint: platform.security.getTlsServerCredentials().ca_fingerprint,
  });
});

app.post('/api/receivers/:id/toggle', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const enable = (req.body || {}).enabled !== false;
  const st = platform.receivers.toggleReceiver(String(req.params.id), enable);
  if (!st) {
    res.status(404).json({ error: 'Receiver not found' });
    return;
  }
  platform.security.recordAudit({
    actor: a.actor,
    role: a.role,
    action: 'RECEIVER_TOGGLED',
    target_type: 'receiver',
    target_id: st.id,
    details: `${enable ? 'Started' : 'Stopped'} ${st.name} (:${st.bound_port})`,
    ip: a.ip,
  });
  res.json({ receiver: st });
});

app.post('/api/receivers/test-ingest', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const body = req.body || {};
  const raw = String(body.raw || '');
  if (!raw.trim()) {
    res.status(400).json({ error: 'Missing raw log line/JSON payload' });
    return;
  }
  const out = platform.ingestRawLine(raw, String(body.host || 'syslog-gw'), String(body.remote_ip || '10.0.1.250'), String(body.receiver_id || 'syslog-udp'));
  platform.security.recordAudit({
    actor: a.actor,
    role: a.role,
    action: 'SYSLOG_TEST_INGEST',
    target_type: 'receiver',
    target_id: String(body.receiver_id || 'syslog-udp'),
    details: `Ingested test telemetry (decoded=${out.decoded}, log_type=${out.event?.log_type || 'none'})`,
    ip: a.ip,
  });
  res.json(out);
});

app.get('/api/sources/catalog', requireAuth, (_req: AuthedRequest, res: Response) => {
  res.json(platform.getLogSourcesCatalog());
});

// --- Discover Search (Piped Language), Scheduled Searches, Aggregations & 360 Dossier ---

app.post('/api/search', requireAuth, (req: AuthedRequest, res: Response) => {
  res.json(platform.searchEvents(req.body || {}));
});

app.post('/api/search/alerts', requireAuth, (req: AuthedRequest, res: Response) => {
  res.json(platform.searchAlerts(req.body || {}));
});

app.get('/api/scheduled-searches', requireAuth, (_req: AuthedRequest, res: Response) => {
  res.json({ scheduled_searches: platform.listScheduledSearches() });
});

app.post('/api/scheduled-searches', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const item = platform.createScheduledSearch({ ...(req.body || {}), owner: a.actor });
  platform.security.recordAudit({
    actor: a.actor,
    role: a.role,
    action: 'SCHEDULED_SEARCH_CREATED',
    target_type: 'scheduled_search',
    target_id: item.id,
    details: `Created scheduled search '${item.name}' (query="${item.query}")`,
    ip: a.ip,
  });
  res.json({ scheduled_search: item });
});

app.post('/api/scheduled-searches/:id/run', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const out = platform.runScheduledSearch(String(req.params.id), a.actor);
  if (!out) {
    res.status(404).json({ error: 'Scheduled search not found' });
    return;
  }
  res.json(out);
});

app.post('/api/scheduled-searches/:id/toggle', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  const out = platform.toggleScheduledSearch(String(req.params.id), (req.body || {}).enabled);
  if (!out) {
    res.status(404).json({ error: 'Scheduled search not found' });
    return;
  }
  res.json({ scheduled_search: out });
});

app.delete('/api/scheduled-searches/:id', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  res.json({ success: platform.deleteScheduledSearch(String(req.params.id)) });
});

// --- Alert Triage, Feedback, Bulk Actions & No-Code Suppressions ---

app.get('/api/alerts/:alertId/triage', requireAuth, (req: AuthedRequest, res: Response) => {
  const id = Number(req.params.alertId || 0);
  const triage = platform.getAlertTriage(id);
  if (!triage) {
    res.status(404).json({ error: 'Alert not found' });
    return;
  }
  res.json(triage);
});

app.post('/api/alerts/:alertId/feedback', requireAuth, (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const id = Number(req.params.alertId || 0);
  const body = req.body || {};
  const fb = body.feedback;
  if (!['true_positive', 'false_positive', 'benign'].includes(fb)) {
    res.status(400).json({ error: 'Invalid feedback verdict' });
    return;
  }
  const updated = platform.submitAlertFeedback(id, fb, a.actor, String(body.note || ''));
  if (!updated) {
    res.status(404).json({ error: 'Alert not found' });
    return;
  }
  platform.security.recordAudit({
    actor: a.actor,
    role: a.role,
    action: fb === 'true_positive' ? 'ALERT_MARKED_TP' : 'ALERT_CLOSED_FEEDBACK',
    target_type: 'alert',
    target_id: String(id),
    details: `Marked Alert #${id} (${updated.rule_name}) as ${fb}${body.note ? ': ' + body.note : ''}`,
    ip: a.ip,
  });
  res.json({ success: true, alert: updated });
});

app.post('/api/alerts/bulk', requireAuth, (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const body = req.body || {};
  const ids = Array.isArray(body.alert_ids) ? body.alert_ids.map(Number) : [];
  const action = String(body.action || '');
  if (!['true_positive', 'false_positive', 'benign', 'suppress', 'escalate', 'close'].includes(action)) {
    res.status(400).json({ error: 'Invalid bulk triage action' });
    return;
  }
  const out = platform.bulkAlertTriage(ids, action as any, { analyst: a.actor, reason: body.reason, owner: a.actor });
  platform.security.recordAudit({
    actor: a.actor,
    role: a.role,
    action: 'ALERTS_BULK_TRIAGE',
    target_type: 'alerts',
    target_id: ids.join(','),
    details: `Bulk action '${action}' on ${out.processed} alerts`,
    ip: a.ip,
  });
  res.json(out);
});

app.get('/api/suppressions', requireAuth, (_req: AuthedRequest, res: Response) => {
  res.json({ suppressions: platform.listSuppressions() });
});

app.post('/api/suppressions', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const sup = platform.createSuppression({ ...(req.body || {}), owner: a.actor });
  platform.security.recordAudit({
    actor: a.actor,
    role: a.role,
    action: 'SUPPRESSION_CREATED',
    target_type: 'suppression',
    target_id: sup.id,
    details: `Created suppression '${sup.name}' (host=${sup.host || '*'}, ip=${sup.ip_cidr || '*'})`,
    ip: a.ip,
  });
  res.json({ suppression: sup });
});

app.post('/api/suppressions/:id/toggle', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const updated = platform.toggleSuppression(String(req.params.id), (req.body || {}).enabled);
  if (!updated) {
    res.status(404).json({ error: 'Suppression not found' });
    return;
  }
  platform.security.recordAudit({
    actor: a.actor,
    role: a.role,
    action: 'SUPPRESSION_TOGGLED',
    target_type: 'suppression',
    target_id: updated.id,
    details: `Set enabled=${updated.enabled}`,
    ip: a.ip,
  });
  res.json({ success: true, suppression: updated });
});

app.delete('/api/suppressions/:id', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const id = String(req.params.id);
  const ok = platform.deleteSuppression(id);
  if (ok) {
    platform.security.recordAudit({
      actor: a.actor,
      role: a.role,
      action: 'SUPPRESSION_DELETED',
      target_type: 'suppression',
      target_id: id,
      details: `Deleted suppression rule ${id}`,
      ip: a.ip,
    });
  }
  res.json({ success: ok });
});

// --- Saved Searches & Hunting Library ---

app.get('/api/saved-searches', requireAuth, (_req: AuthedRequest, res: Response) => {
  res.json({ searches: platform.listSavedSearches() });
});

app.post('/api/saved-searches', requireAuth, (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  res.json({ search: platform.saveSearch({ ...(req.body || {}), created_by: a.actor }) });
});

app.delete('/api/saved-searches/:id', requireAuth, (req: AuthedRequest, res: Response) => {
  res.json({ success: platform.deleteSavedSearch(String(req.params.id)) });
});

app.post('/api/aggregate', requireAuth, (req: AuthedRequest, res: Response) => {
  res.json(platform.aggregate(req.body || {}));
});

app.post('/api/fields/stats', requireAuth, (req: AuthedRequest, res: Response) => {
  res.json(platform.getFieldStats(req.body || {}));
});

app.get('/api/events/:eventId/context', requireAuth, (req: AuthedRequest, res: Response) => {
  const eventId = Number(req.params.eventId || 0);
  const window = Number(req.query.window || 5);
  res.json(platform.getSurroundingEvents(eventId, window));
});

app.get('/api/entity/ip/:ip', requireAuth, (req: AuthedRequest, res: Response) => {
  res.json(platform.getIpDossier(String(req.params.ip)));
});

// --- Attack Topology Graph & Red Team Simulation Lab ---

app.get('/api/graph/attack-topology', requireAuth, (req: AuthedRequest, res: Response) => {
  const windowSec = Number(req.query.window || 7200);
  const ip = req.query.ip ? String(req.query.ip) : undefined;
  res.json(platform.getAttackGraph(windowSec, ip));
});

app.post('/api/simulate', requireAuth, requireRole('engineer', 'admin'), async (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const body = req.body || {};
  const scenario = String(body.scenario || 'cross_source');
  const host = String(body.host || 'server');
  const agentId = String(body.agent_id || '005');
  const targetIp = String(body.target_ip || '172.16.10.134');
  const result = await platform.simulateScenario(scenario, host, agentId, targetIp);
  platform.security.recordAudit({
    actor: a.actor,
    role: a.role,
    action: 'SIMULATION_EXECUTED',
    target_type: 'simulation',
    target_id: scenario,
    details: `Ran Red Team scenario '${scenario}' targeting ${host}`,
    ip: a.ip,
  });
  res.json(result);
});

// --- Live HTTP Canary / AI-Agent Tarpit Deception Endpoints ---

app.get('/robots.txt', (_req: Request, res: Response) => {
  res.type('text/plain').send(
    [
      'User-agent: *',
      'Disallow: /api/v1/internal/admin-keys',
      'Disallow: /api/v1/internal/shadow-backup.json',
      'Disallow: /.env.production',
    ].join('\n')
  );
});

app.get(['/.env.production', '/api/v1/internal/admin-keys', '/api/v1/internal/shadow-backup.json'], (req: Request, res: Response) => {
  const clientIp = String(req.headers['x-forwarded-for'] || req.ip || req.socket.remoteAddress || '198.51.100.250').split(',')[0].trim();
  const ua = String(req.headers['user-agent'] || 'autonomous-crawler');
  const trap = platform.triggerCanaryTrap({
    path: req.path,
    method: req.method,
    ip: clientIp,
    userAgent: ua,
  });
  if (req.path === '/.env.production') {
    res.status(200).type('text/plain').send(
      `# KAVALAN DECEPTION CANARY TARPIT (alert_id=${trap.alert?.id || 'pending'})\nDB_HOST=10.254.0.99\nAWS_ACCESS_KEY_ID=AKIAKAVALANTARPIT0000\nCANARY_TRAP=true\n`
    );
    return;
  }
  res.status(200).json({
    status: 'canary_decoy_token',
    trap_triggered: true,
    alert_id: trap.alert?.id || null,
    canary_event_id: trap.event_id,
    decoy_api_key: 'kavalan_canary_decoy_do_not_use_009911',
  });
});

app.get('/api/canary/status', requireAuth, (_req: AuthedRequest, res: Response) => {
  res.json(platform.getCanaryStatus());
});

app.post('/api/canary/probe', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  const body = req.body || {};
  const trap = platform.triggerCanaryTrap({
    path: String(body.path || '/api/v1/internal/admin-keys'),
    method: 'GET',
    ip: String(body.ip || '198.51.100.244'),
    userAgent: String(body.user_agent || 'Strix-Autonomous-Agent/2.4'),
  });
  res.json({ success: true, ...trap });
});

// --- Custom Detection Rules, Sigma Studio & Logtest ---

app.get('/api/rules', requireAuth, (_req: AuthedRequest, res: Response) => {
  res.json({ rules: platform.listRules() });
});

app.get('/api/rules/templates', requireAuth, (_req: AuthedRequest, res: Response) => {
  res.json({ templates: SigmaRuleConverter.getTemplates() });
});

app.post('/api/rules/sigma/convert', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  try {
    const rawSigma = String((req.body || {}).sigma_yaml || (req.body || {}).yaml || (req.body || {}).sigma || '');
    const rule = SigmaRuleConverter.convert(rawSigma);
    res.json({ success: true, rule });
  } catch (err: any) {
    res.status(400).json({ error: err?.message || 'Failed to parse Sigma rule' });
  }
});

app.post('/api/rules', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const result = platform.saveCustomRule(req.body || {});
  if (!result.success) {
    res.status(400).json({ error: result.error });
    return;
  }
  platform.security.recordAudit({
    actor: a.actor,
    role: a.role,
    action: 'DETECTION_RULE_SAVED',
    target_type: 'rule',
    target_id: String(result.rule?.id || ''),
    details: `Saved rule '${result.rule?.title}' (level ${result.rule?.level})`,
    ip: a.ip,
  });
  res.json(result);
});

app.delete('/api/rules/:ruleId', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const id = Number(req.params.ruleId);
  const ok = platform.deleteCustomRule(id);
  if (ok) {
    platform.security.recordAudit({ actor: a.actor, role: a.role, action: 'DETECTION_RULE_DELETED', target_type: 'rule', target_id: String(id), details: `Deleted rule #${id}`, ip: a.ip });
  }
  res.json({ success: ok, rule_id: id });
});

app.post('/api/rules/:ruleId/toggle', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const id = Number(req.params.ruleId);
  const enabled = (req.body || {}).enabled;
  const updated = platform.toggleCustomRule(id, enabled);
  if (!updated) {
    res.status(404).json({ error: 'Rule not found' });
    return;
  }
  platform.security.recordAudit({ actor: a.actor, role: a.role, action: 'DETECTION_RULE_TOGGLED', target_type: 'rule', target_id: String(id), details: `Rule #${id} enabled=${updated.enabled}`, ip: a.ip });
  res.json({ success: true, rule: updated });
});

app.post('/api/rules/test', requireAuth, (req: AuthedRequest, res: Response) => {
  const body = req.body || {};
  res.json(platform.testCustomRule(body.rule || {}, String(body.log || ''), String(body.host || 'web-01')));
});

app.post('/api/logtest', requireAuth, (req: AuthedRequest, res: Response) => {
  const body = req.body || {};
  res.json(platform.logtest(String(body.log || ''), String(body.host || 'logtest-agent')));
});

// --- Active Response & Containment ---

app.get('/api/active_response/actions', requireAuth, (_req: AuthedRequest, res: Response) => {
  res.json({ actions: platform.activeResponse.getAllActions() });
});

app.post('/api/active_response/dry-run', requireAuth, (req: AuthedRequest, res: Response) => {
  const body = req.body || {};
  res.json(
    platform.activeResponse.dryRunAction({
      command: String(body.action || body.command || 'firewall-drop'),
      actor_ip: String(body.target || body.actor_ip || '203.0.113.154'),
      target_agent: String(body.target_agent || 'all'),
      timeout_sec: Number(body.timeout ?? 600),
    })
  );
});

app.post('/api/active_response/trigger', requireAuth, (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const body = req.body || {};
  const target = String(body.target || body.actor_ip || '');
  if (!target) {
    res.status(400).json({ error: 'Missing target IP/entity' });
    return;
  }
  const mode = body.mode === 'recommend' ? 'recommend' : 'execute';
  if (mode === 'execute' && req.socUser!.role === 'analyst') {
    platform.security.recordAccessDenied(a.actor, a.role, req.method, req.originalUrl, ['engineer', 'admin'], a.ip);
    res.status(403).json({
      error: 'Analysts may queue containment recommendations; direct execution requires engineer or admin role.',
      required_roles: ['engineer', 'admin'],
      current_role: req.socUser!.role,
      audited: true,
    });
    return;
  }

  const order = platform.activeResponse.triggerAction({
    command: String(body.action || body.command || 'firewall-drop'),
    actor_ip: target,
    reason: String(body.reason || 'Manual SOC Containment Order'),
    target_agent: String(body.target_agent || 'all'),
    timeout_sec: Number(body.timeout || 600),
    rule_level: Number(body.rule_level || 12),
    mode,
    actor: a.actor,
  });

  platform.security.recordAudit({
    actor: a.actor,
    role: a.role,
    action: mode === 'recommend' ? 'ACTIVE_RESPONSE_RECOMMENDED' : 'ACTIVE_RESPONSE_EXECUTED',
    target_type: 'active_response',
    target_id: String(order.id),
    details: `${order.command} targeting ${order.actor_ip} on ${order.target_agent} (mode=${mode})`,
    ip: a.ip,
  });

  res.json({
    status: order.status,
    order,
    command_id: order.id,
    action: order.command,
    target: order.actor_ip,
    target_agent: order.target_agent,
    timestamp: order.timestamp,
  });
});

app.post('/api/active_response/:id/approve', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const id = Number(req.params.id || 0);
  const order = platform.activeResponse.approveAction(id, a.actor);
  if (!order) {
    res.status(404).json({ error: 'Recommended containment order not found' });
    return;
  }
  platform.security.recordAudit({
    actor: a.actor,
    role: a.role,
    action: 'ACTIVE_RESPONSE_APPROVED',
    target_type: 'active_response',
    target_id: String(id),
    details: `Approved & dispatched ${order.command} -> ${order.actor_ip}`,
    ip: a.ip,
  });
  res.json({ success: true, order });
});

app.post('/api/active_response/:id/reject', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const id = Number(req.params.id || 0);
  const body = req.body || {};
  const order = platform.activeResponse.rejectAction(id, a.actor, String(body.note || 'Rejected by supervisor'));
  if (!order) {
    res.status(404).json({ error: 'Recommended containment order not found' });
    return;
  }
  platform.security.recordAudit({
    actor: a.actor,
    role: a.role,
    action: 'ACTIVE_RESPONSE_REJECTED',
    target_type: 'active_response',
    target_id: String(id),
    details: `Rejected containment #${id}: ${body.note || ''}`,
    ip: a.ip,
  });
  res.json({ success: true, order });
});

app.post('/api/active_response/unblock', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const body = req.body || {};
  const id = Number(body.id || 0);
  const ok = platform.activeResponse.unblockAction(id, a.actor);
  if (!ok) {
    res.status(404).json({ error: 'Active response order not found' });
    return;
  }
  platform.security.recordAudit({
    actor: a.actor,
    role: a.role,
    action: 'ACTIVE_RESPONSE_UNBLOCKED',
    target_type: 'active_response',
    target_id: String(id),
    details: `Released containment order #${id}`,
    ip: a.ip,
  });
  res.json({ status: 'unblocked', id });
});

// --- SCA & Vulnerability Posture ---

app.get('/api/sca/summary', requireAuth, (_req: AuthedRequest, res: Response) => {
  res.json(platform.vulnEngine.getFleetSummary());
});

app.get('/api/sca/agent/:agentId', requireAuth, (req: AuthedRequest, res: Response) => {
  const agentId = String(req.params.agentId);
  res.json({
    sca: platform.vulnEngine.getAgentSca(agentId),
    vulnerabilities: platform.vulnEngine.getAgentVulnerabilities(agentId),
  });
});

app.get('/api/vuln/all', requireAuth, (_req: AuthedRequest, res: Response) => {
  res.json({ vulnerabilities: platform.vulnEngine.getAllVulnerabilities() });
});

// --- Incident Cases & Autonomous SOAR Playbooks ---

app.get('/api/cases', requireAuth, (req: AuthedRequest, res: Response) => {
  const status = req.query.status ? String(req.query.status) : undefined;
  const severity = req.query.severity ? String(req.query.severity) : undefined;
  res.json({ cases: platform.listCases(status, severity) });
});

app.post('/api/cases', requireAuth, (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const created = platform.createCase(req.body || {});
  platform.security.recordAudit({
    actor: a.actor,
    role: a.role,
    action: 'CASE_CREATED',
    target_type: 'case',
    target_id: created.id,
    details: `Opened case ${created.id} (${created.severity}): ${created.title}`,
    ip: a.ip,
  });
  res.json(created);
});

app.get('/api/cases/handover', requireAuth, (_req: AuthedRequest, res: Response) => {
  res.json(platform.getShiftHandover());
});

app.get('/api/cases/:caseId', requireAuth, (req: AuthedRequest, res: Response) => {
  const c = platform.getCase(String(req.params.caseId));
  if (!c) {
    res.status(404).json({ error: 'Case not found' });
    return;
  }
  res.json(c);
});

app.patch('/api/cases/:caseId/status', requireAuth, (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const c = platform.updateCaseStatus(String(req.params.caseId), req.body || {});
  if (!c) {
    res.status(404).json({ error: 'Case not found' });
    return;
  }
  platform.security.recordAudit({
    actor: a.actor,
    role: a.role,
    action: 'CASE_UPDATED',
    target_type: 'case',
    target_id: c.id,
    details: `Status=${c.status}, assignee=${c.assignee}, closure=${c.closure_reason || '-'}`,
    ip: a.ip,
  });
  res.json(c);
});

app.post('/api/cases/:caseId/notes', requireAuth, (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const body = req.body || {};
  const c = platform.addCaseNote(String(req.params.caseId), String(body.note || ''), a.actor);
  if (!c) {
    res.status(404).json({ error: 'Case not found' });
    return;
  }
  res.json(c);
});

app.post('/api/cases/:caseId/timeline', requireAuth, (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const c = platform.addCaseTimelineEvent(String(req.params.caseId), { ...(req.body || {}), added_by: a.actor });
  if (!c) {
    res.status(404).json({ error: 'Case not found' });
    return;
  }
  res.json(c);
});

app.post('/api/cases/:caseId/evidence', requireAuth, (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const c = platform.addCaseEvidence(String(req.params.caseId), { ...(req.body || {}), added_by: a.actor });
  if (!c) {
    res.status(404).json({ error: 'Case not found' });
    return;
  }
  res.json(c);
});

app.get('/api/cases/:caseId/timeline/export', requireAuth, (req: AuthedRequest, res: Response) => {
  const fmt = (String(req.query.format || 'json').toLowerCase()) as 'json' | 'csv' | 'markdown';
  const exp = platform.exportCaseTimeline(String(req.params.caseId), fmt);
  if (!exp) {
    res.status(404).json({ error: 'Case not found' });
    return;
  }
  res.setHeader('Content-Type', exp.contentType);
  res.setHeader('Content-Disposition', `attachment; filename="${exp.filename}"`);
  res.send(exp.body);
});

app.post('/api/cases/:caseId/playbook', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const playbook = String((req.body || {}).playbook || 'full-containment');
  const out = platform.runCasePlaybook(String(req.params.caseId), playbook);
  platform.security.recordAudit({
    actor: a.actor,
    role: a.role,
    action: 'CASE_PLAYBOOK_RUN',
    target_type: 'case',
    target_id: String(req.params.caseId),
    details: `Executed playbook '${playbook}'`,
    ip: a.ip,
  });
  res.json(out);
});

app.get('/api/soar/playbooks', requireAuth, (_req: AuthedRequest, res: Response) => {
  res.json({ playbooks: platform.soarPlaybooks.listPlaybooks() });
});

app.post('/api/soar/playbooks/:playbookId/toggle', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  const id = String(req.params.playbookId);
  const enabled = Boolean((req.body || {}).enabled);
  const ok = platform.soarPlaybooks.togglePlaybook(id, enabled);
  res.json({ success: ok, id, is_enabled: enabled });
});

app.post('/api/soar/playbooks/:playbookId/dry-run', requireAuth, (req: AuthedRequest, res: Response) => {
  const id = String(req.params.playbookId);
  const target = String((req.body || {}).target || '203.0.113.154');
  const host = String((req.body || {}).host || 'web-01');
  const preview = platform.soarPlaybooks.dryRunPlaybook(id, target, host);
  if (!preview) {
    res.status(404).json({ error: 'Playbook not found' });
    return;
  }
  res.json(preview);
});

app.post('/api/soar/playbooks/:playbookId/run', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const id = String(req.params.playbookId);
  const target = String((req.body || {}).target || '203.0.113.154');
  const run = platform.soarPlaybooks.runManual(id, target);
  if (!run) {
    res.status(404).json({ error: 'Playbook not found' });
    return;
  }
  platform.security.recordAudit({
    actor: a.actor,
    role: a.role,
    action: 'SOAR_PLAYBOOK_EXECUTED',
    target_type: 'playbook',
    target_id: id,
    details: `Triggered SOAR playbook '${id}' against ${target}`,
    ip: a.ip,
  });
  res.json(run);
});

app.get('/api/soar/playbook-runs', requireAuth, (req: AuthedRequest, res: Response) => {
  const limit = Number(req.query.limit || 20);
  res.json({ runs: platform.soarPlaybooks.getRecentRuns(limit) });
});

// --- Retention, Hash-Chain Verification, Backup/Restore & CERT-In 180d / 6h Compliance ---

app.get('/api/retention/status', requireAuth, (_req: AuthedRequest, res: Response) => {
  const idx = platform.getIndexerStats();
  res.json(platform.retention.getStatus(idx.total_events));
});

app.post('/api/retention/policy', requireAuth, requireRole('admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const updated = platform.retention.updatePolicy(req.body || {});
  platform.security.recordAudit({
    actor: a.actor,
    role: a.role,
    action: 'RETENTION_POLICY_UPDATED',
    target_type: 'retention',
    target_id: `${updated.cold_retention_days}d`,
    details: `Updated retention: cold=${updated.cold_retention_days}d, cert_in=${updated.cert_in_mode}, gzip=${updated.compress_cold_gzip}`,
    ip: a.ip,
  });
  res.json({ policy: updated });
});

app.post('/api/retention/archive-now', requireAuth, requireRole('admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const hits = platform.searchEvents({ limit: 500 }).hits;
  const blk = platform.retention.sealEventBatch(hits, 'COLD_GZIP');
  platform.security.recordAudit({
    actor: a.actor,
    role: a.role,
    action: 'ARCHIVE_BLOCK_SEALED',
    target_type: 'log_block',
    target_id: String(blk?.block_index || 'latest'),
    details: blk ? `Sealed gzipped block #${blk.block_index} (${blk.event_count} events, ${blk.compressed_bytes}B)` : 'All events already sealed',
    ip: a.ip,
  });
  res.json({ block: blk, status: platform.retention.getStatus(platform.getIndexerStats().total_events) });
});

app.post('/api/retention/verify-chain', requireAuth, (_req: AuthedRequest, res: Response) => {
  res.json(platform.retention.verifyChain());
});

app.post('/api/retention/simulate-tamper', requireAuth, requireRole('admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const restore = Boolean((req.body || {}).restore);
  const out = platform.retention.simulateBlockTamper(restore);
  platform.security.recordAudit({
    actor: a.actor,
    role: a.role,
    action: restore ? 'ARCHIVE_CHAIN_RESTORED' : 'ARCHIVE_TAMPER_SIMULATED',
    target_type: 'log_block',
    target_id: String(out.block_index || 1),
    details: restore ? 'Restored clean block digest' : 'Simulated hash modification in sealed cold block',
    ip: a.ip,
  });
  res.json({ ...out, chain: platform.retention.verifyChain() });
});

app.get('/api/retention/backup', requireAuth, requireRole('admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const bundle = platform.retention.createSignedBackup({
    suppressions: platform.listSuppressions(),
    rules: platform.listRules(),
    scheduled_searches: platform.listScheduledSearches(),
    cases: platform.listCases(),
    audit_head: platform.security.verifyAuditChain().head_hash,
  });
  platform.security.recordAudit({
    actor: a.actor,
    role: a.role,
    action: 'BACKUP_EXPORTED',
    target_type: 'backup',
    target_id: bundle.sha256_integrity.slice(0, 16),
    details: `Exported signed Kavalan SIEM backup bundle (${bundle.blocks.length} archive blocks)`,
    ip: a.ip,
  });
  res.json(bundle);
});

app.post('/api/retention/restore', requireAuth, requireRole('admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const check = platform.retention.verifyBackupBundle(req.body || {});
  if (!check.valid) {
    res.status(400).json({ error: check.reason });
    return;
  }
  platform.security.recordAudit({
    actor: a.actor,
    role: a.role,
    action: 'BACKUP_RESTORED',
    target_type: 'backup',
    target_id: String((req.body || {}).sha256_integrity || '').slice(0, 16),
    details: 'Verified SHA-256 signature and restored SOC retention policy & configuration bundle',
    ip: a.ip,
  });
  res.json({ success: true, message: 'Backup integrity verified and configuration restored.' });
});

app.get('/api/compliance/certin', requireAuth, (_req: AuthedRequest, res: Response) => {
  const now = Math.floor(Date.now() / 1000);
  const ret = platform.retention.getStatus(platform.getIndexerStats().total_events);
  const reportableCases = platform
    .listCases()
    .filter((c) => c.severity === 'CRITICAL' || c.severity === 'HIGH')
    .map((c) => {
      const deadline = c.cert_in_deadline_at || c.created_at + 6 * 3600;
      return {
        case_id: c.id,
        title: c.title,
        severity: c.severity,
        status: c.status,
        detected_at: c.created_at,
        deadline_at: deadline,
        remaining_sec: Math.max(0, deadline - now),
        overdue: !c.cert_in_reported_at && now > deadline,
        reported_at: c.cert_in_reported_at || null,
        category: c.cert_in_category || 'Cyber security incident',
      };
    });
  res.json({
    cert_in: ret.cert_in,
    reports: ret.cert_in_reports,
    reportable_cases: reportableCases,
  });
});

app.post('/api/compliance/certin/report/:caseId', requireAuth, (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const c = platform.getCase(String(req.params.caseId));
  if (!c) {
    res.status(404).json({ error: 'Incident case not found' });
    return;
  }
  const auditHead = platform.security.verifyAuditChain().head_hash;
  const rep = platform.retention.generateCertInReport(c, a.actor, auditHead, (req.body || {}).category);
  platform.security.recordAudit({
    actor: a.actor,
    role: a.role,
    action: 'CERTIN_REPORT_GENERATED',
    target_type: 'case',
    target_id: c.id,
    details: `Generated CERT-In 6-hour report ${rep.report_id} (within_6h=${rep.within_6h_sla})`,
    ip: a.ip,
  });
  res.json({ report: rep });
});

// --- Pipeline Health, MITRE Coverage, SOC Reporting & Notification Quiet Hours ---

app.get('/api/health/pipeline', requireAuth, (_req: AuthedRequest, res: Response) => {
  res.json(platform.getPipelineHealth());
});

app.post('/api/health/simulate-silent', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  const a = actorInfo(req);
  const sourceId = (req.body || {}).source_id ? String((req.body || {}).source_id) : undefined;
  const mins = Number((req.body || {}).minutes || 40);
  const out = platform.toggleSimulateSilentSource(sourceId, mins);
  platform.security.recordAudit({
    actor: a.actor,
    role: a.role,
    action: out.simulated_silent ? 'PIPELINE_SILENT_SIMULATED' : 'PIPELINE_SILENT_RESTORED',
    target_type: 'pipeline_source',
    target_id: String(out.source_id || ''),
    details: out.simulated_silent ? `Simulated ${mins}m silence on ${out.source_id}` : `Restored ${out.source_id}`,
    ip: a.ip,
  });
  res.json(out);
});

app.get('/api/mitre/coverage', requireAuth, (_req: AuthedRequest, res: Response) => {
  res.json(platform.getMitreCoverage());
});

app.get('/api/reports/summary', requireAuth, (req: AuthedRequest, res: Response) => {
  const period = String(req.query.period || 'daily').toLowerCase() === 'weekly' ? 'weekly' : 'daily';
  res.json(platform.getSocReport(period));
});

app.get('/api/notifications/settings', requireAuth, (_req: AuthedRequest, res: Response) => {
  res.json(platform.getNotificationSettings());
});

app.post('/api/notifications/settings', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  res.json(platform.saveNotificationSettings(req.body || {}));
});

// --- Webhooks & Threat Intelligence ---

app.get('/api/webhooks', requireAuth, (_req: AuthedRequest, res: Response) => {
  res.json({ webhooks: platform.listWebhooks() });
});

app.post('/api/webhooks', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  res.json({ webhook: platform.saveWebhook(req.body || {}) });
});

app.delete('/api/webhooks/:webhookId', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  res.json({ success: platform.deleteWebhook(String(req.params.webhookId)) });
});

app.post('/api/webhooks/test', requireAuth, (_req: AuthedRequest, res: Response) => {
  const count = platform.dispatchWebhook('test_ping', { message: 'Kavalan SIEM Test Notification' });
  const inQuiet = platform.isInQuietHours();
  res.json({
    status: 'ok',
    message:
      count === 0 && inQuiet
        ? 'Suppressed: Quiet Hours active (non-critical test alerts held until quiet window ends).'
        : `Test notification dispatched to ${count} active webhook(s).`,
  });
});

app.get('/api/threat-intel/lookup/:ioc', requireAuth, (req: AuthedRequest, res: Response) => {
  res.json(platform.threatIntel.lookup(String(req.params.ioc)));
});

app.get('/api/threat-intel/summary', requireAuth, (_req: AuthedRequest, res: Response) => {
  res.json(platform.threatIntel.getSummary());
});

app.post('/api/threat-intel/iocs', requireAuth, requireRole('engineer', 'admin'), (req: AuthedRequest, res: Response) => {
  const body = req.body || {};
  if (!body.ioc) {
    res.status(400).json({ error: 'Missing ioc field' });
    return;
  }
  res.json({ ioc: platform.threatIntel.addIoc(body) });
});

// --- Gemini AI & Threat Analyst Copilot ---

app.post('/api/ai/analyze', requireAuth, async (req: AuthedRequest, res: Response) => {
  const ip = (req.body || {}).ip ? String((req.body || {}).ip) : null;
  const st = platform.getState();
  const analysis = await platform.aiAnalyst.analyzeActor(ip, st.sources, [], st.alerts);
  res.json(analysis);
});

app.post('/api/ai/chat', requireAuth, async (req: AuthedRequest, res: Response) => {
  const msg = String((req.body || {}).message || '');
  const st = platform.getState();
  const reply = await platform.aiAnalyst.chat(msg, {
    sources: st.sources,
    alerts: st.alerts,
    totalEvents: st.indexer.total_events,
    activeAgents: st.active_agents,
  });
  res.json(reply);
});

app.get(['/api/gemini/model-info', '/api/sec-llm/model-info'], requireAuth, (_req: AuthedRequest, res: Response) => {
  res.json(platform.gemini.getModelInfo());
});

app.get('/api/gemini/config', requireAuth, (_req: AuthedRequest, res: Response) => {
  res.json(platform.gemini.getConfigStatus());
});

app.post('/api/gemini/config', requireAuth, requireRole('admin'), (req: AuthedRequest, res: Response) => {
  const body = req.body || {};
  res.json(platform.gemini.setConfig(body.api_key, body.model));
});

app.post(['/api/gemini/generate', '/api/sec-llm/generate'], requireAuth, async (req: AuthedRequest, res: Response) => {
  const body = req.body || {};
  const prompt = String(body.prompt || '');
  if (!prompt) {
    res.status(400).json({ error: 'Prompt is required' });
    return;
  }
  const out = await platform.gemini.generate(prompt);
  res.json(out);
});

app.post(['/api/gemini/explain', '/api/sec-llm/explain'], requireAuth, async (req: AuthedRequest, res: Response) => {
  const body = req.body || {};
  const out = await platform.gemini.explainAlert({
    alert_summary: String(body.alert_summary || body.summary || ''),
    ip: body.ip,
    tactics: body.tactics,
    level: body.level,
  });
  res.json(out);
});

const PORT = Number(process.env.PORT) || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[*] Kavalan SIEM Unified Platform (Node.js/Express) listening on http://0.0.0.0:${PORT}`);
});

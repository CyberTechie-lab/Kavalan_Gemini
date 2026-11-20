import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { AgentCertificate, AuditLogEntry, PublicUser, UserAccount, UserRole } from './types.js';

const CERTS_DIR = path.join(process.cwd(), 'data', 'certs');
const AGENTS_CERTS_DIR = path.join(CERTS_DIR, 'agents');

export const DEFAULT_AGENT_BINARY_SHA256 = crypto
  .createHash('sha256')
  .update('kavalan-agent-v4.2.0-signed-binary')
  .digest('hex');

export interface VerifiedSession {
  user_id: string;
  username: string;
  display_name: string;
  role: UserRole;
  iat: number;
  exp: number;
}

export interface RbacCapabilityRow {
  domain: string;
  action: string;
  analyst: boolean;
  engineer: boolean;
  admin: boolean;
}

export const ROLE_PERMISSIONS: Record<UserRole, string[]> = {
  analyst: [
    'alerts:read',
    'alerts:triage',
    'alerts:feedback',
    'alerts:bulk',
    'cases:read',
    'cases:create',
    'cases:update',
    'cases:notes',
    'cases:certin_report',
    'search:read',
    'saved_searches:manage',
    'active_response:recommend',
    'active_response:dry_run',
    'audit:read',
    'ai:query',
    'threat_intel:read',
  ],
  engineer: [
    'alerts:read',
    'alerts:triage',
    'alerts:feedback',
    'alerts:bulk',
    'cases:read',
    'cases:create',
    'cases:update',
    'cases:notes',
    'cases:certin_report',
    'search:read',
    'saved_searches:manage',
    'scheduled_searches:write',
    'rules:write',
    'sigma:convert',
    'suppressions:write',
    'active_response:recommend',
    'active_response:dry_run',
    'active_response:execute',
    'active_response:approve',
    'active_response:unblock',
    'agents:cert_rotate',
    'agents:config_write',
    'agents:delete',
    'receivers:write',
    'soar:manage',
    'soar:run',
    'simulations:run',
    'canary:probe',
    'webhooks:write',
    'threat_intel:read',
    'threat_intel:write',
    'audit:read',
    'ai:query',
  ],
  admin: [
    'alerts:read',
    'alerts:triage',
    'alerts:feedback',
    'alerts:bulk',
    'cases:read',
    'cases:create',
    'cases:update',
    'cases:notes',
    'cases:certin_report',
    'search:read',
    'saved_searches:manage',
    'scheduled_searches:write',
    'rules:write',
    'sigma:convert',
    'suppressions:write',
    'active_response:recommend',
    'active_response:dry_run',
    'active_response:execute',
    'active_response:approve',
    'active_response:unblock',
    'agents:cert_rotate',
    'agents:config_write',
    'agents:delete',
    'receivers:write',
    'soar:manage',
    'soar:run',
    'simulations:run',
    'canary:probe',
    'webhooks:write',
    'threat_intel:read',
    'threat_intel:write',
    'audit:read',
    'ai:query',
    'users:read',
    'users:create',
    'users:role_update',
    'users:disable',
    'retention:policy_write',
    'retention:seal',
    'retention:tamper_test',
    'backup:export',
    'backup:restore',
    'gemini:config_write',
  ],
};

export const RBAC_MATRIX_ROWS: RbacCapabilityRow[] = [
  { domain: 'Triage & Cases', action: 'View alerts, verdict TP/FP, manage cases & notes', analyst: true, engineer: true, admin: true },
  { domain: 'Containment (AR)', action: 'Queue recommended block & run dry-run preview', analyst: true, engineer: true, admin: true },
  { domain: 'Containment (AR)', action: 'Execute live block, approve/reject orders, unblock', analyst: false, engineer: true, admin: true },
  { domain: 'Detection & Tuning', action: 'Deploy Sigma rules, suppressions, scheduled hunts', analyst: false, engineer: true, admin: true },
  { domain: 'Fleet & mTLS PKI', action: 'Rotate X.509 agent certs, receivers & SOAR playbooks', analyst: false, engineer: true, admin: true },
  { domain: 'Vault & Backups', action: 'Seal cold gzip blocks, test tamper, export/restore backups', analyst: false, engineer: false, admin: true },
  { domain: 'IAM & Governance', action: 'Create SOC accounts, assign roles, enable/disable users', analyst: false, engineer: false, admin: true },
];

export class SecurityManager {
  private users = new Map<string, UserAccount>();
  private tokenSecret: string;
  private revokedTokens = new Set<string>();
  private minTokenIat = new Map<string, number>();
  private failedLoginTracker = new Map<string, { count: number; firstAttemptAt: number; lockedUntil: number }>();

  private auditLog: AuditLogEntry[] = [];
  private nextAuditId = 1;
  private auditHeadHash = '0'.repeat(64);

  private caKeyPem = '';
  private caCertPem = '';
  private caFingerprint = '';
  private serverKeyPem = '';
  private serverCertPem = '';
  private agentCerts = new Map<string, AgentCertificate>();

  constructor() {
    this.tokenSecret = process.env.KAVALAN_JWT_SECRET || crypto.randomBytes(32).toString('hex');
    this.initCertificateAuthority();
    this.seedDefaultUsers();
  }

  // =========================================================================
  // 1. User Accounts, Passwords & RBAC Sessions
  // =========================================================================

  private hashPassword(password: string, salt?: string): { salt: string; hash: string } {
    const s = salt || crypto.randomBytes(16).toString('hex');
    const h = crypto.pbkdf2Sync(password, s, 60000, 32, 'sha256').toString('hex');
    return { salt: s, hash: h };
  }

  private verifyPassword(password: string, salt: string, expectedHash: string): boolean {
    const { hash } = this.hashPassword(password, salt);
    const a = Buffer.from(hash, 'hex');
    const b = Buffer.from(expectedHash, 'hex');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  }

  private seedDefaultUsers(): void {
    const now = Math.floor(Date.now() / 1000);
    const seeds: Array<{ id: string; username: string; display: string; email: string; role: UserRole; pass: string }> = [
      {
        id: 'USR-001',
        username: 'admin',
        display: 'R. Patel (SOC Director)',
        email: 'admin@kavalan.local',
        role: 'admin',
        pass: process.env.KAVALAN_ADMIN_PASSWORD || 'KavalanAdmin!2026',
      },
      {
        id: 'USR-002',
        username: 'engineer',
        display: 'M. Lin (Detection Engineer)',
        email: 'engineer@kavalan.local',
        role: 'engineer',
        pass: process.env.KAVALAN_ENG_PASSWORD || 'KavalanEng!2026',
      },
      {
        id: 'USR-003',
        username: 'analyst',
        display: 'A. Sharma (Tier 1 Analyst)',
        email: 'analyst@kavalan.local',
        role: 'analyst',
        pass: process.env.KAVALAN_ANALYST_PASSWORD || 'KavalanSoc!2026',
      },
    ];

    for (const s of seeds) {
      const { salt, hash } = this.hashPassword(s.pass);
      this.users.set(s.username, {
        id: s.id,
        username: s.username,
        display_name: s.display,
        email: s.email,
        role: s.role,
        password_hash: hash,
        salt,
        created_at: now - 86400 * 30,
        last_login_at: null,
        enabled: true,
      });
    }

    this.recordAudit({
      actor: 'system',
      role: 'admin',
      action: 'SECURITY_SUBSYSTEM_INIT',
      target_type: 'ca_pki',
      target_id: this.caFingerprint.slice(0, 16),
      details: 'Initialized RBAC directory (admin/engineer/analyst), HMAC session authority, and Kavalan Root CA',
      ip: '127.0.0.1',
    });
  }

  toPublicUser(u: UserAccount): PublicUser {
    return {
      id: u.id,
      username: u.username,
      display_name: u.display_name,
      email: u.email,
      role: u.role,
      created_at: u.created_at,
      last_login_at: u.last_login_at,
      enabled: u.enabled,
    };
  }

  getPermissionsForRole(role: UserRole): string[] {
    return ROLE_PERMISSIONS[role] || [];
  }

  getRbacMatrix(): RbacCapabilityRow[] {
    return RBAC_MATRIX_ROWS;
  }

  authenticate(
    usernameInput: string,
    passwordInput: string,
    ip = '127.0.0.1'
  ):
    | { ok: true; token: string; user: PublicUser }
    | { ok: false; error: string; locked?: boolean; retry_after_sec?: number } {
    const clean = usernameInput.trim().toLowerCase();
    const now = Math.floor(Date.now() / 1000);
    const trackerKey = `${clean || 'unknown'}@${ip}`;
    const existingFail = this.failedLoginTracker.get(trackerKey);

    if (existingFail && existingFail.lockedUntil > now) {
      const waitSec = existingFail.lockedUntil - now;
      this.recordAudit({
        actor: clean || 'unknown',
        role: 'anonymous',
        action: 'AUTH_LOGIN_BLOCKED_LOCKOUT',
        target_type: 'user',
        target_id: clean || 'unknown',
        details: `Login rejected during brute-force lockout window (${waitSec}s remaining)`,
        ip,
      });
      return {
        ok: false,
        locked: true,
        retry_after_sec: waitSec,
        error: `Account temporarily locked for ${waitSec}s after 5 failed login attempts.`,
      };
    }

    const recordFailure = (actorName: string, actorRole: string, targetId: string, baseMsg: string) => {
      const cur = this.failedLoginTracker.get(trackerKey);
      const resetWindow = !cur || now - cur.firstAttemptAt > 300;
      const count = resetWindow ? 1 : cur.count + 1;
      const lockedUntil = count >= 5 ? now + 60 : 0;
      this.failedLoginTracker.set(trackerKey, {
        count,
        firstAttemptAt: resetWindow ? now : cur.firstAttemptAt,
        lockedUntil,
      });

      this.recordAudit({
        actor: actorName,
        role: actorRole,
        action: lockedUntil > 0 ? 'AUTH_ACCOUNT_LOCKED_BRUTE_FORCE' : 'AUTH_LOGIN_FAILED',
        target_type: 'user',
        target_id: targetId,
        details:
          lockedUntil > 0
            ? `${baseMsg} — 5 failed attempts reached; locked for 60s`
            : `${baseMsg} (attempt ${count}/5)`,
        ip,
      });

      if (lockedUntil > 0) {
        return {
          ok: false as const,
          locked: true,
          retry_after_sec: 60,
          error: 'Too many failed login attempts (5/5). Account locked for 60 seconds.',
        };
      }
      return {
        ok: false as const,
        error: `${baseMsg} (${count}/5 attempts before 60s lockout)`,
      };
    };

    const user = this.users.get(clean);
    if (!user || !user.enabled) {
      return recordFailure(
        clean || 'unknown',
        user?.role || 'anonymous',
        user?.id || clean || 'unknown',
        user && !user.enabled ? 'Account is disabled by administrator' : 'Invalid username or password'
      );
    }

    if (!this.verifyPassword(passwordInput, user.salt, user.password_hash)) {
      return recordFailure(user.username, user.role, user.id, 'Invalid username or password');
    }

    this.failedLoginTracker.delete(trackerKey);
    user.last_login_at = now;
    const payload: VerifiedSession = {
      user_id: user.id,
      username: user.username,
      display_name: user.display_name,
      role: user.role,
      iat: now,
      exp: now + 12 * 3600,
    };
    const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const sig = crypto.createHmac('sha256', this.tokenSecret).update(encoded).digest('base64url');
    const token = `${encoded}.${sig}`;

    this.recordAudit({
      actor: user.display_name,
      role: user.role,
      action: 'AUTH_LOGIN_SUCCESS',
      target_type: 'session',
      target_id: user.id,
      details: `Authenticated SOC session issued for ${user.username} (${user.role})`,
      ip,
    });

    return { ok: true, token, user: this.toPublicUser(user) };
  }

  verifyToken(token: string | undefined | null): VerifiedSession | null {
    if (!token || !token.includes('.')) return null;
    if (this.revokedTokens.has(token)) return null;
    const [encoded, sig] = token.split('.');
    if (!encoded || !sig) return null;
    const expectedSig = crypto.createHmac('sha256', this.tokenSecret).update(encoded).digest('base64url');
    const a = Buffer.from(sig);
    const b = Buffer.from(expectedSig);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    try {
      const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) as VerifiedSession;
      if (!payload || payload.exp < Math.floor(Date.now() / 1000)) return null;
      const acct = this.users.get(payload.username);
      if (!acct || !acct.enabled) return null;
      const minIat = this.minTokenIat.get(acct.username) || 0;
      if ((payload.iat || 0) < minIat) return null;
      payload.role = acct.role; // reflect live role updates immediately
      payload.display_name = acct.display_name;
      return payload;
    } catch {
      return null;
    }
  }

  revokeToken(token: string, actor: string, role: string, ip = '127.0.0.1'): void {
    if (token) this.revokedTokens.add(token);
    this.recordAudit({
      actor,
      role,
      action: 'AUTH_LOGOUT',
      target_type: 'session',
      target_id: actor,
      details: 'User logged out and invalidated bearer session token',
      ip,
    });
  }

  listUsers(): PublicUser[] {
    return Array.from(this.users.values()).map((u) => this.toPublicUser(u));
  }

  createUser(
    input: { username: string; display_name?: string; email?: string; role: UserRole; password: string },
    actor: string,
    actorRole: string,
    ip = '127.0.0.1'
  ): { ok: true; user: PublicUser } | { ok: false; error: string } {
    const username = String(input.username || '').trim().toLowerCase();
    if (!/^[a-z0-9_.-]{3,32}$/.test(username)) {
      return { ok: false, error: 'Username must be 3-32 chars (a-z, 0-9, _, ., -)' };
    }
    if (this.users.has(username)) {
      return { ok: false, error: `User '${username}' already exists` };
    }
    if (!['analyst', 'engineer', 'admin'].includes(input.role)) {
      return { ok: false, error: 'Role must be analyst, engineer, or admin' };
    }
    if (!input.password || input.password.length < 8) {
      return { ok: false, error: 'Password must be at least 8 characters' };
    }
    const { salt, hash } = this.hashPassword(input.password);
    const id = `USR-${String(this.users.size + 1).padStart(3, '0')}`;
    const acct: UserAccount = {
      id,
      username,
      display_name: input.display_name?.trim() || username,
      email: input.email?.trim() || `${username}@kavalan.local`,
      role: input.role,
      password_hash: hash,
      salt,
      created_at: Math.floor(Date.now() / 1000),
      last_login_at: null,
      enabled: true,
    };
    this.users.set(username, acct);
    this.recordAudit({
      actor,
      role: actorRole,
      action: 'USER_CREATED',
      target_type: 'user',
      target_id: acct.id,
      details: `Created user '${username}' with role '${acct.role}'`,
      ip,
    });
    return { ok: true, user: this.toPublicUser(acct) };
  }

  updateUserRole(
    userIdOrName: string,
    updates: { role?: UserRole; enabled?: boolean },
    actor: string,
    actorRole: string,
    ip = '127.0.0.1',
    actorUserId?: string
  ): { ok: true; user: PublicUser } | { ok: false; error: string; notFound?: boolean } {
    const target = Array.from(this.users.values()).find((u) => u.id === userIdOrName || u.username === userIdOrName);
    if (!target) {
      return { ok: false, notFound: true, error: 'User not found' };
    }

    const nextRole = updates.role && ['analyst', 'engineer', 'admin'].includes(updates.role) ? updates.role : target.role;
    const nextEnabled = updates.enabled !== undefined ? Boolean(updates.enabled) : target.enabled;
    const isSelf = Boolean(actorUserId && target.id === actorUserId) || target.display_name === actor || target.username === actor;

    if (isSelf && (nextRole !== target.role || !nextEnabled)) {
      this.recordAudit({
        actor,
        role: actorRole,
        action: 'AUTHZ_POLICY_GUARD_BLOCKED',
        target_type: 'user',
        target_id: target.id,
        details: `Blocked self-lockout attempt on '${target.username}' (requested role=${nextRole}, enabled=${nextEnabled})`,
        ip,
      });
      return {
        ok: false,
        error: 'Self-lockout protection: administrators cannot demote or disable their own active account.',
      };
    }

    const activeAdminsAfter = Array.from(this.users.values()).filter((u) => {
      const effRole = u.id === target.id ? nextRole : u.role;
      const effEnabled = u.id === target.id ? nextEnabled : u.enabled;
      return effRole === 'admin' && effEnabled;
    }).length;

    if (activeAdminsAfter < 1) {
      this.recordAudit({
        actor,
        role: actorRole,
        action: 'AUTHZ_POLICY_GUARD_BLOCKED',
        target_type: 'user',
        target_id: target.id,
        details: `Blocked last-admin removal attempt on '${target.username}'`,
        ip,
      });
      return {
        ok: false,
        error: 'Last-admin guard: at least one enabled administrator account must remain active.',
      };
    }

    const prevRole = target.role;
    const prevEnabled = target.enabled;
    target.role = nextRole;
    target.enabled = nextEnabled;

    if (!target.enabled) {
      this.minTokenIat.set(target.username, Math.floor(Date.now() / 1000) + 1);
    }

    this.recordAudit({
      actor,
      role: actorRole,
      action: prevEnabled !== target.enabled ? (target.enabled ? 'USER_ENABLED' : 'USER_DISABLED') : 'USER_RBAC_UPDATED',
      target_type: 'user',
      target_id: target.id,
      details: `Updated '${target.username}': role=${prevRole}->${target.role}, enabled=${target.enabled}`,
      ip,
    });
    return { ok: true, user: this.toPublicUser(target) };
  }

  recordAccessDenied(
    actor: string,
    role: string,
    method: string,
    reqPath: string,
    allowedRoles: UserRole[],
    ip = '127.0.0.1'
  ): AuditLogEntry {
    return this.recordAudit({
      actor,
      role,
      action: 'AUTHZ_PERMISSION_DENIED',
      target_type: 'api_route',
      target_id: `${method.toUpperCase()} ${reqPath}`,
      details: `Blocked unauthorized ${method.toUpperCase()} ${reqPath} by role '${role}' (requires: ${allowedRoles.join(' | ')})`,
      ip,
    });
  }

  // =========================================================================
  // 2. Cryptographically Hash-Chained Immutable Audit Trail
  // =========================================================================

  recordAudit(entry: {
    actor: string;
    role: string;
    action: string;
    target_type: string;
    target_id: string;
    details: string;
    ip?: string;
  }): AuditLogEntry {
    const timestamp = Math.floor(Date.now() / 1000);
    const id = this.nextAuditId++;
    const prev_hash = this.auditHeadHash;
    const payloadStr = JSON.stringify({
      id,
      timestamp,
      actor: entry.actor,
      role: entry.role,
      action: entry.action,
      target_type: entry.target_type,
      target_id: entry.target_id,
      details: entry.details,
      ip: entry.ip || '127.0.0.1',
      prev_hash,
    });
    const entry_hash = crypto.createHash('sha256').update(payloadStr).digest('hex');
    this.auditHeadHash = entry_hash;

    const record: AuditLogEntry = {
      id,
      timestamp,
      actor: entry.actor,
      role: entry.role,
      action: entry.action,
      target_type: entry.target_type,
      target_id: entry.target_id,
      details: entry.details,
      ip: entry.ip || '127.0.0.1',
      prev_hash,
      entry_hash,
    };
    this.auditLog.unshift(record);
    if (this.auditLog.length > 2000) this.auditLog.length = 2000;
    return record;
  }

  listAudit(filters: { actor?: string; action?: string; limit?: number } = {}): AuditLogEntry[] {
    let items = this.auditLog;
    if (filters.actor) {
      const a = filters.actor.toLowerCase();
      items = items.filter((e) => e.actor.toLowerCase().includes(a));
    }
    if (filters.action) {
      const act = filters.action.toLowerCase();
      items = items.filter((e) => e.action.toLowerCase().includes(act));
    }
    return items.slice(0, Math.min(500, Math.max(1, filters.limit || 100)));
  }

  verifyAuditChain(): { valid: boolean; checked_entries: number; head_hash: string; broken_at_id: number | null } {
    const chronological = [...this.auditLog].reverse();
    let expectedPrev = '0'.repeat(64);
    for (const e of chronological) {
      if (e.prev_hash !== expectedPrev) {
        return { valid: false, checked_entries: chronological.length, head_hash: this.auditHeadHash, broken_at_id: e.id };
      }
      const payloadStr = JSON.stringify({
        id: e.id,
        timestamp: e.timestamp,
        actor: e.actor,
        role: e.role,
        action: e.action,
        target_type: e.target_type,
        target_id: e.target_id,
        details: e.details,
        ip: e.ip,
        prev_hash: e.prev_hash,
      });
      const recalc = crypto.createHash('sha256').update(payloadStr).digest('hex');
      if (recalc !== e.entry_hash) {
        return { valid: false, checked_entries: chronological.length, head_hash: this.auditHeadHash, broken_at_id: e.id };
      }
      expectedPrev = e.entry_hash;
    }
    return {
      valid: true,
      checked_entries: chronological.length,
      head_hash: this.auditHeadHash,
      broken_at_id: null,
    };
  }

  // =========================================================================
  // 3. Root CA, Server TLS Certs & Per-Agent X.509 mTLS Certificates
  // =========================================================================

  private initCertificateAuthority(): void {
    try {
      fs.mkdirSync(AGENTS_CERTS_DIR, { recursive: true });
      const caKeyPath = path.join(CERTS_DIR, 'ca.key');
      const caCertPath = path.join(CERTS_DIR, 'ca.crt');
      const srvKeyPath = path.join(CERTS_DIR, 'server.key');
      const srvCertPath = path.join(CERTS_DIR, 'server.crt');

      if (!fs.existsSync(caKeyPath) || !fs.existsSync(caCertPath)) {
        execFileSync('openssl', [
          'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
          '-keyout', caKeyPath, '-out', caCertPath,
          '-days', '3650', '-subj', '/CN=Kavalan-SIEM-Root-CA/O=Kavalan Security/C=IN',
        ]);
      }

      if (!fs.existsSync(srvKeyPath) || !fs.existsSync(srvCertPath)) {
        const srvCsrPath = path.join(CERTS_DIR, 'server.csr');
        execFileSync('openssl', [
          'req', '-newkey', 'rsa:2048', '-nodes',
          '-keyout', srvKeyPath, '-out', srvCsrPath,
          '-subj', '/CN=kavalan-manager.local/O=Kavalan Manager/C=IN',
        ]);
        execFileSync('openssl', [
          'x509', '-req', '-in', srvCsrPath,
          '-CA', caCertPath, '-CAkey', caKeyPath, '-CAcreateserial',
          '-out', srvCertPath, '-days', '730',
        ]);
      }

      this.caKeyPem = fs.readFileSync(caKeyPath, 'utf8');
      this.caCertPem = fs.readFileSync(caCertPath, 'utf8');
      this.serverKeyPem = fs.readFileSync(srvKeyPath, 'utf8');
      this.serverCertPem = fs.readFileSync(srvCertPath, 'utf8');
      this.caFingerprint = this.pemFingerprint(this.caCertPem);
    } catch {
      // Fallback deterministic PEM metadata if openssl unavailable in restricted runtime
      this.caFingerprint = crypto.createHash('sha256').update('kavalan-root-ca-fallback').digest('hex');
      this.caCertPem = '-----BEGIN CERTIFICATE-----\nKAVALAN-ROOT-CA-FALLBACK\n-----END CERTIFICATE-----';
    }
  }

  private pemFingerprint(pem: string): string {
    const clean = pem
      .replace(/-----BEGIN CERTIFICATE-----/g, '')
      .replace(/-----END CERTIFICATE-----/g, '')
      .replace(/\s+/g, '');
    try {
      const der = Buffer.from(clean, 'base64');
      return crypto.createHash('sha256').update(der).digest('hex');
    } catch {
      return crypto.createHash('sha256').update(pem).digest('hex');
    }
  }

  getTlsServerCredentials(): { ca: string; key: string; cert: string; ca_fingerprint: string } {
    return {
      ca: this.caCertPem,
      key: this.serverKeyPem,
      cert: this.serverCertPem,
      ca_fingerprint: this.caFingerprint,
    };
  }

  issueAgentCert(agentId: string, hostName: string, keyVersion = 1, prevRevoked: string[] = []): {
    record: AgentCertificate;
    plaintext_key: string;
  } {
    const now = Math.floor(Date.now() / 1000);
    const serial = crypto.randomBytes(8).toString('hex').toUpperCase();
    const subjectCn = `kavalan-agent-${agentId}.${hostName.replace(/[^a-zA-Z0-9.-]/g, '_')}`;
    let certPem: string;

    try {
      const caKeyPath = path.join(CERTS_DIR, 'ca.key');
      const caCertPath = path.join(CERTS_DIR, 'ca.crt');
      const agentKeyPath = path.join(AGENTS_CERTS_DIR, `agent-${agentId}-v${keyVersion}.key`);
      const agentCsrPath = path.join(AGENTS_CERTS_DIR, `agent-${agentId}-v${keyVersion}.csr`);
      const agentCertPath = path.join(AGENTS_CERTS_DIR, `agent-${agentId}-v${keyVersion}.crt`);

      execFileSync('openssl', [
        'req', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', agentKeyPath, '-out', agentCsrPath,
        '-subj', `/CN=${subjectCn}/O=Kavalan Endpoint/OU=Agent-${agentId}`,
      ]);
      execFileSync('openssl', [
        'x509', '-req', '-in', agentCsrPath,
        '-CA', caCertPath, '-CAkey', caKeyPath,
        '-set_serial', `0x${serial}`,
        '-out', agentCertPath, '-days', '90',
      ]);
      certPem = fs.readFileSync(agentCertPath, 'utf8');
    } catch {
      certPem = `-----BEGIN CERTIFICATE-----\n${Buffer.from(`${subjectCn}:${serial}:v${keyVersion}`).toString('base64')}\n-----END CERTIFICATE-----`;
    }

    const plaintextKey = `kv_ag_${agentId}_v${keyVersion}_${crypto.randomBytes(16).toString('hex')}`;
    const apiKeyHash = crypto.createHash('sha256').update(plaintextKey).digest('hex');
    const fp = this.pemFingerprint(certPem);

    const record: AgentCertificate = {
      agent_id: agentId,
      serial,
      fingerprint_sha256: fp,
      subject_cn: subjectCn,
      key_version: keyVersion,
      api_key_hash: apiKeyHash,
      api_key_preview: `${plaintextKey.slice(0, 16)}...${plaintextKey.slice(-4)}`,
      cert_pem: certPem,
      issued_at: now,
      expires_at: now + 90 * 86400,
      revoked_serials: prevRevoked,
      tls_mode: 'mTLS_STRICT',
    };
    this.agentCerts.set(agentId, record);
    return { record, plaintext_key: plaintextKey };
  }

  rotateAgentCert(agentId: string, hostName: string, actor: string, role: string, ip = '127.0.0.1'): {
    record: AgentCertificate;
    plaintext_key: string;
  } {
    const existing = this.agentCerts.get(agentId);
    const prevRevoked = existing ? [...existing.revoked_serials, existing.serial] : [];
    const nextVersion = existing ? existing.key_version + 1 : 1;
    const issued = this.issueAgentCert(agentId, hostName, nextVersion, prevRevoked);

    this.recordAudit({
      actor,
      role,
      action: 'AGENT_CERT_ROTATED',
      target_type: 'agent',
      target_id: agentId,
      details: `Rotated mTLS cert & key to v${nextVersion} (serial=${issued.record.serial}, revoked=${prevRevoked.length})`,
      ip,
    });
    return issued;
  }

  getAgentCert(agentId: string): AgentCertificate | null {
    return this.agentCerts.get(agentId) || null;
  }

  verifyAgentTransport(
    agentId: string,
    headers: { certFp?: string; agentKey?: string; binaryHash?: string }
  ): { ok: boolean; tamperDetected: boolean; reason?: string } {
    const cert = this.agentCerts.get(agentId);
    if (!cert) {
      return { ok: true, tamperDetected: false }; // allow initial bootstrap before registration
    }
    if (headers.certFp) {
      const fp = headers.certFp.trim().toLowerCase();
      if (fp !== cert.fingerprint_sha256.toLowerCase()) {
        return {
          ok: false,
          tamperDetected: true,
          reason: `mTLS Certificate Fingerprint Mismatch (got ${fp.slice(0, 12)}..., expected ${cert.fingerprint_sha256.slice(0, 12)}...)`,
        };
      }
    }
    if (headers.agentKey) {
      const kh = crypto.createHash('sha256').update(headers.agentKey.trim()).digest('hex');
      if (kh !== cert.api_key_hash) {
        return {
          ok: false,
          tamperDetected: true,
          reason: 'Invalid or rotated-out Agent Transport Key presented',
        };
      }
    }
    if (headers.binaryHash && headers.binaryHash.trim().toLowerCase() !== DEFAULT_AGENT_BINARY_SHA256) {
      return {
        ok: false,
        tamperDetected: true,
        reason: `Agent binary integrity checksum mismatch (${headers.binaryHash.slice(0, 14)}...)`,
      };
    }
    return { ok: true, tamperDetected: false };
  }
}

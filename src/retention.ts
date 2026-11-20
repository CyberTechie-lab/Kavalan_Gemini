import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { CertInReport, IncidentCase, IndexedEvent, LogChainBlock, RetentionPolicy } from './types.js';

const ARCHIVE_DIR = path.join(process.cwd(), 'data', 'archive');

export class RetentionArchiveManager {
  private policy: RetentionPolicy = {
    hot_days: 7,
    warm_days: 30,
    cold_retention_days: 180, // CERT-In 2022 mandate: minimum 180 days
    cert_in_mode: true,
    cert_in_reporting_hours: 6, // CERT-In 2022 mandate: report within 6 hours
    compress_cold_gzip: true,
    auto_hash_chain: true,
    ntp_server: 'time.nplindia.org (IST NTP)',
    ntp_offset_ms: 4,
    updated_at: Math.floor(Date.now() / 1000),
  };

  private blocks: LogChainBlock[] = [];
  private certInReports: CertInReport[] = [];
  private nextReportNum = 1;
  private lastSealedEventId = 0;

  constructor() {
    fs.mkdirSync(ARCHIVE_DIR, { recursive: true });
  }

  getPolicy(): RetentionPolicy {
    return { ...this.policy };
  }

  updatePolicy(updates: Partial<RetentionPolicy>): RetentionPolicy {
    const requestedCold = Number(updates.cold_retention_days ?? this.policy.cold_retention_days);
    this.policy = {
      ...this.policy,
      ...updates,
      cold_retention_days: updates.cert_in_mode === false ? Math.max(1, requestedCold) : Math.max(180, requestedCold),
      cert_in_reporting_hours: 6,
      updated_at: Math.floor(Date.now() / 1000),
    };
    return this.getPolicy();
  }

  sealEventBatch(events: IndexedEvent[], tier: LogChainBlock['tier'] = 'COLD_GZIP'): LogChainBlock | null {
    const unsealed = events.filter((e) => e.id > this.lastSealedEventId);
    const target = unsealed.length > 0 ? unsealed : events.slice(0, 25);
    if (target.length === 0) return null;

    const sorted = [...target].sort((a, b) => a.id - b.id);
    const blockIndex = this.blocks.length + 1;
    const prevBlockHash = this.blocks.length > 0 ? this.blocks[this.blocks.length - 1].block_hash : '0'.repeat(64);
    const ndjson = sorted.map((e) => JSON.stringify({ id: e.id, ts: e.timestamp, host: e.host, src: e.source_ip, type: e.log_type, action: e.action, raw: e.raw })).join('\n');
    const rawBuf = Buffer.from(ndjson, 'utf8');
    const merkleRoot = crypto.createHash('sha256').update(rawBuf).digest('hex');

    let compressedBytes = rawBuf.length;
    let archiveFile: string | null = null;
    if (this.policy.compress_cold_gzip && tier === 'COLD_GZIP') {
      const gz = zlib.gzipSync(rawBuf, { level: 9 });
      compressedBytes = gz.length;
      archiveFile = `kavalan-block-${String(blockIndex).padStart(5, '0')}.ndjson.gz`;
      try {
        fs.writeFileSync(path.join(ARCHIVE_DIR, archiveFile), gz);
      } catch {
        archiveFile = null;
      }
    }

    const sealedAt = Math.floor(Date.now() / 1000);
    const blockHash = crypto
      .createHash('sha256')
      .update(`${blockIndex}|${sorted[0].id}|${sorted[sorted.length - 1].id}|${merkleRoot}|${prevBlockHash}`)
      .digest('hex');

    const block: LogChainBlock = {
      block_index: blockIndex,
      tier,
      first_event_id: sorted[0].id,
      last_event_id: sorted[sorted.length - 1].id,
      first_ts: sorted[0].timestamp,
      last_ts: sorted[sorted.length - 1].timestamp,
      event_count: sorted.length,
      raw_bytes: rawBuf.length,
      compressed_bytes: compressedBytes,
      archive_file: archiveFile,
      prev_block_hash: prevBlockHash,
      merkle_root: merkleRoot,
      block_hash: blockHash,
      sealed_at: sealedAt,
      tampered: false,
    };

    this.blocks.push(block);
    this.lastSealedEventId = Math.max(this.lastSealedEventId, sorted[sorted.length - 1].id);
    return block;
  }

  verifyChain(): {
    valid: boolean;
    total_blocks: number;
    tampered_blocks: number[];
    head_hash: string;
    total_raw_bytes: number;
    total_compressed_bytes: number;
    compression_ratio_pct: number;
  } {
    let expectedPrev = '0'.repeat(64);
    const tamperedBlocks: number[] = [];
    let totalRaw = 0;
    let totalComp = 0;

    for (const blk of this.blocks) {
      totalRaw += blk.raw_bytes;
      totalComp += blk.compressed_bytes;
      let blockOk = blk.prev_block_hash === expectedPrev;

      if (blockOk && blk.archive_file) {
        const fullPath = path.join(ARCHIVE_DIR, blk.archive_file);
        if (fs.existsSync(fullPath)) {
          try {
            const gz = fs.readFileSync(fullPath);
            const raw = zlib.gunzipSync(gz);
            const diskMerkle = crypto.createHash('sha256').update(raw).digest('hex');
            if (diskMerkle !== blk.merkle_root) blockOk = false;
          } catch {
            blockOk = false;
          }
        }
      }

      if (blockOk) {
        const recalc = crypto
          .createHash('sha256')
          .update(`${blk.block_index}|${blk.first_event_id}|${blk.last_event_id}|${blk.merkle_root}|${blk.prev_block_hash}`)
          .digest('hex');
        if (recalc !== blk.block_hash) blockOk = false;
      }

      blk.tampered = !blockOk;
      if (!blockOk) tamperedBlocks.push(blk.block_index);
      expectedPrev = blk.block_hash;
    }

    const ratio = totalRaw > 0 ? Math.round((1 - totalComp / totalRaw) * 1000) / 10 : 0;
    return {
      valid: tamperedBlocks.length === 0,
      total_blocks: this.blocks.length,
      tampered_blocks: tamperedBlocks,
      head_hash: this.blocks.length > 0 ? this.blocks[this.blocks.length - 1].block_hash : '0'.repeat(64),
      total_raw_bytes: totalRaw,
      total_compressed_bytes: totalComp,
      compression_ratio_pct: Math.max(0, ratio),
    };
  }

  simulateBlockTamper(restore = false): { tampered: boolean; block_index: number | null } {
    if (this.blocks.length === 0) return { tampered: false, block_index: null };
    const blk = this.blocks[this.blocks.length - 1];
    if (restore) {
      blk.merkle_root = blk.merkle_root.replace(/^.{4}/, (blk as any)._orig_prefix || blk.merkle_root.slice(0, 4));
      if (blk.archive_file) {
        const recalc = crypto
          .createHash('sha256')
          .update(`${blk.block_index}|${blk.first_event_id}|${blk.last_event_id}|${blk.merkle_root}|${blk.prev_block_hash}`)
          .digest('hex');
        blk.block_hash = recalc;
      }
      blk.tampered = false;
      return { tampered: false, block_index: blk.block_index };
    }
    (blk as any)._orig_prefix = blk.merkle_root.slice(0, 4);
    blk.merkle_root = `dead${blk.merkle_root.slice(4)}`;
    blk.tampered = true;
    return { tampered: true, block_index: blk.block_index };
  }

  getStatus(hotEventCount: number): Record<string, any> {
    const chain = this.verifyChain();
    const certInCompliant =
      this.policy.cold_retention_days >= 180 &&
      Math.abs(this.policy.ntp_offset_ms) <= 100 &&
      chain.valid;

    return {
      policy: this.getPolicy(),
      hot_events_count: hotEventCount,
      sealed_events_count: this.blocks.reduce((a, b) => a + b.event_count, 0),
      chain,
      blocks: [...this.blocks].reverse().slice(0, 30),
      cert_in: {
        compliant: certInCompliant,
        retention_mandate_days: 180,
        configured_days: this.policy.cold_retention_days,
        reporting_window_hours: 6,
        ntp_synced: Math.abs(this.policy.ntp_offset_ms) <= 100,
        ntp_server: this.policy.ntp_server,
        ntp_offset_ms: this.policy.ntp_offset_ms,
        reports_generated: this.certInReports.length,
      },
      cert_in_reports: this.certInReports.slice(0, 20),
    };
  }

  generateCertInReport(
    c: IncidentCase,
    actor: string,
    auditHeadHash: string,
    category?: string
  ): CertInReport {
    const now = Math.floor(Date.now() / 1000);
    const detected = c.created_at || now;
    const deadline = c.cert_in_deadline_at || detected + 6 * 3600;
    const withinSla = now <= deadline;
    const reportId = `CERTIN-${new Date(now * 1000).getUTCFullYear()}-${String(this.nextReportNum++).padStart(4, '0')}`;

    c.cert_in_reported_at = now;
    c.cert_in_category = category || c.cert_in_category || 'Unauthorized access / Exploitation of IT systems';

    const report: CertInReport = {
      report_id: reportId,
      case_id: c.id,
      generated_at: now,
      generated_by: actor,
      detected_at: detected,
      deadline_at: deadline,
      within_6h_sla: withinSla,
      incident_category: c.cert_in_category,
      severity: c.severity,
      affected_assets: c.entities.hosts || ['unknown-host'],
      indicators_of_compromise: [...(c.entities.ips || []), ...(c.entities.users || [])],
      summary: c.description || c.title,
      actions_taken: (c.playbooks_run || []).map((p) => p.playbook),
      log_retention_verified_180d: this.policy.cold_retention_days >= 180 && this.verifyChain().valid,
      audit_chain_head_hash: auditHeadHash,
    };
    this.certInReports.unshift(report);
    return report;
  }

  createSignedBackup(stateSnapshot: Record<string, any>): Record<string, any> {
    const createdAt = Math.floor(Date.now() / 1000);
    const body = {
      kavalan_backup_version: '4.2',
      created_at: createdAt,
      policy: this.getPolicy(),
      blocks: this.blocks,
      cert_in_reports: this.certInReports,
      snapshot: stateSnapshot,
    };
    const digest = crypto.createHash('sha256').update(JSON.stringify(body)).digest('hex');
    return { ...body, sha256_integrity: digest };
  }

  verifyBackupBundle(bundle: Record<string, any>): { valid: boolean; reason?: string } {
    if (!bundle || typeof bundle !== 'object' || !bundle.sha256_integrity || !bundle.snapshot) {
      return { valid: false, reason: 'Invalid Kavalan backup bundle structure' };
    }
    const { sha256_integrity, ...rest } = bundle;
    const expected = crypto.createHash('sha256').update(JSON.stringify(rest)).digest('hex');
    if (expected !== sha256_integrity) {
      return { valid: false, reason: 'Backup SHA-256 integrity verification failed (bundle corrupted or altered)' };
    }
    if (bundle.policy) {
      this.updatePolicy(bundle.policy);
    }
    return { valid: true };
  }
}

import { IndexedEvent } from './types.js';

export interface PipedSearchResult {
  total: number;
  hits: IndexedEvent[];
  piped_mode: boolean;
  columns: string[];
  rows: Array<Record<string, any>>;
  stages_executed: string[];
}

export function extractEventField(e: IndexedEvent, rawField: string): any {
  const f = rawField.trim();
  const low = f.toLowerCase();
  if (low === 'src_ip' || low === 'ip' || low === 'source_ip' || low === 'source.ip') return e.source_ip;
  if (low === 'host' || low === 'host.name') return e.host;
  if (low === 'type' || low === 'log_type') return e.log_type;
  if (low === 'path' || low === 'target' || low === 'url.path') return e.target;
  if (low === 'user' || low === 'user.name') return e.user ?? '';
  if (low === 'action' || low === 'event.action') return e.action;
  if (low === 'outcome' || low === 'event.outcome') return e.outcome;
  if (low === 'status') return e.status;
  if (low === 'timestamp' || low === 'ts') return e.timestamp;
  if (low === 'ingest_lag_ms') return e.ingest_lag_ms;
  if (low === 'eventid' || low === 'event_id') return e.meta?.event_id ?? e.status;
  if (e.ecs && (e.ecs as any)[f] !== undefined) return (e.ecs as any)[f];
  if (f.startsWith('ocsf.') && e.ocsf) return (e.ocsf as any)[f.slice(5)];
  if ((e as any)[f] !== undefined) return (e as any)[f];
  if (e.meta && e.meta[f] !== undefined) return e.meta[f];
  if (e.meta?.json_data && e.meta.json_data[f] !== undefined) return e.meta.json_data[f];
  return undefined;
}

export class PipedQueryEngine {
  /**
   * Splits a query like `src_ip=1.2.3.4 | stats count by path | where count>50`
   * respecting quotes.
   */
  static splitPipes(rawQuery: string): string[] {
    const parts: string[] = [];
    let cur = '';
    let quote: string | null = null;
    for (let i = 0; i < rawQuery.length; i++) {
      const ch = rawQuery[i];
      if ((ch === '"' || ch === "'") && rawQuery[i - 1] !== '\\') {
        if (!quote) quote = ch;
        else if (quote === ch) quote = null;
        cur += ch;
      } else if (ch === '|' && !quote) {
        if (cur.trim()) parts.push(cur.trim());
        cur = '';
      } else {
        cur += ch;
      }
    }
    if (cur.trim()) parts.push(cur.trim());
    return parts;
  }

  static matchBaseFilter(events: IndexedEvent[], filterExpr: string, structured: Record<string, any> = {}): IndexedEvent[] {
    const sourceIp = structured.source_ip ? String(structured.source_ip).trim() : '';
    const logType = structured.log_type ? String(structured.log_type).trim() : '';
    const outcome = structured.outcome ? String(structured.outcome).trim() : '';
    const host = structured.host ? String(structured.host).trim() : '';
    const startTs = structured.start_ts ? Number(structured.start_ts) : 0;
    const endTs = structured.end_ts ? Number(structured.end_ts) : 0;

    // Parse filter expression (supports OR, NOT, field=val, field!=val, field:val, field>num, field<num)
    const orBranches = filterExpr.trim()
      ? filterExpr.split(/\s+OR\s+/i).map((b) => b.trim()).filter(Boolean)
      : [''];

    const evalSingleBranch = (e: IndexedEvent, branchStr: string): boolean => {
      if (!branchStr) return true;
      let rest = branchStr;
      const mustExclude: string[] = [];
      const mustInclude: string[] = [];
      const fieldPreds: Array<{ field: string; op: string; val: string; neg: boolean }> = [];

      // NOT "..."
      let m: RegExpExecArray | null;
      const notQuoted = /NOT\s+"([^"]+)"/gi;
      while ((m = notQuoted.exec(branchStr)) !== null) {
        mustExclude.push(m[1].toLowerCase());
      }
      rest = rest.replace(/NOT\s+"([^"]+)"/gi, ' ');

      // NOT field[:=]val
      const notFieldRe = /NOT\s+([a-zA-Z0-9_.]+)(!=|>=|<=|=|:|>|<)("[^"]+"|\S+)/gi;
      while ((m = notFieldRe.exec(rest)) !== null) {
        fieldPreds.push({
          field: m[1],
          op: m[2],
          val: m[3].replace(/^"|"$/g, ''),
          neg: true,
        });
      }
      rest = rest.replace(/NOT\s+[a-zA-Z0-9_.]+(?:!=|>=|<=|=|:|>|<)(?:"[^"]+"|\S+)/gi, ' ');

      // field(!=|>=|<=|=|:|>|<)val
      const fieldRe = /([a-zA-Z0-9_.]+)(!=|>=|<=|=|:|>|<)("[^"]+"|\S+)/g;
      while ((m = fieldRe.exec(rest)) !== null) {
        fieldPreds.push({
          field: m[1],
          op: m[2],
          val: m[3].replace(/^"|"$/g, ''),
          neg: false,
        });
      }
      rest = rest.replace(/[a-zA-Z0-9_.]+(?:!=|>=|<=|=|:|>|<)(?:"[^"]+"|\S+)/g, ' ');

      const quotedRe = /"([^"]+)"/g;
      while ((m = quotedRe.exec(rest)) !== null) {
        mustInclude.push(m[1].toLowerCase());
      }
      rest = rest.replace(/"([^"]+)"/g, ' ');

      for (const tok of rest.split(/\s+/).filter(Boolean)) {
        if (tok.toUpperCase() === 'AND' || tok === '*') continue;
        mustInclude.push(tok.toLowerCase());
      }

      for (const pred of fieldPreds) {
        const rawActual = extractEventField(e, pred.field);
        const actualStr = rawActual === undefined || rawActual === null ? '' : String(rawActual).toLowerCase();
        const targetLow = pred.val.toLowerCase();
        let ok = false;

        if (pred.op === '!=') {
          ok = actualStr !== targetLow;
        } else if (['>', '>=', '<', '<='].includes(pred.op)) {
          const numA = Number(rawActual);
          const numB = Number(pred.val);
          if (!Number.isNaN(numA) && !Number.isNaN(numB)) {
            if (pred.op === '>') ok = numA > numB;
            else if (pred.op === '>=') ok = numA >= numB;
            else if (pred.op === '<') ok = numA < numB;
            else ok = numA <= numB;
          }
        } else if (pred.op === '=') {
          if (targetLow.includes('*')) {
            const rx = new RegExp('^' + targetLow.replace(/\*/g, '.*') + '$', 'i');
            ok = rx.test(actualStr);
          } else {
            ok = actualStr === targetLow || (pred.field === 'path' && actualStr.includes(targetLow));
          }
        } else {
          // ":" substring / exact match
          ok = actualStr.includes(targetLow);
        }

        if (pred.neg ? ok : !ok) return false;
      }

      if (mustInclude.length > 0 || mustExclude.length > 0) {
        const hay = `${e.host} ${e.source_ip} ${e.log_type} ${e.action} ${e.target} ${e.outcome} ${e.status ?? ''} ${e.user ?? ''} ${e.raw ?? ''}`.toLowerCase();
        for (const inc of mustInclude) {
          if (!hay.includes(inc)) return false;
        }
        for (const exc of mustExclude) {
          if (hay.includes(exc)) return false;
        }
      }
      return true;
    };

    return events.filter((e) => {
      if (sourceIp && e.source_ip !== sourceIp) return false;
      if (logType && e.log_type !== logType) return false;
      if (outcome && e.outcome !== outcome) return false;
      if (host && e.host !== host) return false;
      if (startTs && e.timestamp < startTs) return false;
      if (endTs && e.timestamp > endTs) return false;

      if (orBranches.length === 1 && !orBranches[0]) return true;
      return orBranches.some((branch) => evalSingleBranch(e, branch));
    });
  }

  static execute(events: IndexedEvent[], query: Record<string, any>): PipedSearchResult {
    const qRaw = String(query.q || '').trim();
    const segments = this.splitPipes(qRaw);
    const filterExpr = segments[0] && !/^(stats|where|sort|head|limit|fields)\b/i.test(segments[0]) ? segments[0] : '';
    const pipeStages = filterExpr ? segments.slice(1) : segments;

    const baseMatched = this.matchBaseFilter(events, filterExpr, query).sort(
      (a, b) => b.timestamp - a.timestamp || b.id - a.id
    );

    if (pipeStages.length === 0) {
      const limit = Math.min(500, Math.max(1, Number(query.limit ?? 100)));
      const offset = Math.max(0, Number(query.offset ?? 0));
      return {
        total: baseMatched.length,
        hits: baseMatched.slice(offset, offset + limit),
        piped_mode: false,
        columns: [],
        rows: [],
        stages_executed: [],
      };
    }

    // Transform events to flat rows for piping
    let rows: Array<Record<string, any>> = baseMatched.map((e) => ({
      id: e.id,
      timestamp: e.timestamp,
      host: e.host,
      src_ip: e.source_ip,
      source_ip: e.source_ip,
      log_type: e.log_type,
      action: e.action,
      path: e.target,
      target: e.target,
      outcome: e.outcome,
      status: e.status ?? '',
      user: e.user ?? '',
      ingest_lag_ms: e.ingest_lag_ms,
    }));

    const stagesExecuted: string[] = [];
    let activeColumns: string[] = ['timestamp', 'host', 'src_ip', 'log_type', 'action', 'target', 'outcome'];

    for (const stage of pipeStages) {
      const statsM = /^stats\s+(.+)$/i.exec(stage);
      const whereM = /^where\s+(.+)$/i.exec(stage);
      const sortM = /^sort\s+(.+)$/i.exec(stage);
      const headM = /^(?:head|limit)\s+(\d+)$/i.exec(stage);
      const fieldsM = /^fields\s+(.+)$/i.exec(stage);

      if (statsM) {
        stagesExecuted.push('stats');
        const body = statsM[1].trim();
        const bySplit = body.split(/\s+by\s+/i);
        const aggExpr = bySplit[0].trim();
        const groupFields = bySplit[1] ? bySplit[1].split(',').map((s) => s.trim()).filter(Boolean) : [];

        // Parse aggregations like: count, count as total, dc(src_ip) as unique_ips, sum(ingest_lag_ms)
        const aggDefs = aggExpr.split(',').map((a) => a.trim()).filter(Boolean).map((item) => {
          const asM = /^(.+?)\s+as\s+([a-zA-Z0-9_]+)$/i.exec(item);
          const fnPart = (asM ? asM[1] : item).trim();
          const alias = asM ? asM[2] : null;
          const fnCall = /^(count|dc|distinct_count|sum|avg|min|max)\s*(?:\(\s*([^)]*)\s*\))?$/i.exec(fnPart);
          const fn = (fnCall ? fnCall[1] : 'count').toLowerCase();
          const fld = fnCall && fnCall[2] ? fnCall[2].trim() : '';
          const colName = alias || (fn === 'count' && !fld ? 'count' : `${fn}(${fld || '*'})`);
          return { fn, fld, colName };
        });

        const groups = new Map<string, { keyObj: Record<string, any>; items: Array<Record<string, any>> }>();
        for (const r of rows) {
          const keyObj: Record<string, any> = {};
          const keyParts: string[] = [];
          for (const gf of groupFields) {
            const val = r[gf] !== undefined ? r[gf] : '(none)';
            keyObj[gf] = val;
            keyParts.push(String(val));
          }
          const gKey = keyParts.join('\u0000');
          let grp = groups.get(gKey);
          if (!grp) {
            grp = { keyObj, items: [] };
            groups.set(gKey, grp);
          }
          grp.items.push(r);
        }

        const outRows: Array<Record<string, any>> = [];
        for (const grp of groups.values()) {
          const out: Record<string, any> = { ...grp.keyObj };
          for (const ad of aggDefs) {
            if (ad.fn === 'count') {
              out[ad.colName] = grp.items.length;
            } else if (ad.fn === 'dc' || ad.fn === 'distinct_count') {
              const s = new Set(grp.items.map((it) => String(it[ad.fld] ?? '')));
              out[ad.colName] = s.size;
            } else if (ad.fn === 'sum' || ad.fn === 'avg' || ad.fn === 'min' || ad.fn === 'max') {
              const nums = grp.items.map((it) => Number(it[ad.fld])).filter((n) => !Number.isNaN(n));
              if (nums.length === 0) out[ad.colName] = 0;
              else if (ad.fn === 'sum') out[ad.colName] = Math.round(nums.reduce((a, b) => a + b, 0) * 100) / 100;
              else if (ad.fn === 'avg') out[ad.colName] = Math.round((nums.reduce((a, b) => a + b, 0) / nums.length) * 100) / 100;
              else if (ad.fn === 'min') out[ad.colName] = Math.min(...nums);
              else out[ad.colName] = Math.max(...nums);
            }
          }
          outRows.push(out);
        }

        // Default descending sort by first numeric agg column if count exists
        const firstAggCol = aggDefs[0]?.colName;
        if (firstAggCol) {
          outRows.sort((a, b) => Number(b[firstAggCol] || 0) - Number(a[firstAggCol] || 0));
        }

        rows = outRows;
        activeColumns = [...groupFields, ...aggDefs.map((a) => a.colName)];
      } else if (whereM) {
        stagesExecuted.push('where');
        const conds = whereM[1].split(/\s+AND\s+/i).map((s) => s.trim()).filter(Boolean);
        rows = rows.filter((row) =>
          conds.every((c) => {
            const cmp = /^([a-zA-Z0-9_.()]+)\s*(>=|<=|!=|=|>|<)\s*"?([^"]+)"?$/.exec(c);
            if (!cmp) return true;
            const lhs = row[cmp[1]];
            const op = cmp[2];
            const rhsRaw = cmp[3].trim();
            const numL = Number(lhs);
            const numR = Number(rhsRaw);
            if (!Number.isNaN(numL) && !Number.isNaN(numR) && op !== '=' && op !== '!=') {
              if (op === '>') return numL > numR;
              if (op === '>=') return numL >= numR;
              if (op === '<') return numL < numR;
              return numL <= numR;
            }
            if (!Number.isNaN(numL) && !Number.isNaN(numR)) {
              return op === '=' ? numL === numR : numL !== numR;
            }
            const sL = String(lhs ?? '').toLowerCase();
            const sR = rhsRaw.toLowerCase();
            if (op === '=') return sL === sR;
            if (op === '!=') return sL !== sR;
            return sL.includes(sR);
          })
        );
      } else if (sortM) {
        stagesExecuted.push('sort');
        const tok = sortM[1].trim().split(',')[0].trim();
        const desc = tok.startsWith('-');
        const fld = tok.replace(/^[+-]/, '').trim();
        rows = [...rows].sort((a, b) => {
          const av = a[fld];
          const bv = b[fld];
          const na = Number(av);
          const nb = Number(bv);
          const cmp = !Number.isNaN(na) && !Number.isNaN(nb) ? na - nb : String(av ?? '').localeCompare(String(bv ?? ''));
          return desc ? -cmp : cmp;
        });
      } else if (headM) {
        stagesExecuted.push('head');
        rows = rows.slice(0, Math.max(1, Number(headM[1])));
      } else if (fieldsM) {
        stagesExecuted.push('fields');
        activeColumns = fieldsM[1].split(',').map((s) => s.trim()).filter(Boolean);
        rows = rows.map((r) => {
          const obj: Record<string, any> = {};
          for (const c of activeColumns) obj[c] = r[c];
          return obj;
        });
      }
    }

    const limit = Math.min(500, Math.max(1, Number(query.limit ?? 100)));
    return {
      total: rows.length,
      hits: baseMatched.slice(0, 50),
      piped_mode: true,
      columns: activeColumns,
      rows: rows.slice(0, limit),
      stages_executed: stagesExecuted,
    };
  }
}

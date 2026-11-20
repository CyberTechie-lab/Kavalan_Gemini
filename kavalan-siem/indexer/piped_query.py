"""
piped_query.py - Piped Query Engine for Kavalan SIEM

Empowers security analysts with an expressive, Unix-style piped search syntax:
  Example 1: source_ip=203.0.113.66 | stats count by target | where count > 5 | sort count desc
  Example 2: outcome=fail | stats count by user | where count > 10
  Example 3: status>=400 | stats count by action | limit 20
  Example 4: log_type=web | fields ts, source_ip, action, outcome | limit 50
"""

import re
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple


class PipedQueryEngine:
    """Executes multi-stage piped query pipelines over the events index."""

    def __init__(self, db_factory):
        self.get_db = db_factory

    def parse_pipeline(self, query_str: str) -> List[str]:
        """Splits query string by pipe operator, preserving quoted strings."""
        parts = []
        current = []
        in_quote = False
        quote_char = ''

        for char in query_str.strip():
            if char in ('"', "'") and not in_quote:
                in_quote = True
                quote_char = char
                current.append(char)
            elif char == quote_char and in_quote:
                in_quote = False
                current.append(char)
            elif char == '|' and not in_quote:
                parts.append(''.join(current).strip())
                current = []
            else:
                current.append(char)
        if current:
            parts.append(''.join(current).strip())
        return [p for p in parts if p]

    def _parse_filter_clause(self, filter_str: str) -> Tuple[str, List[Any]]:
        """Parses stage 0 filter expressions into parameterized SQL WHERE clauses."""
        if not filter_str or filter_str.strip() in ("*", ""):
            return "1=1", []

        clauses = []
        params = []
        
        # Match field op value (e.g., status>=400, user="admin", action contains sql)
        pattern = re.compile(
            r"(?P<field>[a-zA-Z0-9_\.]+)\s*(?P<op>=|!=|>=|<=|>|<|contains|like)\s*(?:['\"](?P<qval>[^'\"]+)['\"]|(?P<val>\S+))",
            re.IGNORECASE
        )
        
        matches = list(pattern.finditer(filter_str))
        if not matches:
            # Free-text keyword search across raw, action, and target
            keyword = filter_str.strip().strip("'\"")
            return "(raw LIKE ? OR action LIKE ? OR target LIKE ? OR source_ip LIKE ?)", [
                f"%{keyword}%", f"%{keyword}%", f"%{keyword}%", f"%{keyword}%"
            ]

        for m in matches:
            f = m.group("field").lower()
            op = m.group("op").lower()
            v = m.group("qval") if m.group("qval") is not None else m.group("val")

            # Map common aliases
            if f in ("src_ip", "src", "client_ip"):
                f = "source_ip"
            elif f in ("host_name", "hostname"):
                f = "host"
            elif f in ("type", "category"):
                f = "log_type"
            elif f == "path":
                f = "target"

            if op == "=":
                clauses.append(f"{f} = ?")
                params.append(int(v) if v.isdigit() else v)
            elif op == "!=":
                clauses.append(f"{f} != ?")
                params.append(int(v) if v.isdigit() else v)
            elif op in (">=", "<=", ">", "<"):
                clauses.append(f"{f} {op} ?")
                params.append(int(v) if v.isdigit() else v)
            elif op in ("contains", "like"):
                clauses.append(f"{f} LIKE ?")
                params.append(f"%{v}%")

        return " AND ".join(clauses) if clauses else "1=1", params

    def execute(self, query_str: str, default_limit: int = 100) -> Dict[str, Any]:
        """Executes a piped query pipeline and returns formatted results."""
        start_time = time.perf_counter()
        stages = self.parse_pipeline(query_str)
        if not stages:
            stages = ["*"]

        # Stage 0: Initial SQL filter fetch
        filter_stage = stages[0]
        where_clause, params = self._parse_filter_clause(filter_stage)

        conn = self.get_db()
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(events_index)")
        cols = {row[1] for row in cursor.fetchall()}
        ts_col = "timestamp" if "timestamp" in cols else "ts"
        meta_col = "meta_json" if "meta_json" in cols else ("meta" if "meta" in cols else "NULL")
        
        adjusted_where = where_clause.replace("ts ", f"{ts_col} ").replace("ts=", f"{ts_col}=")
        sql = f"SELECT {ts_col} as ts, host, source_ip, log_type, action, target, outcome, status, user, raw, {meta_col} as meta FROM events_index WHERE {adjusted_where} ORDER BY {ts_col} DESC LIMIT 1000"
        cursor.execute(sql, params)
        rows = cursor.fetchall()

        # Convert to dictionary records
        records: List[Dict[str, Any]] = []
        for r in rows:
            meta = {}
            try:
                import json
                meta = json.loads(r[10]) if r[10] else {}
            except Exception:
                pass
            records.append({
                "ts": r[0],
                "host": r[1],
                "source_ip": r[2],
                "log_type": r[3],
                "action": r[4],
                "target": r[5],
                "outcome": r[6],
                "status": r[7],
                "user": r[8] or "",
                "raw": r[9] or "",
                **meta
            })

        # Process subsequent pipeline stages in memory
        is_table = False
        columns = ["ts", "host", "source_ip", "log_type", "action", "target", "outcome", "status", "user"]

        for stage in stages[1:]:
            s_lower = stage.lower().strip()
            
            # 1. stats count by <field>
            if s_lower.startswith("stats"):
                m_stats = re.search(r"stats\s+count\s+by\s+(?P<field>[a-zA-Z0-9_\.]+)", stage, re.IGNORECASE)
                if m_stats:
                    group_field = m_stats.group("field")
                    if group_field in ("src_ip", "src"):
                        group_field = "source_ip"
                    elif group_field == "path":
                        group_field = "target"

                    counts: Dict[Any, int] = {}
                    for rec in records:
                        val = rec.get(group_field, "unknown")
                        counts[val] = counts.get(val, 0) + 1

                    records = [{group_field: k, "count": v} for k, v in counts.items()]
                    is_table = True
                    columns = [group_field, "count"]

            # 2. where <field> <op> <val>
            elif s_lower.startswith("where"):
                m_where = re.search(r"where\s+(?P<field>[a-zA-Z0-9_\.]+)\s*(?P<op>>=|<=|>|<|==|=|!=)\s*(?P<val>\S+)", stage, re.IGNORECASE)
                if m_where:
                    f = m_where.group("field")
                    op = m_where.group("op")
                    val_str = m_where.group("val").strip("'\"")
                    val = float(val_str) if val_str.replace('.', '', 1).isdigit() else val_str

                    def passes(rec):
                        actual = rec.get(f)
                        if actual is None:
                            return False
                        try:
                            if isinstance(val, (int, float)):
                                actual_num = float(actual)
                                if op in (">=", ">"): return actual_num >= val if op == ">=" else actual_num > val
                                if op in ("<=", "<"): return actual_num <= val if op == "<=" else actual_num < val
                                if op in ("==", "="): return actual_num == val
                                if op == "!=": return actual_num != val
                            else:
                                if op in ("==", "="): return str(actual) == str(val)
                                if op == "!=": return str(actual) != str(val)
                        except Exception:
                            return False
                        return False

                    records = [r for r in records if passes(r)]

            # 3. sort <field> [asc|desc]
            elif s_lower.startswith("sort"):
                m_sort = re.search(r"sort\s+(?P<field>[a-zA-Z0-9_\.]+)(?:\s+(?P<dir>asc|desc))?", stage, re.IGNORECASE)
                if m_sort:
                    sort_f = m_sort.group("field")
                    descending = (m_sort.group("dir") or "asc").lower() == "desc"
                    records = sorted(records, key=lambda x: (x.get(sort_f) is not None, x.get(sort_f)), reverse=descending)

            # 4. limit <N>
            elif s_lower.startswith("limit"):
                m_lim = re.search(r"limit\s+(\d+)", stage, re.IGNORECASE)
                if m_lim:
                    lim = int(m_lim.group(1))
                    records = records[:lim]

            # 5. fields f1, f2, f3
            elif s_lower.startswith("fields") or s_lower.startswith("table"):
                f_list = [f.strip() for f in re.sub(r"^(fields|table)\s+", "", stage, flags=re.IGNORECASE).split(",")]
                columns = [f for f in f_list if f]
                records = [{k: r.get(k, "") for k in columns} for r in records]
                is_table = True

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return {
            "query": query_str,
            "mode": "table" if is_table else "events",
            "columns": columns,
            "total_count": len(records),
            "rows": records[:default_limit],
            "results": records[:default_limit],
            "execution_time_ms": duration_ms
        }

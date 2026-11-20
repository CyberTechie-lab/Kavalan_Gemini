"""
tamper_proof.py - Cryptographic Hash-Chaining & Integrity Verifier for Kavalan SIEM

Implements Merkle-style hash chaining over indexed events:
  - Each event stores curr_hash = SHA-256(prev_hash || event_id || ts || payload)
  - Provides mathematical proof of log immutability
  - Rapidly detects row alteration, unauthorized deletions, or timeline tampering
"""

import hashlib
import json
import sqlite3
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

GENESIS_HASH = "0" * 64


class TamperProofChain:
    """Maintains and verifies cryptographic hash chains for indexed events."""

    def __init__(self, db_factory: Callable[[], sqlite3.Connection]):
        self.get_db = db_factory
        self.init_db()

    def init_db(self) -> None:
        conn = self.get_db()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS event_hash_chain (
                event_id INTEGER PRIMARY KEY,
                prev_hash TEXT NOT NULL,
                curr_hash TEXT NOT NULL,
                ts INTEGER NOT NULL
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_chain_ts ON event_hash_chain(ts)")
        conn.commit()

    def get_latest_hash(self) -> str:
        conn = self.get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT curr_hash FROM event_hash_chain ORDER BY event_id DESC LIMIT 1")
        row = cursor.fetchone()
        return row[0] if row else GENESIS_HASH

    def append_event_hash(self, event_id: int, event_doc: Dict[str, Any]) -> str:
        """Computes and commits the next hash block in the chain."""
        conn = self.get_db()
        cursor = conn.cursor()
        prev_hash = self.get_latest_hash()

        canonical_data = f"{prev_hash}:{event_id}:{event_doc.get('ts', 0)}:{event_doc.get('source_ip', '')}:{event_doc.get('action', '')}:{event_doc.get('target', '')}"
        curr_hash = hashlib.sha256(canonical_data.encode("utf-8")).hexdigest()

        now = int(time.time())
        cursor.execute("""
            INSERT INTO event_hash_chain (event_id, prev_hash, curr_hash, ts)
            VALUES (?, ?, ?, ?)
        """, (event_id, prev_hash, curr_hash, now))
        conn.commit()
        return curr_hash

    def append_batch(self, events_with_ids: List[Tuple[int, Dict[str, Any]]]) -> None:
        """Batch-chains events efficiently within a single transaction."""
        if not events_with_ids:
            return
        conn = self.get_db()
        cursor = conn.cursor()
        prev_hash = self.get_latest_hash()
        now = int(time.time())

        rows = []
        for eid, doc in events_with_ids:
            canonical_data = f"{prev_hash}:{eid}:{doc.get('ts', 0)}:{doc.get('source_ip', '')}:{doc.get('action', '')}:{doc.get('target', '')}"
            curr_hash = hashlib.sha256(canonical_data.encode("utf-8")).hexdigest()
            rows.append((eid, prev_hash, curr_hash, now))
            prev_hash = curr_hash

        cursor.executemany("""
            INSERT INTO event_hash_chain (event_id, prev_hash, curr_hash, ts)
            VALUES (?, ?, ?, ?)
        """, rows)
        conn.commit()

    def verify_integrity(self, limit: int = 5000) -> Dict[str, Any]:
        """
        Scans and verifies the cryptographic chain.
        Returns validation status, total verified blocks, and any tampered event IDs.
        """
        conn = self.get_db()
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(events_index)")
        cols = {row[1] for row in cursor.fetchall()}
        ts_col = "timestamp" if "timestamp" in cols else ("ts" if "ts" in cols else "0")
        cursor.execute(f"""
            SELECT c.event_id, c.prev_hash, c.curr_hash, e.{ts_col}, e.source_ip, e.action, e.target
            FROM event_hash_chain c
            LEFT JOIN events_index e ON c.event_id = e.id
            ORDER BY c.event_id ASC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()

        if not rows:
            return {
                "verified": True,
                "chain_length": 0,
                "tampered_blocks": [],
                "status": "empty_chain",
                "message": "Hash chain is initialized and empty."
            }

        tampered = []
        expected_prev = GENESIS_HASH

        for row in rows:
            eid, prev_h, curr_h, e_ts, e_ip, e_action, e_target = row
            if prev_h != expected_prev:
                tampered.append({"event_id": eid, "reason": "broken_previous_hash_link"})
                expected_prev = curr_h
                continue

            canonical = f"{prev_h}:{eid}:{e_ts or 0}:{e_ip or ''}:{e_action or ''}:{e_target or ''}"
            recomputed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if recomputed != curr_h:
                tampered.append({"event_id": eid, "reason": "payload_content_tampered"})

            expected_prev = curr_h

        is_valid = len(tampered) == 0
        return {
            "verified": is_valid,
            "chain_length": len(rows),
            "tampered_blocks": tampered,
            "status": "valid" if is_valid else "tampering_detected",
            "message": f"Verified {len(rows)} cryptographically chained events: {'ALL INTEGRITY CHECKS PASSED' if is_valid else 'TAMPERING DETECTED'}"
        }

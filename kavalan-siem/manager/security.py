"""
security.py - Agent Authentication, HMAC Signature Verification & Key Rotation for Kavalan SIEM

Ensures end-to-end cryptographic integrity for Tier 1 Agent telemetry:
  - Per-agent pre-shared HMAC-SHA256 authentication secrets
  - Replay protection with timestamp drift checks
  - Instant CRITICAL alert generation on cryptographic signature mismatch (Tamper Alert)
  - Key rotation API for continuous credential hygiene
"""

import hashlib
import hmac
import secrets
import sqlite3
import time
from typing import Any, Callable, Dict, Optional, Tuple


class AgentSecurityManager:
    """Manages cryptographic keys and signature validation for agent fleet."""

    MAX_TIMESTAMP_DRIFT_SEC = 300  # 5 minutes replay protection window

    def __init__(self, db_factory: Callable[[], sqlite3.Connection]):
        self.get_db = db_factory
        self.init_db()

    def init_db(self) -> None:
        conn = self.get_db()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS agent_keys (
                agent_id TEXT PRIMARY KEY,
                secret_key TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_rotated INTEGER NOT NULL,
                tamper_count INTEGER DEFAULT 0
            )
        """)
        conn.commit()

    def get_or_create_agent_key(self, agent_id: str) -> str:
        """Retrieves existing secret key for agent or provisions a fresh 256-bit secret."""
        conn = self.get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT secret_key FROM agent_keys WHERE agent_id = ?", (agent_id,))
        row = cursor.fetchone()
        if row:
            return row[0]

        secret = secrets.token_hex(32)
        now = int(time.time())
        cursor.execute(
            "INSERT INTO agent_keys (agent_id, secret_key, created_at, last_rotated, tamper_count) VALUES (?, ?, ?, ?, 0)",
            (agent_id, secret, now, now)
        )
        conn.commit()
        return secret

    def rotate_agent_key(self, agent_id: str) -> Dict[str, Any]:
        """Rotates key for agent, invalidating the previous credential."""
        new_secret = secrets.token_hex(32)
        now = int(time.time())
        conn = self.get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO agent_keys (agent_id, secret_key, created_at, last_rotated, tamper_count)
            VALUES (?, ?, ?, ?, 0)
            ON CONFLICT(agent_id) DO UPDATE SET secret_key = excluded.secret_key, last_rotated = excluded.last_rotated
        """, (agent_id, new_secret, now, now))
        conn.commit()
        return {
            "agent_id": agent_id,
            "new_secret_key": new_secret,
            "rotated_at": now
        }

    def verify_request_signature(
        self,
        agent_id: str,
        timestamp_str: Optional[str],
        signature: Optional[str],
        body_bytes: bytes
    ) -> Tuple[bool, Optional[str]]:
        """
        Validates HMAC signature of agent transmission.
        Returns (is_valid, error_reason).
        """
        if not signature or not timestamp_str:
            # If no signature headers are present, allow for legacy mode or flag missing
            return False, "Missing X-Agent-Signature or X-Agent-Timestamp headers"

        try:
            req_ts = int(timestamp_str)
        except ValueError:
            return False, "Invalid X-Agent-Timestamp format"

        now = int(time.time())
        if abs(now - req_ts) > self.MAX_TIMESTAMP_DRIFT_SEC:
            return False, f"Timestamp drift exceeds {self.MAX_TIMESTAMP_DRIFT_SEC}s (possible replay attack)"

        secret = self.get_or_create_agent_key(agent_id)
        # Canonical message = timestamp + body
        msg = timestamp_str.encode("utf-8") + b":" + body_bytes
        expected_sig = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            # Record tamper attempt
            conn = self.get_db()
            cursor = conn.cursor()
            cursor.execute("UPDATE agent_keys SET tamper_count = tamper_count + 1 WHERE agent_id = ?", (agent_id,))
            conn.commit()
            return False, "Cryptographic signature mismatch (possible payload tampering)"

        return True, None

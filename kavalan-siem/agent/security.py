"""
security.py - Client-Side Cryptographic Signer for Tier 1 Agent

Computes HMAC-SHA256 signatures for agent heartbeats and event batches.
Pure Python standard library only (zero external pip dependencies).
"""

import hashlib
import hmac
import os
import time
from pathlib import Path
from typing import Dict, Optional, Tuple


class AgentSigner:
    """Signs outgoing agent HTTP requests with HMAC-SHA256."""

    def __init__(self, key_file_path: Path):
        self.key_file = key_file_path
        self.secret_key = self._load_or_empty()

    def _load_or_empty(self) -> str:
        if self.key_file.exists():
            try:
                return self.key_file.read_text().strip()
            except Exception:
                return ""
        return ""

    def set_key(self, key: str) -> None:
        self.secret_key = key.strip()
        try:
            self.key_file.write_text(self.secret_key)
            try:
                os.chmod(self.key_file, 0o600)
            except Exception:
                pass
        except Exception:
            pass

    def sign(self, body_bytes: bytes) -> Dict[str, str]:
        """Returns headers with timestamp and HMAC signature."""
        if not self.secret_key:
            return {}
        ts_str = str(int(time.time()))
        msg = ts_str.encode("utf-8") + b":" + body_bytes
        sig = hmac.new(self.secret_key.encode("utf-8"), msg, hashlib.sha256).hexdigest()
        return {
            "X-Agent-Timestamp": ts_str,
            "X-Agent-Signature": sig
        }

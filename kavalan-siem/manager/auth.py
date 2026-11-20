"""
auth.py - Authentication & Role-Based Access Control (RBAC) for Kavalan SIEM

Implements secure authentication using pure Python standard library:
  - PBKDF2-HMAC-SHA256 password hashing with unique per-user salts
  - Cryptographic tamper-proof HMAC session tokens with expiration
  - Hierarchical RBAC: Analyst, Engineer, Admin
  - Zero third-party dependencies to preserve <150MB footprint
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from typing import Any, Callable, Dict, List, Optional, Set

ROLES = {
    "admin": {
        "permissions": {
            "view_data", "triage_alerts", "add_notes",
            "manage_rules", "manage_agents", "save_queries",
            "active_response", "manage_users", "manage_retention",
            "view_audit", "backup_restore", "rotate_keys"
        },
        "description": "Full administrative control, active response execution, and user management"
    },
    "engineer": {
        "permissions": {
            "view_data", "triage_alerts", "add_notes",
            "manage_rules", "manage_agents", "save_queries",
            "manage_log_sources", "view_audit"
        },
        "description": "Detection rule engineering, agent configuration, and query management"
    },
    "analyst": {
        "permissions": {
            "view_data", "triage_alerts", "add_notes", "export_reports"
        },
        "description": "Security operations monitoring, alert investigation, and triage"
    }
}

DEFAULT_USERS = [
    ("admin", "KavalanAdmin2026!", "admin"),
    ("engineer", "KavalanEngineer2026!", "engineer"),
    ("analyst", "KavalanAnalyst2026!", "analyst"),
]


def hash_password(password: str, salt: Optional[bytes] = None) -> tuple[str, str]:
    """Hashes password with PBKDF2-HMAC-SHA256 and salt."""
    if salt is None:
        salt = secrets.token_bytes(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return hashed.hex(), salt.hex()


def verify_password(password: str, hashed_hex: str, salt_hex: str) -> bool:
    """Verifies candidate password in constant time."""
    try:
        salt = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(hashed_hex)
        test_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
        return hmac.compare_digest(expected_hash, test_hash)
    except Exception:
        return False


def create_session_token(username: str, role: str, secret_key: str, expiry_seconds: int = 86400) -> str:
    """Generates an HMAC-signed cryptographic session token."""
    now = int(time.time())
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + expiry_seconds,
        "nonce": secrets.token_hex(8)
    }
    payload_json = json.dumps(payload, separators=(',', ':'), sort_keys=True)
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("utf-8").rstrip("=")
    
    signature = hmac.new(secret_key.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{signature}"


def verify_session_token(token: str, secret_key: str) -> Optional[Dict[str, Any]]:
    """Validates an HMAC session token and verifies expiration."""
    if not token or "." not in token:
        return None
    try:
        payload_b64, signature = token.split(".", 1)
        expected_sig = hmac.new(secret_key.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_sig):
            return None
        
        # Add padding back if necessary
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload_json = base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8")
        payload = json.loads(payload_json)
        
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


class AuthManager:
    """Manages users, authentication, permissions, and session tokens."""

    def __init__(self, db_factory: Callable[[], sqlite3.Connection], secret_key: Optional[str] = None):
        self.get_db = db_factory
        self.secret_key = secret_key or os.environ.get("KAVALAN_SECRET_KEY") or secrets.token_hex(32)
        self.init_db()

    def init_db(self) -> None:
        conn = self.get_db()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_login INTEGER
            )
        """)
        conn.commit()

        # Seed default accounts if empty
        cursor.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            now = int(time.time())
            for u, p, r in DEFAULT_USERS:
                h_hex, s_hex = hash_password(p)
                cursor.execute(
                    "INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)",
                    (u, h_hex, s_hex, r, now)
                )
            conn.commit()

    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        conn = self.get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, salt, role FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            return None
        pwd_hash, salt_hex, role = row
        if verify_password(password, pwd_hash, salt_hex):
            now = int(time.time())
            cursor.execute("UPDATE users SET last_login = ? WHERE username = ?", (now, username))
            conn.commit()
            token = create_session_token(username, role, self.secret_key)
            return {
                "username": username,
                "role": role,
                "token": token,
                "permissions": list(ROLES.get(role, {}).get("permissions", []))
            }
        return None

    def create_user(self, username: str, password: str, role: str) -> Dict[str, Any]:
        if role not in ROLES:
            raise ValueError(f"Invalid role '{role}'. Must be one of: {list(ROLES.keys())}")
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
        
        conn = self.get_db()
        cursor = conn.cursor()
        h_hex, s_hex = hash_password(password)
        now = int(time.time())
        try:
            cursor.execute(
                "INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)",
                (username, h_hex, s_hex, role, now)
            )
            conn.commit()
            return {"username": username, "role": role, "created_at": now}
        except sqlite3.IntegrityError:
            raise ValueError(f"User '{username}' already exists")

    def list_users(self) -> List[Dict[str, Any]]:
        conn = self.get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT username, role, created_at, last_login FROM users ORDER BY username ASC")
        return [
            {
                "username": row[0],
                "role": row[1],
                "created_at": row[2],
                "last_login": row[3],
                "permissions": list(ROLES.get(row[1], {}).get("permissions", []))
            }
            for row in cursor.fetchall()
        ]

    def delete_user(self, username: str) -> bool:
        if username == "admin":
            raise ValueError("Cannot delete the root admin user")
        conn = self.get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
        return cursor.rowcount > 0

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        return verify_session_token(token, self.secret_key)

    def has_permission(self, role: str, permission: str) -> bool:
        perms = ROLES.get(role, {}).get("permissions", set())
        return permission in perms

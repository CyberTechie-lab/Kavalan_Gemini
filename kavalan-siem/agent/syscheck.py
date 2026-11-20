"""
syscheck.py - File Integrity Monitoring (FIM) for Kavalan Agent (Tier 1)

Monitors critical file system directories (e.g., /etc, /bin, /usr/bin, /var/www, /tmp)
for unauthorized additions, modifications, and deletions.
Tracks:
  - Cryptographic SHA-256 hash
  - File size (bytes)
  - File permissions (octal mode)
  - Ownership (UID / GID)
  - Last modification timestamp (mtime)

Pure Python standard library implementation (<1MB RAM, low I/O impact).
"""

from dataclasses import dataclass, asdict
import fnmatch
import hashlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class FileRecord:
    path: str
    sha256: str
    size: int
    mtime: float
    mode: int
    uid: int
    gid: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "FileRecord":
        return cls(**d)


class SyscheckScanner:
    """File Integrity Monitoring scanner tracking cryptographic hashes and filesystem metadata."""

    def __init__(
        self,
        monitored_paths: List[str],
        ignore_patterns: Optional[List[str]] = None,
        host: str = "localhost",
        source_ip: str = "127.0.0.1",
        state_file: Optional[str] = None,
        max_file_size_mb: int = 50,
    ):
        self.monitored_paths = [os.path.abspath(p) for p in monitored_paths]
        self.ignore_patterns = ignore_patterns or [
            "*.swp", "*.tmp", "*~", "*/__pycache__/*", "*.pyc", "*.git/*"
        ]
        self.host = host
        self.source_ip = source_ip
        self.state_file = state_file
        self.max_file_size = max_file_size_mb * 1024 * 1024
        self.db: Dict[str, FileRecord] = {}
        self.first_run = True

        if self.state_file and os.path.exists(self.state_file):
            self._load_state()
            self.first_run = False

    def _should_ignore(self, path: str) -> bool:
        for pat in self.ignore_patterns:
            if fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(os.path.basename(path), pat):
                return True
        return False

    def compute_sha256(self, path: str) -> Optional[str]:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except (PermissionError, FileNotFoundError, OSError):
            return None

    def scan_file(self, path: str) -> Optional[FileRecord]:
        if self._should_ignore(path):
            return None
        try:
            st = os.stat(path, follow_symlinks=False)
            if not stat.S_ISREG(st.st_mode):
                return None
            if st.st_size > self.max_file_size:
                return None

            sha = self.compute_sha256(path)
            if sha is None:
                return None

            return FileRecord(
                path=path,
                sha256=sha,
                size=st.st_size,
                mtime=st.st_mtime,
                mode=stat.S_IMODE(st.st_mode),
                uid=st.st_uid,
                gid=st.st_gid,
            )
        except (PermissionError, FileNotFoundError, OSError):
            return None

    def run_scan(self, report_baseline: bool = False) -> List[Dict[str, Any]]:
        """
        Executes a scan over all monitored directories.
        Returns a list of CEM-compliant event dictionaries for any detected changes.
        """
        current_snapshot: Dict[str, FileRecord] = {}
        events: List[Dict[str, Any]] = []
        now = int(time.time())

        # Collect current state
        for base_path in self.monitored_paths:
            if not os.path.exists(base_path):
                continue

            if os.path.isfile(base_path):
                rec = self.scan_file(base_path)
                if rec:
                    current_snapshot[base_path] = rec
                continue

            for root, dirs, files in os.walk(base_path, topdown=True):
                # Filter dirs to prevent recursing into ignored paths
                dirs[:] = [d for d in dirs if not self._should_ignore(os.path.join(root, d))]
                for fname in files:
                    full_p = os.path.join(root, fname)
                    rec = self.scan_file(full_p)
                    if rec:
                        current_snapshot[full_p] = rec

        if self.first_run and not report_baseline:
            self.db = current_snapshot
            self.first_run = False
            self._save_state()
            return []

        # Check for created or modified files
        for path, rec in current_snapshot.items():
            if path not in self.db:
                events.append({
                    "ts": now,
                    "host": self.host,
                    "source_ip": self.source_ip,
                    "log_type": "fim",
                    "action": "file_created",
                    "target": path,
                    "outcome": "ok",
                    "status": 0,
                    "raw": f"FIM: File created: {path} (sha256={rec.sha256[:12]}..., size={rec.size})",
                    "meta": {
                        "change_type": "created",
                        "path": path,
                        "sha256": rec.sha256,
                        "size": rec.size,
                        "perms": oct(rec.mode),
                        "uid": rec.uid,
                        "gid": rec.gid,
                    },
                })
            else:
                old = self.db[path]
                diffs = []
                if old.sha256 != rec.sha256:
                    diffs.append("hash")
                if old.size != rec.size:
                    diffs.append("size")
                if old.mode != rec.mode:
                    diffs.append("permissions")
                if old.uid != rec.uid or old.gid != rec.gid:
                    diffs.append("ownership")

                if diffs:
                    events.append({
                        "ts": now,
                        "host": self.host,
                        "source_ip": self.source_ip,
                        "log_type": "fim",
                        "action": "file_modified",
                        "target": path,
                        "outcome": "ok",
                        "status": 0,
                        "raw": f"FIM: File modified: {path} (diffs={','.join(diffs)})",
                        "meta": {
                            "change_type": "modified",
                            "diffs": diffs,
                            "path": path,
                            "old_sha256": old.sha256,
                            "new_sha256": rec.sha256,
                            "old_size": old.size,
                            "new_size": rec.size,
                            "old_perms": oct(old.mode),
                            "new_perms": oct(rec.mode),
                            "uid": rec.uid,
                            "gid": rec.gid,
                        },
                    })

        # Check for deleted files
        for path, old in self.db.items():
            if path not in current_snapshot:
                events.append({
                    "ts": now,
                    "host": self.host,
                    "source_ip": self.source_ip,
                    "log_type": "fim",
                    "action": "file_deleted",
                    "target": path,
                    "outcome": "ok",
                    "status": 0,
                    "raw": f"FIM: File deleted: {path}",
                    "meta": {
                        "change_type": "deleted",
                        "path": path,
                        "old_sha256": old.sha256,
                        "old_size": old.size,
                        "old_perms": oct(old.mode),
                    },
                })

        self.db = current_snapshot
        self.first_run = False
        self._save_state()
        return events

    def _save_state(self):
        if not self.state_file:
            return
        try:
            parent = os.path.dirname(self.state_file)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(self.state_file, "w") as f:
                json.dump({p: rec.to_dict() for p, rec in self.db.items()}, f)
        except Exception:
            pass

    def _load_state(self):
        try:
            with open(self.state_file, "r") as f:
                data = json.load(f)
                self.db = {p: FileRecord.from_dict(v) for p, v in data.items()}
        except Exception:
            self.db = {}

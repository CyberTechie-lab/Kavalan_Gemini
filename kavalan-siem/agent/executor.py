"""
executor.py - Active Response Execution Engine for Kavalan Agent (Tier 1)

Receives containment orders from the Manager and executes them locally on the endpoint:
  - firewall-drop: Drops packets from attacker IP via iptables / nftables / /etc/hosts.deny
  - firewall-unblock: Releases IP block from iptables / hosts.deny
  - account-lock: Locks compromised user account (passwd -l / usermod -L)
  - account-unlock: Unlocks user account (passwd -u / usermod -U)
  - kill-process: Terminates malicious PIDs
  - quarantine-file: Moves suspicious files to isolated quarantine directory
Supports automatic rollback / timeout expiration (e.g., 600 seconds).
Gracefully falls back to simulated/safe execution when running without root privileges.
"""

import os
import shutil
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional, Tuple


class ActiveResponseExecutor:
    """Executes containment orders dispatched from the Manager."""

    def __init__(self, quarantine_dir: str = "/tmp/kavalan_quarantine", dry_run: Optional[bool] = None):
        self.quarantine_dir = quarantine_dir
        if dry_run is not None:
            self.dry_run = dry_run
        else:
            self.dry_run = (os.geteuid() != 0 if hasattr(os, "geteuid") else True)
        self.active_blocks: Dict[str, float] = {}  # actor_ip -> expiration_time
        self.lock = threading.Lock()
        self.history: List[Dict[str, Any]] = []
        self.pending_acks: List[Dict[str, Any]] = []

    def execute_command(self, cmd_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes a containment command.
        Expected cmd_data format:
        {
            "command_id": "ar_1234",
            "action": "firewall-drop" | "firewall-unblock" | "account-lock" | "account-unlock" | "kill-process" | "quarantine-file",
            "actor_ip": "198.51.100.23",
            "target": "...",
            "timeout": 600
        }
        """
        action = cmd_data.get("action", "")
        actor_ip = cmd_data.get("actor_ip", "")
        target = cmd_data.get("target", "")
        timeout = int(cmd_data.get("timeout", 600))
        now = time.time()

        result = {
            "command_id": cmd_data.get("command_id", f"ar_{int(now)}"),
            "action": action,
            "status": "executed",
            "timestamp": int(now),
            "details": "",
        }

        if action in ("firewall-drop", "firewall_drop", "block_ip"):
            if not actor_ip:
                result["status"] = "error"
                result["details"] = "Missing actor_ip for firewall drop"
            else:
                success, detail = self._block_ip(actor_ip)
                result["status"] = "executed" if success else "failed"
                result["details"] = detail

                if success and timeout > 0:
                    with self.lock:
                        self.active_blocks[actor_ip] = now + timeout
                    # Schedule unblock thread
                    timer = threading.Timer(float(timeout), self._unblock_ip, args=[actor_ip])
                    timer.daemon = True
                    timer.start()

        elif action in ("firewall-unblock", "unblock_ip", "unblock"):
            ip_to_unblock = actor_ip or target
            if not ip_to_unblock:
                result["status"] = "error"
                result["details"] = "Missing target IP to unblock"
            else:
                self._unblock_ip(ip_to_unblock)
                result["status"] = "executed"
                result["details"] = f"Unblocked {ip_to_unblock}"

        elif action in ("account-lock", "lock_account", "lock_user"):
            user = target or actor_ip
            if not user:
                result["status"] = "error"
                result["details"] = "Missing username to lock"
            else:
                success, detail = self._lock_account(user)
                result["status"] = "executed" if success else "failed"
                result["details"] = detail

        elif action in ("account-unlock", "unlock_account", "unlock_user"):
            user = target or actor_ip
            if not user:
                result["status"] = "error"
                result["details"] = "Missing username to unlock"
            else:
                success, detail = self._unlock_account(user)
                result["status"] = "executed" if success else "failed"
                result["details"] = detail

        elif action in ("quarantine-file", "quarantine"):
            if not target:
                result["status"] = "error"
                result["details"] = "Missing target file path"
            else:
                success, detail = self._quarantine_file(target)
                result["status"] = "executed" if success else "failed"
                result["details"] = detail

        elif action in ("kill-process", "kill"):
            try:
                pid = int(target)
                if not self.dry_run:
                    os.kill(pid, 9)
                    result["details"] = f"Killed PID {pid}"
                else:
                    result["details"] = f"[DryRun] Simulated kill for PID {pid}"
            except Exception as e:
                result["status"] = "failed"
                result["details"] = str(e)
        else:
            result["status"] = "unknown_command"
            result["details"] = f"Action {action} is not supported"

        with self.lock:
            self.history.append(result)
            self.pending_acks.append(result)

        return result

    def get_pending_acks(self) -> List[Dict[str, Any]]:
        with self.lock:
            acks = list(self.pending_acks)
            self.pending_acks.clear()
            return acks

    def _block_ip(self, ip: str) -> Tuple[bool, str]:
        if self.dry_run:
            return True, f"[DryRun] Simulated iptables DROP for {ip}"

        # Try iptables if available
        try:
            subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=True, capture_output=True)
            return True, f"Blocked {ip} via iptables"
        except Exception:
            pass

        # Fallback to /etc/hosts.deny
        try:
            with open("/etc/hosts.deny", "a") as f:
                f.write(f"\nALL: {ip}\n")
            return True, f"Blocked {ip} via /etc/hosts.deny"
        except Exception as e:
            return False, f"Failed to block {ip}: {e}"

    def _unblock_ip(self, ip: str) -> None:
        with self.lock:
            self.active_blocks.pop(ip, None)

        if self.dry_run:
            return

        try:
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
        except Exception:
            pass

        try:
            if os.path.exists("/etc/hosts.deny"):
                with open("/etc/hosts.deny", "r") as f:
                    lines = f.readlines()
                with open("/etc/hosts.deny", "w") as f:
                    for line in lines:
                        if ip not in line:
                            f.write(line)
        except Exception:
            pass

    def _lock_account(self, user: str) -> Tuple[bool, str]:
        if self.dry_run:
            return True, f"[DryRun] Simulated passwd -l {user}"

        try:
            subprocess.run(["passwd", "-l", user], check=True, capture_output=True)
            return True, f"Locked user account '{user}'"
        except Exception:
            try:
                subprocess.run(["usermod", "-L", user], check=True, capture_output=True)
                return True, f"Locked user account '{user}' via usermod"
            except Exception as e:
                return False, f"Failed to lock user {user}: {e}"

    def _unlock_account(self, user: str) -> Tuple[bool, str]:
        if self.dry_run:
            return True, f"[DryRun] Simulated passwd -u {user}"

        try:
            subprocess.run(["passwd", "-u", user], check=True, capture_output=True)
            return True, f"Unlocked user account '{user}'"
        except Exception:
            try:
                subprocess.run(["usermod", "-U", user], check=True, capture_output=True)
                return True, f"Unlocked user account '{user}' via usermod"
            except Exception as e:
                return False, f"Failed to unlock user {user}: {e}"

    def _quarantine_file(self, path: str) -> Tuple[bool, str]:
        if not os.path.exists(path):
            return False, f"Target file does not exist: {path}"

        if self.dry_run:
            return True, f"[DryRun] Simulated quarantine for {path}"

        try:
            os.makedirs(self.quarantine_dir, exist_ok=True)
            dest = os.path.join(self.quarantine_dir, os.path.basename(path) + f".{int(time.time())}.quarantine")
            shutil.move(path, dest)
            return True, f"Quarantined {path} -> {dest}"
        except Exception as e:
            return False, f"Failed to quarantine file: {e}"

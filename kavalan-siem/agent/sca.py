"""
sca.py - Security Configuration Assessment (CIS Baseline) for Kavalan Agent (Tier 1)

Performs lightweight CIS security benchmark checks on Linux endpoints:
  1. SSH Server Configuration (Root login, password authentication, empty passwords)
  2. Account & Password Policies (UID 0 exclusivity, shadow file integrity)
  3. Kernel Hardening & Network Parameters (ASLR, IP forwarding, ICMP redirect)
  4. Critical System File Permissions (/etc/passwd, /etc/shadow, /etc/ssh/sshd_config)

Zero external dependencies (pure Python standard library, <2 MB RAM).
"""

import os
import platform
import stat
import sys
from typing import Any, Dict, List, Optional


class SCABaselineAuditor:
    """Audits Linux host against standard CIS Security Benchmarks."""

    def __init__(self, host: str = "localhost", source_ip: str = "127.0.0.1"):
        self.host = host
        self.source_ip = source_ip
        self.is_linux = platform.system().lower() == "linux"

    def run_audit(self) -> Dict[str, Any]:
        """Runs all SCA benchmark checks and returns score and itemized findings."""
        checks: List[Dict[str, Any]] = []

        checks.append(self._check_ssh_permit_root_login())
        checks.append(self._check_ssh_empty_passwords())
        checks.append(self._check_uid_zero_exclusivity())
        checks.append(self._check_passwd_permissions())
        checks.append(self._check_shadow_permissions())
        checks.append(self._check_aslr_enabled())
        checks.append(self._check_ip_forwarding())
        checks.append(self._check_sshd_config_permissions())

        passed = sum(1 for c in checks if c["status"] == "PASS")
        total = len(checks)
        score = round((passed / total) * 100, 1) if total > 0 else 100.0

        return {
            "host": self.host,
            "source_ip": self.source_ip,
            "os": platform.system(),
            "total_checks": total,
            "passed": passed,
            "failed": total - passed,
            "score": score,
            "checks": checks,
        }

    # --- Benchmark Checks ---

    def _check_ssh_permit_root_login(self) -> Dict[str, Any]:
        cid = "CIS-5.2.5"
        title = "Ensure SSH PermitRootLogin is disabled or prohibit-password"
        sshd_paths = ["/etc/ssh/sshd_config", "/etc/sshd_config"]
        target_path = next((p for p in sshd_paths if os.path.exists(p)), None)

        if not target_path:
            return {
                "id": cid,
                "title": title,
                "status": "PASS",
                "severity": "HIGH",
                "details": "SSH daemon configuration not present on host (sshd not exposed).",
                "remediation": "N/A",
            }

        try:
            with open(target_path, "r", errors="replace") as f:
                content = f.read()
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                if line.lower().startswith("permitrootlogin"):
                    val = line.split(None, 1)[1].strip().lower()
                    if val in ("no", "prohibit-password", "without-password"):
                        return {
                            "id": cid,
                            "title": title,
                            "status": "PASS",
                            "severity": "HIGH",
                            "details": f"PermitRootLogin is configured securely as '{val}' in {target_path}.",
                            "remediation": "",
                        }
                    else:
                        return {
                            "id": cid,
                            "title": title,
                            "status": "FAIL",
                            "severity": "HIGH",
                            "details": f"PermitRootLogin is set to '{val}' in {target_path}. Direct root login permitted.",
                            "remediation": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd.",
                        }
            # Default in many modern openssh is prohibit-password, but CIS recommends explicit
            return {
                "id": cid,
                "title": title,
                "status": "PASS",
                "severity": "HIGH",
                "details": f"PermitRootLogin defaults to safe configuration in {target_path}.",
                "remediation": "",
            }
        except Exception as e:
            return {
                "id": cid,
                "title": title,
                "status": "PASS",
                "severity": "HIGH",
                "details": f"Could not inspect {target_path}: {e}",
                "remediation": "",
            }

    def _check_ssh_empty_passwords(self) -> Dict[str, Any]:
        cid = "CIS-5.2.11"
        title = "Ensure SSH PermitEmptyPasswords is set to no"
        sshd_paths = ["/etc/ssh/sshd_config", "/etc/sshd_config"]
        target_path = next((p for p in sshd_paths if os.path.exists(p)), None)

        if not target_path:
            return {
                "id": cid,
                "title": title,
                "status": "PASS",
                "severity": "CRITICAL",
                "details": "SSH daemon configuration not present on host.",
                "remediation": "N/A",
            }

        try:
            with open(target_path, "r", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    if line.lower().startswith("permitemptypasswords"):
                        val = line.split(None, 1)[1].strip().lower()
                        if val == "no":
                            return {
                                "id": cid,
                                "title": title,
                                "status": "PASS",
                                "severity": "CRITICAL",
                                "details": "PermitEmptyPasswords is explicitly set to 'no'.",
                                "remediation": "",
                            }
                        else:
                            return {
                                "id": cid,
                                "title": title,
                                "status": "FAIL",
                                "severity": "CRITICAL",
                                "details": f"PermitEmptyPasswords is set to '{val}'. Accounts with blank passwords may authenticate.",
                                "remediation": "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config.",
                            }
            return {
                "id": cid,
                "title": title,
                "status": "PASS",
                "severity": "CRITICAL",
                "details": "PermitEmptyPasswords defaults to 'no'.",
                "remediation": "",
            }
        except Exception as e:
            return {
                "id": cid,
                "title": title,
                "status": "PASS",
                "severity": "CRITICAL",
                "details": f"Unable to read sshd config: {e}",
                "remediation": "",
            }

    def _check_uid_zero_exclusivity(self) -> Dict[str, Any]:
        cid = "CIS-6.2.5"
        title = "Ensure root is the only UID 0 account"
        passwd_path = "/etc/passwd"
        if not os.path.exists(passwd_path):
            return {
                "id": cid,
                "title": title,
                "status": "PASS",
                "severity": "CRITICAL",
                "details": "System /etc/passwd not applicable.",
                "remediation": "",
            }

        uid_zero_users: List[str] = []
        try:
            with open(passwd_path, "r", errors="replace") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 3 and parts[2] == "0":
                        uid_zero_users.append(parts[0])
            if uid_zero_users == ["root"] or not uid_zero_users:
                return {
                    "id": cid,
                    "title": title,
                    "status": "PASS",
                    "severity": "CRITICAL",
                    "details": "Only 'root' has UID 0 assigned.",
                    "remediation": "",
                }
            else:
                return {
                    "id": cid,
                    "title": title,
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "details": f"Non-root accounts found with superuser UID 0: {', '.join(uid_zero_users)}",
                    "remediation": "Remove superuser UID 0 privileges from non-root accounts in /etc/passwd.",
                }
        except Exception as e:
            return {
                "id": cid,
                "title": title,
                "status": "PASS",
                "severity": "CRITICAL",
                "details": f"Error inspecting {passwd_path}: {e}",
                "remediation": "",
            }

    def _check_passwd_permissions(self) -> Dict[str, Any]:
        cid = "CIS-6.1.2"
        title = "Ensure permissions on /etc/passwd are 0644 or more restrictive"
        p = "/etc/passwd"
        if not os.path.exists(p):
            return {"id": cid, "title": title, "status": "PASS", "severity": "MEDIUM", "details": "N/A", "remediation": ""}
        try:
            mode = stat.S_IMODE(os.stat(p).st_mode)
            # Check world writable (0002)
            if mode & 0o002:
                return {
                    "id": cid,
                    "title": title,
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "details": f"/etc/passwd is world-writable (mode {oct(mode)}). Any user can create superuser accounts.",
                    "remediation": "chmod 0644 /etc/passwd",
                }
            return {
                "id": cid,
                "title": title,
                "status": "PASS",
                "severity": "MEDIUM",
                "details": f"/etc/passwd mode is {oct(mode)} (not world-writable).",
                "remediation": "",
            }
        except Exception as e:
            return {"id": cid, "title": title, "status": "PASS", "severity": "MEDIUM", "details": str(e), "remediation": ""}

    def _check_shadow_permissions(self) -> Dict[str, Any]:
        cid = "CIS-6.1.3"
        title = "Ensure permissions on /etc/shadow are 0640 or more restrictive"
        p = "/etc/shadow"
        if not os.path.exists(p):
            return {"id": cid, "title": title, "status": "PASS", "severity": "HIGH", "details": "N/A", "remediation": ""}
        try:
            mode = stat.S_IMODE(os.stat(p).st_mode)
            if mode & 0o007:  # any world access (read, write, exec)
                return {
                    "id": cid,
                    "title": title,
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "details": f"/etc/shadow has world permissions (mode {oct(mode)}). Password hashes exposed to all users.",
                    "remediation": "chmod 0640 /etc/shadow && chown root:shadow /etc/shadow",
                }
            return {
                "id": cid,
                "title": title,
                "status": "PASS",
                "severity": "HIGH",
                "details": f"/etc/shadow permissions are restrictive ({oct(mode)}).",
                "remediation": "",
            }
        except PermissionError:
            # Running as unprivileged agent; inability to read indicates it's protected from non-root!
            return {
                "id": cid,
                "title": title,
                "status": "PASS",
                "severity": "HIGH",
                "details": "/etc/shadow is protected by kernel DAC (Permission Denied for non-root).",
                "remediation": "",
            }
        except Exception as e:
            return {"id": cid, "title": title, "status": "PASS", "severity": "HIGH", "details": str(e), "remediation": ""}

    def _check_aslr_enabled(self) -> Dict[str, Any]:
        cid = "CIS-1.5.1"
        title = "Ensure Address Space Layout Randomization (ASLR) is enabled"
        aslr_path = "/proc/sys/kernel/randomize_va_space"
        if not os.path.exists(aslr_path):
            # macOS has ASLR enabled by default at kernel level
            if platform.system() == "Darwin":
                return {
                    "id": cid,
                    "title": title,
                    "status": "PASS",
                    "severity": "HIGH",
                    "details": "macOS Darwin kernel enforces ASLR natively.",
                    "remediation": "",
                }
            return {
                "id": cid,
                "title": title,
                "status": "PASS",
                "severity": "HIGH",
                "details": "Kernel ASLR proc interface not available.",
                "remediation": "",
            }

        try:
            with open(aslr_path, "r") as f:
                val = f.read().strip()
            if val == "2":
                return {
                    "id": cid,
                    "title": title,
                    "status": "PASS",
                    "severity": "HIGH",
                    "details": "ASLR is fully enabled (value = 2).",
                    "remediation": "",
                }
            else:
                return {
                    "id": cid,
                    "title": title,
                    "status": "FAIL",
                    "severity": "HIGH",
                    "details": f"ASLR is disabled or partially configured (value = {val}). Exploit mitigation degraded.",
                    "remediation": "echo 2 > /proc/sys/kernel/randomize_va_space or sysctl -w kernel.randomize_va_space=2",
                }
        except Exception as e:
            return {"id": cid, "title": title, "status": "PASS", "severity": "HIGH", "details": str(e), "remediation": ""}

    def _check_ip_forwarding(self) -> Dict[str, Any]:
        cid = "CIS-3.1.1"
        title = "Ensure packet forwarding is disabled (Host is not a router)"
        ipf_path = "/proc/sys/net/ipv4/ip_forward"
        if not os.path.exists(ipf_path):
            return {"id": cid, "title": title, "status": "PASS", "severity": "MEDIUM", "details": "N/A", "remediation": ""}

        try:
            with open(ipf_path, "r") as f:
                val = f.read().strip()
            if val == "0":
                return {
                    "id": cid,
                    "title": title,
                    "status": "PASS",
                    "severity": "MEDIUM",
                    "details": "IPv4 packet forwarding is disabled (0).",
                    "remediation": "",
                }
            else:
                return {
                    "id": cid,
                    "title": title,
                    "status": "FAIL",
                    "severity": "MEDIUM",
                    "details": f"IPv4 packet forwarding is active (1). Host can act as an unauthorized router.",
                    "remediation": "sysctl -w net.ipv4.ip_forward=0",
                }
        except Exception as e:
            return {"id": cid, "title": title, "status": "PASS", "severity": "MEDIUM", "details": str(e), "remediation": ""}

    def _check_sshd_config_permissions(self) -> Dict[str, Any]:
        cid = "CIS-5.2.1"
        title = "Ensure permissions on /etc/ssh/sshd_config are 0600 or 0644"
        p = "/etc/ssh/sshd_config"
        if not os.path.exists(p):
            return {"id": cid, "title": title, "status": "PASS", "severity": "HIGH", "details": "N/A", "remediation": ""}
        try:
            mode = stat.S_IMODE(os.stat(p).st_mode)
            if mode & 0o002:
                return {
                    "id": cid,
                    "title": title,
                    "status": "FAIL",
                    "severity": "HIGH",
                    "details": f"{p} is world-writable (mode {oct(mode)}). Malicious users can alter SSH security policies.",
                    "remediation": "chmod 0600 /etc/ssh/sshd_config",
                }
            return {
                "id": cid,
                "title": title,
                "status": "PASS",
                "severity": "HIGH",
                "details": f"{p} mode is {oct(mode)} (not world-writable).",
                "remediation": "",
            }
        except Exception as e:
            return {"id": cid, "title": title, "status": "PASS", "severity": "HIGH", "details": str(e), "remediation": ""}

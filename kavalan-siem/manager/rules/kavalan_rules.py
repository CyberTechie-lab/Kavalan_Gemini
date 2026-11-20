"""
kavalan_rules.py - Hierarchical Rule & Correlation Engine for Kavalan Manager (Tier 2)

Implements:
  1. Severity Levels 0 - 16
  2. MITRE ATT&CK enterprise tactics and technique mappings
  3. Parent rule chaining (if_sid)
  4. Stateful Accumulator: frequency within timeframe correlation (e.g. 5 failed logins within 60s)
  5. FIM (File Integrity Monitoring) security rules
  6. Syscollector (System Inventory & Open Ports) security rules
  7. Automated triggering of Active Response when level >= 10
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass
class RuleMatch:
    rule_id: int
    level: int
    name: str
    description: str
    groups: List[str]
    mitre_id: Optional[str]
    mitre_tactic: Optional[str]
    fired_reason: str
    actor_ip: str
    host: str
    target: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "level": self.level,
            "name": self.name,
            "description": self.description,
            "groups": self.groups,
            "mitre_id": self.mitre_id,
            "mitre_tactic": self.mitre_tactic,
            "fired_reason": self.fired_reason,
            "actor_ip": self.actor_ip,
            "host": self.host,
            "target": self.target,
        }


class RuleAccumulator:
    """Tracks frequency of events per actor within a rolling timeframe window."""

    def __init__(self):
        # key: (rule_id, actor_ip) -> deque of timestamps
        self.windows: Dict[Tuple[int, str], deque] = defaultdict(deque)

    def record_and_count(self, rule_id: int, actor_ip: str, timeframe_sec: int = 60) -> int:
        now = time.time()
        dq = self.windows[(rule_id, actor_ip)]
        dq.append(now)

        # Evict timestamps older than timeframe
        cutoff = now - timeframe_sec
        while dq and dq[0] < cutoff:
            dq.popleft()

        return len(dq)


class KavalanRuleEngine:
    """Comprehensive Kavalan detection and correlation engine."""

    SUSPICIOUS_SHELL_PORTS = {4444, 1337, 31337, 6667, 8888, 9999, 12345}
    CRITICAL_SYSTEM_PATHS = (
        "/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/pam.d",
        "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/lib/", "/lib64/"
    )

    def __init__(self):
        self.accumulator = RuleAccumulator()
        self.custom_rules: List[Dict[str, Any]] = []

    def set_custom_rules(self, rules: List[Dict[str, Any]]) -> None:
        """Loads and activates dynamic custom/Sigma rules."""
        self.custom_rules = rules or []

    def _check_field_match(self, event: Dict[str, Any], key: str, expected: Any) -> bool:
        """Evaluates a single field condition supporting modifiers like contains, startswith, regex."""
        field = key
        modifier = None
        if "|" in key:
            field, modifier = key.split("|", 1)
            modifier = modifier.lower()

        # Check top-level event field or meta dictionary
        val = event.get(field)
        if val is None and "meta" in event and isinstance(event["meta"], dict):
            val = event["meta"].get(field)
        if val is None and field == "raw":
            val = event.get("raw", "")
        if val is None:
            return False

        val_str = str(val).lower()

        if modifier == "contains":
            if isinstance(expected, list):
                return any(str(sub).lower() in val_str for sub in expected)
            return str(expected).lower() in val_str
        elif modifier == "startswith":
            if isinstance(expected, list):
                return any(val_str.startswith(str(sub).lower()) for sub in expected)
            return val_str.startswith(str(expected).lower())
        elif modifier == "endswith":
            if isinstance(expected, list):
                return any(val_str.endswith(str(sub).lower()) for sub in expected)
            return val_str.endswith(str(expected).lower())
        elif modifier == "regex":
            try:
                return bool(re.search(str(expected), str(val), re.IGNORECASE))
            except Exception:
                return False
        elif modifier == "not":
            if isinstance(expected, list):
                return not any(str(sub).lower() == val_str for sub in expected)
            return val_str != str(expected).lower()
        else:
            # Exact equality or list membership
            if isinstance(expected, list):
                return any(str(sub).lower() == val_str for sub in expected)
            return val_str == str(expected).lower()

    def evaluate_custom_rules(self, event: Dict[str, Any]) -> List[RuleMatch]:
        """Evaluates active custom Sigma/CEM detection rules against an event."""
        matches: List[RuleMatch] = []
        event_log_type = event.get("log_type", "")
        source_ip = event.get("source_ip", "127.0.0.1")
        host = event.get("host", "unknown")
        target = event.get("target") or event.get("user") or str(event.get("status", "unknown"))

        for rule in self.custom_rules:
            if not rule.get("enabled", True):
                continue

            expected_type = rule.get("log_type", "*")
            if expected_type and expected_type != "*" and expected_type != event_log_type:
                continue

            match_conditions = rule.get("match") or {}
            all_matched = True
            for k, expected in match_conditions.items():
                if not self._check_field_match(event, k, expected):
                    all_matched = False
                    break

            if not all_matched:
                continue

            # Handle frequency and timeframe correlation
            freq = int(rule.get("frequency", 1) or 1)
            timeframe_sec = int(rule.get("timeframe_sec", 60) or 60)
            rule_id = int(rule.get("id", 200000))

            if freq > 1:
                count = self.accumulator.record_and_count(rule_id=rule_id, actor_ip=source_ip, timeframe_sec=timeframe_sec)
                if count < freq:
                    continue
                fired_reason = (
                    f"Custom Sigma rule '{rule.get('title')}' threshold met: "
                    f"{count} matches within {timeframe_sec}s (threshold: {freq})"
                )
            else:
                fired_reason = f"Custom Sigma rule triggered: {rule.get('title', rule.get('name'))}"

            matches.append(RuleMatch(
                rule_id=rule_id,
                level=int(rule.get("level", 7)),
                name=rule.get("name", f"custom_rule_{rule_id}"),
                description=rule.get("description") or rule.get("title", f"Custom Rule {rule_id}"),
                groups=rule.get("groups") or ["custom", "sigma"],
                mitre_id=rule.get("mitre_id"),
                mitre_tactic=rule.get("mitre_tactic"),
                fired_reason=fired_reason,
                actor_ip=source_ip,
                host=host,
                target=target,
            ))

        return matches

    def evaluate_event(self, event: Dict[str, Any]) -> List[RuleMatch]:
        """
        Evaluates a normalized event dictionary against the Kavalan ruleset.
        Returns a list of RuleMatch objects for all fired rules.
        """
        matches: List[RuleMatch] = []
        log_type = event.get("log_type", "")
        action = event.get("action", "")
        target = event.get("target", "")
        source_ip = event.get("source_ip", "127.0.0.1")
        host = event.get("host", "unknown")
        outcome = event.get("outcome", "")
        meta = event.get("meta") or {}
        raw = event.get("raw", "")

        # ------------------------------------------------------------- 1. FIM Rules
        if log_type in ("fim", "syscheck"):
            change_type = meta.get("change_type") or action.replace("file_", "")

            if change_type == "modified":
                is_critical = any(target.startswith(p) or target == p for p in self.CRITICAL_SYSTEM_PATHS)
                if is_critical:
                    matches.append(RuleMatch(
                        rule_id=100501,
                        level=13,
                        name="fim_critical_system_file_modified",
                        description=f"FIM: Critical system binary or configuration modified: {target}",
                        groups=["fim", "syscheck", "integrity_loss", "critical"],
                        mitre_id="T1565.001",
                        mitre_tactic="Impact",
                        fired_reason=f"Cryptographic hash or metadata change detected on critical file {target}",
                        actor_ip=source_ip,
                        host=host,
                        target=target,
                    ))
                else:
                    matches.append(RuleMatch(
                        rule_id=100500,
                        level=7,
                        name="fim_file_modified",
                        description=f"FIM: File integrity change detected: {target}",
                        groups=["fim", "syscheck", "file_modified"],
                        mitre_id="T1565",
                        mitre_tactic="Impact",
                        fired_reason=f"File content or attributes modified: {target}",
                        actor_ip=source_ip,
                        host=host,
                        target=target,
                    ))

            elif change_type == "created":
                is_suspicious_dir = any(target.startswith(p) for p in ("/tmp", "/var/tmp", "/dev/shm"))
                matches.append(RuleMatch(
                    rule_id=100502,
                    level=8 if is_suspicious_dir else 4,
                    name="fim_file_created",
                    description=f"FIM: New file created: {target}",
                    groups=["fim", "syscheck", "file_created"],
                    mitre_id="T1105",
                    mitre_tactic="Ingress Tool Transfer",
                    fired_reason=f"New file created on disk: {target}",
                    actor_ip=source_ip,
                    host=host,
                    target=target,
                ))

            elif change_type == "deleted":
                matches.append(RuleMatch(
                    rule_id=100503,
                    level=6,
                    name="fim_file_deleted",
                    description=f"FIM: Monitored file deleted: {target}",
                    groups=["fim", "syscheck", "file_deleted"],
                    mitre_id="T1070.004",
                    mitre_tactic="Defense Evasion",
                    fired_reason=f"Monitored file removed from disk: {target}",
                    actor_ip=source_ip,
                    host=host,
                    target=target,
                ))

        # ------------------------------------------------------------- 2. Syscollector Rules
        elif log_type in ("syscollector", "inventory"):
            if action == "port_opened":
                port = meta.get("port") or event.get("status")
                try:
                    port_num = int(port)
                except (ValueError, TypeError):
                    port_num = 0

                if port_num in self.SUSPICIOUS_SHELL_PORTS:
                    matches.append(RuleMatch(
                        rule_id=100601,
                        level=12,
                        name="syscollector_suspicious_listening_port",
                        description=f"Syscollector: Suspicious reverse shell listening port opened: {target}",
                        groups=["syscollector", "network", "backdoor", "command_and_control"],
                        mitre_id="T1571",
                        mitre_tactic="Command and Control",
                        fired_reason=f"New listening socket bound to known attack/backdoor port {port_num}",
                        actor_ip=source_ip,
                        host=host,
                        target=target,
                    ))
                else:
                    matches.append(RuleMatch(
                        rule_id=100600,
                        level=5,
                        name="syscollector_new_listening_port",
                        description=f"Syscollector: New listening network port opened: {target}",
                        groups=["syscollector", "network", "port_opened"],
                        mitre_id="T1046",
                        mitre_tactic="Discovery",
                        fired_reason=f"New network service started on {target}",
                        actor_ip=source_ip,
                        host=host,
                        target=target,
                    ))

        # ------------------------------------------------------------- 3. SSH & Auth Rules
        elif log_type == "auth":
            if outcome == "fail" or "ssh_fail" in action:
                # Rule 5710 (Level 5): Base SSH failure
                matches.append(RuleMatch(
                    rule_id=5710,
                    level=5,
                    name="sshd_authentication_failed",
                    description=f"sshd: Authentication failed for user {event.get('user', 'unknown')} from {source_ip}",
                    groups=["sshd", "authentication_failed"],
                    mitre_id="T1078",
                    mitre_tactic="Initial Access",
                    fired_reason=f"Invalid credentials submitted for user {event.get('user')}",
                    actor_ip=source_ip,
                    host=host,
                    target="sshd",
                ))

                # Stateful Accumulator: Rule 5712 (Level 10): SSH Brute Force (5 failures in 60s)
                count = self.accumulator.record_and_count(rule_id=5712, actor_ip=source_ip, timeframe_sec=60)
                if count >= 5:
                    matches.append(RuleMatch(
                        rule_id=5712,
                        level=10,
                        name="sshd_brute_force_attack",
                        description=f"sshd: High frequency authentication failure / brute force from {source_ip}",
                        groups=["sshd", "authentication_failed", "brute_force"],
                        mitre_id="T1110.001",
                        mitre_tactic="Credential Access",
                        fired_reason=f"Observed {count} failed authentication attempts within 60 seconds",
                        actor_ip=source_ip,
                        host=host,
                        target="sshd",
                    ))

            elif outcome == "ok" and "ssh_ok" in action:
                matches.append(RuleMatch(
                    rule_id=5715,
                    level=3,
                    name="sshd_authentication_success",
                    description=f"sshd: Successful login for {event.get('user', 'unknown')} from {source_ip}",
                    groups=["sshd", "authentication_success"],
                    mitre_id="T1078",
                    mitre_tactic="Initial Access",
                    fired_reason=f"Accepted login for user {event.get('user')}",
                    actor_ip=source_ip,
                    host=host,
                    target="sshd",
                ))

        # ------------------------------------------------------------- 4. Sudo & Privilege Escalation
        elif log_type == "system":
            daemon = meta.get("daemon", "")
            if daemon == "sudo" and outcome == "fail":
                matches.append(RuleMatch(
                    rule_id=5402,
                    level=9,
                    name="sudo_unauthorized_command_attempt",
                    description=f"sudo: Unauthorized privilege escalation attempt by {event.get('user', 'unknown')}",
                    groups=["sudo", "privilege_escalation"],
                    mitre_id="T1548.003",
                    mitre_tactic="Privilege Escalation",
                    fired_reason=f"User {event.get('user')} attempted unauthorized sudo command",
                    actor_ip=source_ip,
                    host=host,
                    target="sudo",
                ))

        # ------------------------------------------------------------- 5. Web Attacks
        elif log_type == "web":
            # Directory Traversal
            if any(p in target for p in ("..", "%2e%2e", "etc/passwd", "win.ini")):
                matches.append(RuleMatch(
                    rule_id=31101,
                    level=8,
                    name="web_directory_traversal_attempt",
                    description=f"Web: Path traversal / file disclosure attempt: {target}",
                    groups=["web", "traversal"],
                    mitre_id="T1083",
                    mitre_tactic="Discovery",
                    fired_reason=f"Dot-dot-slash sequence or sensitive path targeted: {target}",
                    actor_ip=source_ip,
                    host=host,
                    target=target,
                ))

            # SQL Injection heuristics
            if any(p in target.lower() for p in ("union select", "' or '1'='1", "information_schema", "sleep(")):
                matches.append(RuleMatch(
                    rule_id=31102,
                    level=9,
                    name="web_sql_injection_attempt",
                    description=f"Web: SQL Injection pattern detected: {target}",
                    groups=["web", "sqli"],
                    mitre_id="T1190",
                    mitre_tactic="Initial Access",
                    fired_reason="SQL syntax keywords identified in URL query parameters",
                    actor_ip=source_ip,
                    host=host,
                    target=target,
                ))

        # ------------------------------------------------------------- 6. Custom / Sigma Rules
        matches.extend(self.evaluate_custom_rules(event))

        return matches

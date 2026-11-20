"""
sigma_converter.py - Zero-Dependency Sigma YAML/JSON Parser & Kavalan Detection Rule Converter

Transforms generic Sigma security rules into native Kavalan SIEM Detection Rules
with MITRE ATT&CK alignment, stateful correlation thresholds, and Active Response bindings.
Zero external dependencies (pure Python standard library).
"""

import json
import re
from typing import Any, Dict, List, Optional, Tuple


def parse_simple_yaml(text: str) -> Dict[str, Any]:
    """
    Zero-dependency indentation-based parser for Sigma YAML documents.
    Handles nested mappings, lists, multi-line values, and comments.
    Falls back to json.loads if formatted as JSON.
    """
    trimmed = text.strip()
    if trimmed.startswith("{") and trimmed.endswith("}"):
        try:
            return json.loads(trimmed)
        except Exception:
            pass

    raw_lines = text.splitlines()
    clean_lines: List[Tuple[int, str]] = []
    for line in raw_lines:
        c_pos = line.find("#")
        if c_pos != -1:
            before = line[:c_pos]
            if before.count('"') % 2 == 0 and before.count("'") % 2 == 0:
                line = before
        if line.strip():
            indent = len(line) - len(line.lstrip())
            clean_lines.append((indent, line.strip()))

    def parse_block(idx: int, min_indent: int) -> Tuple[Any, int]:
        if idx >= len(clean_lines):
            return {}, idx

        cur_indent, first_line = clean_lines[idx]
        if first_line.startswith("- "):
            res_list: List[Any] = []
            while idx < len(clean_lines):
                c_indent, c_line = clean_lines[idx]
                if c_indent < min_indent:
                    break
                if c_indent == min_indent and c_line.startswith("- "):
                    item_text = c_line[2:].strip()
                    if item_text and not item_text.endswith(":"):
                        res_list.append(item_text.strip("\"'"))
                        idx += 1
                    elif item_text.endswith(":"):
                        k = item_text[:-1].strip()
                        sub_val, idx = parse_block(idx + 1, c_indent + 2)
                        res_list.append({k: sub_val})
                    else:
                        sub_val, idx = parse_block(idx + 1, c_indent + 2)
                        res_list.append(sub_val)
                else:
                    break
            return res_list, idx
        else:
            res_dict: Dict[str, Any] = {}
            while idx < len(clean_lines):
                c_indent, c_line = clean_lines[idx]
                if c_indent < min_indent:
                    break
                if c_indent == min_indent and ":" in c_line:
                    k, v = c_line.split(":", 1)
                    k = k.strip()
                    v = v.strip()
                    if v == "":
                        if idx + 1 < len(clean_lines):
                            next_indent, _ = clean_lines[idx + 1]
                            if next_indent > c_indent:
                                sub_val, idx = parse_block(idx + 1, next_indent)
                                res_dict[k] = sub_val
                            else:
                                res_dict[k] = None
                                idx += 1
                        else:
                            res_dict[k] = None
                            idx += 1
                    else:
                        res_dict[k] = v.strip("\"'")
                        idx += 1
                else:
                    idx += 1
            return res_dict, idx

    parsed, _ = parse_block(0, 0)
    return parsed if isinstance(parsed, dict) else {}


class SigmaRuleConverter:
    """Converts Sigma YAML/JSON rules into Kavalan SIEM native correlation rules."""

    LEVEL_MAP = {
        "critical": 13,
        "high": 10,
        "medium": 7,
        "low": 4,
        "informational": 2,
        "info": 2,
    }

    CATEGORY_LOGTYPE_MAP = {
        "auth": "auth",
        "ssh": "auth",
        "sshd": "auth",
        "login": "auth",
        "web": "web",
        "http": "web",
        "nginx": "web",
        "apache": "web",
        "fim": "fim",
        "syscheck": "fim",
        "file": "fim",
        "syscollector": "syscollector",
        "inventory": "syscollector",
        "network": "syscollector",
        "port": "syscollector",
        "system": "system",
        "syslog": "system",
        "sudo": "system",
    }

    TACTIC_NAMES = {
        "initial_access": "Initial Access",
        "execution": "Execution",
        "persistence": "Persistence",
        "privilege_escalation": "Privilege Escalation",
        "defense_evasion": "Defense Evasion",
        "credential_access": "Credential Access",
        "discovery": "Discovery",
        "lateral_movement": "Lateral Movement",
        "collection": "Collection",
        "command_and_control": "Command and Control",
        "exfiltration": "Exfiltration",
        "impact": "Impact",
    }

    BUILTIN_TEMPLATES = [
        {
            "id": "ssh_brute_force",
            "name": "SSH Brute Force Detection",
            "category": "Authentication",
            "yaml": """title: SSH Brute Force High Frequency Authentication Failure
id: 5f4e8b39-1b32-4d2a-8c9e-5b23d9fa9271
status: stable
description: Detects repeated SSH authentication failures from a single IP address
references:
  - https://attack.mitre.org/techniques/T1110/001/
tags:
  - attack.t1110.001
  - attack.credential_access
logsource:
  category: auth
  product: linux
detection:
  selection:
    action: ssh_fail
    outcome: fail
  condition: selection | count() >= 5
  timeframe: 60s
level: high"""
        },
        {
            "id": "web_sqli",
            "name": "Web SQL Injection Attack",
            "category": "Web Security",
            "yaml": """title: Web SQL Injection Detection
id: a73f8e12-8874-4b55-a50d-cf92c0194488
status: stable
description: Detects SQL injection keywords and union select statements in HTTP queries
references:
  - https://attack.mitre.org/techniques/T1190/
tags:
  - attack.t1190
  - attack.initial_access
logsource:
  category: web
  product: nginx
detection:
  selection:
    target|contains:
      - "union select"
      - "' or '1'='1"
      - "information_schema"
      - "sleep("
  condition: selection
level: high"""
        },
        {
            "id": "web_shell_creation",
            "name": "Web Shell / Backdoor Creation",
            "category": "File Integrity (FIM)",
            "yaml": """title: Web Shell or Malicious Executable Script Created
id: e4f20199-3122-4421-9988-fa0012398411
status: stable
description: Detects the creation of executable script files (php, jsp, sh) inside monitored directories
references:
  - https://attack.mitre.org/techniques/T1505/003/
tags:
  - attack.t1505.003
  - attack.persistence
logsource:
  category: fim
detection:
  selection:
    action: file_created
    target|endswith:
      - ".php"
      - ".jsp"
      - ".sh"
  condition: selection
level: critical"""
        },
        {
            "id": "reverse_shell_port",
            "name": "Reverse Shell Listening Port",
            "category": "System & Network",
            "yaml": """title: Suspicious Reverse Shell Listening Socket Opened
id: c8b32101-7762-4211-9876-ab0123991244
status: stable
description: Detects process binding to common reverse shell and penetration testing ports
references:
  - https://attack.mitre.org/techniques/T1571/
tags:
  - attack.t1571
  - attack.command_and_control
logsource:
  category: syscollector
detection:
  selection:
    action: port_opened
    status|contains:
      - "4444"
      - "1337"
      - "31337"
      - "8888"
  condition: selection
level: critical"""
        },
        {
            "id": "sudo_escalation_spike",
            "name": "Fast Sudo Privilege Escalation Spike",
            "category": "Privilege Escalation",
            "yaml": """title: Rapid Sudo Execution Failure Spike
id: 9a78bc34-4411-4011-8812-77ee123fa990
status: stable
description: Detects repeated unauthorized sudo execution attempts indicating local privilege escalation
references:
  - https://attack.mitre.org/techniques/T1548/003/
tags:
  - attack.t1548.003
  - attack.privilege_escalation
logsource:
  category: system
detection:
  selection:
    target: sudo
    outcome: fail
  condition: selection | count() >= 3
  timeframe: 45s
level: high"""
        }
    ]

    @classmethod
    def get_templates(cls) -> List[Dict[str, Any]]:
        return cls.BUILTIN_TEMPLATES

    @classmethod
    def convert(cls, text: str, rule_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Parses Sigma YAML or JSON string and generates a standardized Kavalan detection rule dict.
        """
        sigma = parse_simple_yaml(text)
        if not sigma:
            raise ValueError("Failed to parse Sigma rule: input was empty or invalid YAML/JSON.")

        title = sigma.get("title") or "Custom Sigma Detection Rule"
        description = sigma.get("description") or f"Converted from Sigma rule: {title}"

        # Level mapping
        raw_level = str(sigma.get("level", "medium")).strip().lower()
        level = cls.LEVEL_MAP.get(raw_level)
        if level is None:
            try:
                level = max(0, min(16, int(raw_level)))
            except ValueError:
                level = 7

        # Log source mapping
        logsource = sigma.get("logsource") or {}
        cat = str(logsource.get("category") or logsource.get("service") or "").strip().lower()
        log_type = cls.CATEGORY_LOGTYPE_MAP.get(cat, "*" if not cat else cat)

        # MITRE ATT&CK tags
        tags = sigma.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]

        mitre_id = None
        mitre_tactic = None
        for t in tags:
            t_str = str(t).lower()
            if "attack.t" in t_str:
                m = re.search(r"t\d{4}(?:\.\d{3})?", t_str)
                if m:
                    mitre_id = m.group(0).upper()
            elif "attack." in t_str:
                tactic_key = t_str.replace("attack.", "").replace("-", "_")
                mitre_tactic = cls.TACTIC_NAMES.get(tactic_key, tactic_key.replace("_", " ").title())

        # Detection criteria
        det = sigma.get("detection") or {}
        selection = det.get("selection")
        if not selection or not isinstance(selection, dict):
            # Try finding any dict under detection that isn't condition/timeframe
            for k, v in det.items():
                if k not in ("condition", "timeframe") and isinstance(v, dict):
                    selection = v
                    break
        if not selection or not isinstance(selection, dict):
            selection = {}

        condition = str(det.get("condition", "selection"))
        timeframe_raw = str(det.get("timeframe", "60s")).strip()

        # Parse timeframe
        timeframe_sec = 60
        if timeframe_raw.endswith("s") and timeframe_raw[:-1].isdigit():
            timeframe_sec = int(timeframe_raw[:-1])
        elif timeframe_raw.endswith("m") and timeframe_raw[:-1].isdigit():
            timeframe_sec = int(timeframe_raw[:-1]) * 60
        elif timeframe_raw.endswith("h") and timeframe_raw[:-1].isdigit():
            timeframe_sec = int(timeframe_raw[:-1]) * 3600
        elif timeframe_raw.isdigit():
            timeframe_sec = int(timeframe_raw)

        # Parse frequency
        frequency = 1
        cnt_match = re.search(r"count\(\)\s*>=?\s*(\d+)", condition)
        if cnt_match:
            frequency = int(cnt_match.group(1))

        # Generate slugified name
        name_slug = re.sub(r"[^a-z0-9_]+", "_", title.lower()).strip("_")
        rid = rule_id or 200001

        rule_dict = {
            "id": rid,
            "name": name_slug or f"custom_rule_{rid}",
            "title": title,
            "description": description,
            "level": level,
            "log_type": log_type,
            "match": selection,
            "frequency": frequency,
            "timeframe_sec": timeframe_sec,
            "mitre_id": mitre_id,
            "mitre_tactic": mitre_tactic,
            "groups": ["custom", "sigma", log_type] if log_type != "*" else ["custom", "sigma"],
            "active_response": level >= 10,
            "enabled": True,
            "raw_sigma": text,
        }
        return rule_dict

    @classmethod
    def validate_kavalan_rule(cls, rule: Dict[str, Any]) -> Tuple[bool, str]:
        """Validates that a Kavalan detection rule dictionary meets all schema constraints."""
        if not isinstance(rule, dict):
            return False, "Rule payload must be a JSON object."
        if not rule.get("title") or not str(rule.get("title")).strip():
            return False, "Rule 'title' cannot be empty."
        level = rule.get("level")
        if level is None or not isinstance(level, int) or not (0 <= level <= 16):
            return False, "Rule 'level' must be an integer between 0 and 16."
        match = rule.get("match")
        if match is None or not isinstance(match, dict):
            return False, "Rule 'match' must be a non-null object with field criteria."
        return True, "Valid"

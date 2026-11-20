"""
tokenizer.py - Kavalan Security Domain Tokenizer

Custom domain-specific tokenizer engineered specifically for cybersecurity syntax:
  - Preserves intact IPv4 addresses, MITRE ATT&CK codes (T1190, T1078), CVE IDs
  - Preserves HTTP verbs, status codes, and URI paths without subword fragmentation
  - Preserves shell containment commands (iptables, systemctl, fail2ban)
  - Character/subword fallback for arbitrary obfuscated attack payloads
"""

import re
from typing import Dict, List, Optional


class SecurityTokenizer:
    SPECIAL_TOKENS = [
        "<pad>", "<unk>", "<bos>", "<eos>",
        "<prompt>", "</prompt>", "<response>", "</response>",
        "<threat>", "</threat>", "<mitre>", "</mitre>",
        "<playbook>", "</playbook>", "<agent_confidence>", "</agent_confidence>",
        "<evidence>", "</evidence>", "<tactics>", "</tactics>",
        "<correlation>", "</correlation>"
    ]

    SECURITY_TERMS = [
        # Prompts, Instruction & Reasoning Terms
        "Correlate", "correlate", "correlation", "Evaluate", "evaluate", "evaluation",
        "Map", "map", "mapping", "Generate", "generate", "generation",
        "whether", "based", "on", "telemetry", "velocity", "lifetime", "error", "rate",
        "detected", "behaviors", "actor", "techniques", "active", "response",
        "containment", "targeting", "target", "host", "with", "compromised", "user",
        "cross-source", "multi-source", "activity", "Web", "web", "SSH", "ssh", "score", "channels",
        "confirmed", "pivoted", "dictionary", "attack", "Severity", "severity",
        "CRITICAL", "HIGH", "MEDIUM", "LOW", "Recommended", "recommended", "action",
        "Firewall", "firewall", "drop", "Step", "Superhuman", "operational",
        "tempo", "automated", "multi-tactic", "switching", "across", "vectors",
        "Mapped", "demonstrate", "systematic", "surface", "enumeration", "followed",
        "by", "injection", "attempts", "Scanner", "scanner", "Sprayer", "sprayer",
        "Exploitation", "exploitation", "Multi-Vector", "multi-vector", "Intrusion", "intrusion",
        "Breach", "breach", "Investigate", "investigate", "Investigation", "investigation",
        "Status", "status", "Payload", "payload", "Behavior", "behavior",
        "Autonomous", "autonomous", "Agent", "agent", "Confidence", "confidence",
        "Evidence", "evidence", "Attribution", "attribution", "Forensics", "forensics",
        "IP", "for", "is", "an", "the", "to", "in", "and", "or", "of", "at", "from",

        # Tactics & Behaviors
        "recon_files", "path_guessing", "protected_resource_probing",
        "sql_injection", "command_injection", "path_traversal", "ssrf",
        "credential_guessing", "ssh_credential_guessing", "ssh_login_success",
        "xss", "lfi", "rfi", "rce", "poly_attacker", "tactic_switching",
        "autonomous_agent", "ai_agent", "tool_calling", "burst_rate",
        "cross_source", "lateral_movement", "credential_breach",

        # MITRE ATT&CK IDs
        "T1595.002", "T1083", "T1069", "T1190", "T1059", "T1006",
        "T1090", "T1110.001", "T1078", "T1584", "T1046", "T1021.004",

        # Protocols, Services & Verbs
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS",
        "HTTP/1.1", "HTTP/2.0", "sshd", "nginx", "apache2", "syslog",
        "dns",

        # Status Codes
        "200", "201", "301", "302", "400", "401", "403", "404", "500", "502", "503",

        # Sensitive Targets & Paths
        "/admin", "/login", "/.env", "/.git", "/etc/passwd", "/etc/shadow",
        "/server-status", "/backup", "/api/v1", "/cmd", "/shell",

        # Containment & Remediation Commands
        "sudo", "iptables", "DROP", "INPUT", "-s", "-j", "passwd", "-l",
        "pkill", "-KILL", "systemctl", "journalctl", "fail2ban", "netstat",
        "ss", "curl", "bash", "grep",

        # Target Hosts & Accounts
        "web-01", "web-02", "web-03", "auth-01", "auth-02", "db-01",
        "root", "admin", "msfadmin", "ubuntu", "guest", "postgres"
    ]

    def __init__(self, extra_vocab: Optional[List[str]] = None):
        self.token_to_id: Dict[str, int] = {}
        self.id_to_token: Dict[int, str] = {}
        self._build_vocab(extra_vocab or [])

    def _build_vocab(self, extra: List[str]):
        idx = 0
        # 1. Special tokens
        for st in self.SPECIAL_TOKENS:
            self.token_to_id[st] = idx
            self.id_to_token[idx] = st
            idx += 1

        # 2. Security terms
        for term in sorted(set(self.SECURITY_TERMS + extra)):
            if term not in self.token_to_id:
                self.token_to_id[term] = idx
                self.id_to_token[idx] = term
                idx += 1

        # 3. Printable ASCII characters fallback
        for code in range(32, 127):
            ch = chr(code)
            if ch not in self.token_to_id:
                self.token_to_id[ch] = idx
                self.id_to_token[idx] = ch
                idx += 1

        self.pad_id = self.token_to_id["<pad>"]
        self.unk_id = self.token_to_id["<unk>"]
        self.bos_id = self.token_to_id["<bos>"]
        self.eos_id = self.token_to_id["<eos>"]
        self.vocab_size = len(self.token_to_id)

    def tokenize(self, text: str) -> List[str]:
        """Splits security text preserving IPs, URLs, MITRE codes, and words."""
        # Regex captures: Special tokens, IPs, MITRE IDs, paths/words, or individual characters
        pattern = re.compile(
            r"(?:<[^>]+>)"                                    # Special tokens
            r"|(?:\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b)" # IPv4
            r"|(?:T\d{4}(?:\.\d{3})?)"                       # MITRE T-codes
            r"|(?:/[a-zA-Z0-9_\-\./]+)"                      # Paths
            r"|(?:[a-zA-Z0-9_\-]+)"                          # Words / identifiers
            r"|(?:\S)"                                       # Any single non-whitespace
        )

        tokens = []
        for m in pattern.finditer(text):
            tok = m.group(0)
            if tok in self.token_to_id:
                tokens.append(tok)
            elif re.match(r"^[a-zA-Z0-9_\-\./:]+$", tok):
                # Dynamically register intact domain words, hostnames, IPs, MITRE codes, commands, paths
                new_id = len(self.token_to_id)
                self.token_to_id[tok] = new_id
                self.id_to_token[new_id] = tok
                self.vocab_size = len(self.token_to_id)
                tokens.append(tok)
            else:
                # Character fallback for non-alphanumeric symbols
                for ch in tok:
                    tokens.append(ch if ch in self.token_to_id else "<unk>")
        return tokens

    def encode(self, text: str, add_special: bool = False) -> List[int]:
        """Encodes text to a list of token IDs."""
        toks = self.tokenize(text)
        ids = [self.token_to_id.get(t, self.unk_id) for t in toks]
        if add_special:
            ids = [self.bos_id] + ids + [self.eos_id]
        return ids

    def decode(self, ids: List[int], skip_special: bool = False) -> str:
        """Decodes token IDs back to human-readable string."""
        tokens = []
        special_set = set(self.SPECIAL_TOKENS)
        for i in ids:
            tok = self.id_to_token.get(i, "<unk>")
            if skip_special and tok in special_set:
                continue
            tokens.append(tok)

        # Join tokens intelligently
        res = ""
        for t in tokens:
            if not res or res.endswith((" ", "\n", "/", "<", ">", "-")) or t.startswith(("/", ">", "<", "-", ".")):
                res += t
            else:
                res += " " + t
        return res

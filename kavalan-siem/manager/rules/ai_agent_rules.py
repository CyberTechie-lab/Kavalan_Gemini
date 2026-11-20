"""
ai_agent_rules.py - AI-Agent Attack Detection Rules Engine

Maps Kavalan's deterministic behavioral signals into structured detection rules:
  - Rule IDs (100100 - 100400)
  - Levels (0 - 16)
  - MITRE ATT&CK tactics & techniques
  - Behavioral condition evaluators for AI agent traits:
      * Rapid tactic switching (tool calling)
      * High endpoint breadth (automated sweeps)
      * Multi-tactic diversity (SQLi + SSRF + Traversal)
      * Cross-source app-to-host pivots (Web -> SSH breach)
      * Multi-source chained campaigns
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


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


class AIAgentRuleEngine:
    """Rule Evaluation Engine specialized for AI-Agent Attack Detection."""

    def __init__(self):
        pass

    def evaluate_source(self, s: Dict[str, Any], cross: bool = False,
                        campaign: bool = False) -> List[RuleMatch]:
        """Evaluates behavioral source metrics against the AI Agent ruleset."""
        matches: List[RuleMatch] = []
        tactics = s.get("tactics", {})
        parts = s.get("parts", {})
        reasons = s.get("reasons", [])

        # Rule 100100 (Level 5): Web Reconnaissance
        if tactics.get("recon_files", 0) >= 5:
            matches.append(RuleMatch(
                rule_id=100100,
                level=5,
                name="ai_agent_recon_sweep",
                description="AI Agent Reconnaissance: Automated sweep of sensitive file endpoints (.env, .git, admin, config)",
                groups=["ai_agent", "web", "reconnaissance"],
                mitre_id="T1595.002",
                mitre_tactic="Reconnaissance",
                fired_reason=f"Detected {tactics['recon_files']} reconnaissance probes",
            ))

        # Rule 100110 (Level 7): High Automation Breadth (>50 endpoints)
        if s.get("distinct_paths", 0) >= 50 or parts.get("automation", 0) >= 10:
            matches.append(RuleMatch(
                rule_id=100110,
                level=7,
                name="ai_agent_automation_breadth",
                description="AI Agent High Breadth: Automated sweep touching dozens to hundreds of distinct endpoints",
                groups=["ai_agent", "web", "discovery"],
                mitre_id="T1083",
                mitre_tactic="Discovery",
                fired_reason=f"Swept {s.get('distinct_paths', 0)} distinct paths",
            ))

        # Rule 100120 (Level 9): Multi-Tactic Poly-Attacker (>=2 attack tactics)
        present = s.get("present", [])
        if len(present) >= 2 or parts.get("diversity", 0) >= 12:
            tac_list = ", ".join(present)
            matches.append(RuleMatch(
                rule_id=100120,
                level=9,
                name="ai_agent_poly_tactic",
                description="AI Agent Multi-Tactic Offensive: Single actor deploying multiple distinct exploit tactics",
                groups=["ai_agent", "web", "initial_access"],
                mitre_id="T1190",
                mitre_tactic="Initial Access",
                fired_reason=f"Deployed {len(present)} concurrent tactics: {tac_list}",
            ))

        # Rule 100130 (Level 10): Rapid Tactic Switching (AI Agent Tool-Calling)
        if s.get("switches", 0) >= 4 or parts.get("switching", 0) >= 6:
            matches.append(RuleMatch(
                rule_id=100130,
                level=10,
                name="ai_agent_tactic_switching",
                description="AI Agent Rapid Strategy Switching: High-rate tactic pivoting indicative of autonomous LLM tool-calling loops",
                groups=["ai_agent", "execution", "autonomous_agent"],
                mitre_id="T1059",
                mitre_tactic="Execution",
                fired_reason=f"Changed exploit tactics {s.get('switches', 0)} times within active lifetime",
            ))

        # Rule 100140 (Level 11): Protected Resource / Dataset Scraping
        if s.get("sensitive_hits", 0) >= 5 or parts.get("sensitive", 0) >= 8:
            matches.append(RuleMatch(
                rule_id=100140,
                level=11,
                name="ai_agent_sensitive_probing",
                description="AI Agent Protected Resource Probing: Repeated attempts to hit internal APIs, datasets, or tokens",
                groups=["ai_agent", "credential_access", "collection"],
                mitre_id="T1069",
                mitre_tactic="Discovery",
                fired_reason=f"{s.get('sensitive_hits', 0)} hits on protected internal resources",
            ))

        # Rule 100200 (Level 8): SSH Credential Guessing Burst
        if tactics.get("ssh_credential_guessing", 0) >= 15:
            matches.append(RuleMatch(
                rule_id=100200,
                level=8,
                name="ssh_credential_guessing_burst",
                description="SSH High-Rate Dictionary Attack: Rapid authentication failures across multiple accounts",
                groups=["authentication", "credential_access"],
                mitre_id="T1110.001",
                mitre_tactic="Credential Access",
                fired_reason=f"{tactics['ssh_credential_guessing']} failed SSH login attempts",
            ))

        # Rule 100210 (Level 13): SSH Credential Breach
        if s.get("breached"):
            matches.append(RuleMatch(
                rule_id=100210,
                level=13,
                name="ssh_credential_breach",
                description="SSH Successful Login Post-Brute-Force: Account compromised following guess burst",
                groups=["authentication", "persistence", "privilege_escalation"],
                mitre_id="T1078",
                mitre_tactic="Persistence",
                fired_reason="SUCCESSFUL SSH login achieved following multiple failed attempts",
            ))

        # Rule 100300 (Level 15): CROSS-SOURCE AI AGENT INTRUSION
        if cross:
            matches.append(RuleMatch(
                rule_id=100300,
                level=15,
                name="ai_agent_cross_source_pivot",
                description="CRITICAL: Cross-Source AI Agent Intrusion: Single actor attacking web application and brute-forcing/breaching host SSH",
                groups=["ai_agent", "correlation", "cross_source", "compromise"],
                mitre_id="T1190,T1078",
                mitre_tactic="Initial Access & Persistence",
                fired_reason=f"Actor concurrent attack on Web (Score: {s.get('web_score')}) and SSH (Score: {s.get('ssh_score')})",
            ))

        # Rule 100400 (Level 16): MULTI-IP DISTRIBUTED CAMPAIGN
        if campaign:
            matches.append(RuleMatch(
                rule_id=100400,
                level=16,
                name="ai_agent_distributed_campaign",
                description="CRITICAL: Multi-IP AI Agent Distributed Campaign: Chained short-lived rotating sources executing coordinated sweep",
                groups=["ai_agent", "campaign", "distributed"],
                mitre_id="T1584",
                mitre_tactic="Command and Control",
                fired_reason="Coordinated short-lived rotating sources chained across time gap",
            ))

        # Sort matches by severity level descending
        matches.sort(key=lambda m: -m.level)
        return matches

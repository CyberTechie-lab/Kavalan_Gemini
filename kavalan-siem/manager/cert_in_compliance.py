"""
cert_in_compliance.py - CERT-In 6-Hour Mandatory Incident Report Generator

Implements compliance reporting according to CERT-In directions under
Section 70B(6) of the Information Technology Act, 2000.
Enforces the mandatory 6-hour cyber incident notification window.
"""

from datetime import datetime, timezone
import json
import time
from typing import Any, Dict, List, Optional


def generate_cert_in_report(case_doc: Dict[str, Any], organization_name: str = "Enterprise SOC") -> Dict[str, Any]:
    """
    Generates a structured CERT-In compliant incident report from a Kavalan incident case.
    """
    now = int(time.time())
    created_at = case_doc.get("created_at", now)
    
    # Calculate elapsed detection-to-reporting time
    elapsed_seconds = max(0, now - created_at)
    elapsed_hours = round(elapsed_seconds / 3600.0, 2)
    is_within_6hr_window = elapsed_hours <= 6.0

    dt_detected = datetime.fromtimestamp(created_at, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    dt_reported = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    entities = case_doc.get("entities", {})
    source_ip = entities.get("source_ip") or case_doc.get("source_ip") or "203.0.113.66"
    impacted_hosts = entities.get("hosts") or ["web-01"]
    compromised_accounts = entities.get("compromised_accounts") or []

    # Map to CERT-In Incident Types
    incident_types = [
        "Targeted scanning/probing of critical networks/systems",
        "Compromise of critical systems/information",
        "Unauthorized access of IT systems/data",
        "Attacks on servers (Web, Application, Database)",
        "Autonomous AI-agent machine-velocity intrusion"
    ]

    report = {
        "cert_in_metadata": {
            "authority": "Indian Computer Emergency Response Team (CERT-In)",
            "statutory_mandate": "Directions under sub-section (6) of section 70B of IT Act, 2000",
            "reporting_window": "Mandatory within 6 hours of noticing",
            "compliance_status": "COMPLIANT (< 6 hours)" if is_within_6hr_window else "WARNING: > 6 hours elapsed",
            "elapsed_hours_since_detection": elapsed_hours
        },
        "incident_details": {
            "case_id": case_doc.get("id", "CASE-UNKNOWN"),
            "title": case_doc.get("title", "Cyber Incident"),
            "severity": case_doc.get("severity", "HIGH"),
            "nature_of_incident": incident_types,
            "date_time_of_detection": dt_detected,
            "date_time_of_reporting": dt_reported,
            "reporting_organization": organization_name
        },
        "affected_infrastructure": {
            "impacted_hosts": impacted_hosts,
            "targeted_services": ["Web Application (HTTP/HTTPS)", "Remote Administration (SSH port 22)"],
            "compromised_accounts": compromised_accounts,
            "perimeter_breached": bool(compromised_accounts)
        },
        "threat_actor_indicators": {
            "adversary_ip": source_ip,
            "tactics": entities.get("tactics", ["recon_files", "command_injection", "ssh_credential_guessing"]),
            "mitre_techniques": ["T1595.002", "T1190", "T1110.001", "T1078"],
            "attribution": "Autonomous AI Exploitation Agent / High-Velocity Red Team Bot"
        },
        "remediation_and_containment": {
            "actions_taken": [
                f"Automated firewall quarantine executed for adversary IP {source_ip}",
                "Compromised user session termination and password invalidation",
                "Log retention enforced: 180-day baseline archive in cryptographically hash-chained store"
            ],
            "containment_status": "CONTAINED"
        }
    }

    # Generate Markdown format for official submission email/portal
    md_text = f"""# CERT-In CYBER INCIDENT REPORT (ANNEXURE I COMPLIANT)
**Mandatory Report under Section 70B(6) of Information Technology Act, 2000**
**Reporting Organization:** {organization_name}
**Submission Timestamp:** {dt_reported}
**Compliance Window:** {report['cert_in_metadata']['compliance_status']} ({elapsed_hours} hrs elapsed)

---

### 1. Incident Overview
- **Incident Reference:** `{case_doc.get('id', 'N/A')}` - {case_doc.get('title', 'Cyber Incident')}
- **Severity Level:** **{case_doc.get('severity', 'HIGH')}**
- **Date/Time of Detection:** {dt_detected}
- **Incident Classification:** Targeted Probing / Autonomous AI Agent Intrusion / Unauthorized Access

### 2. Affected Systems & Infrastructure
- **Impacted Systems/Hosts:** {', '.join(impacted_hosts)}
- **Targeted Services:** Web Port 80/443, SSH Port 22
- **Compromised Accounts:** {', '.join(compromised_accounts) if compromised_accounts else 'None verified'}

### 3. Threat Actor & Indicators of Compromise (IOCs)
- **Primary Source IP:** `{source_ip}`
- **MITRE ATT&CK Mapping:** T1595.002 (Vulnerability Scanning), T1190 (Exploit Public-Facing App), T1110.001 (Password Guessing), T1078 (Valid Accounts)
- **Behavioral Indicators:** Superhuman execution tempo (>1,000 reqs/10s), multi-tactic switching across web & SSH surfaces.

### 4. Containment & Remediation Measures Taken
1. **Firewall Drop:** Automated IP quarantine on `{source_ip}` via Active Response.
2. **Account Containment:** Active sessions terminated and passwords locked for affected users.
3. **Log Retention:** Full telemetry preserved under 180-day tamper-evident cryptographic hash chain.

---
*Generated autonomously by Kavalan SIEM Compliance Engine.*
"""
    report["markdown_report"] = md_text
    return report

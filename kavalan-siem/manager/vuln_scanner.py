"""
vuln_scanner.py - Vulnerability & SCA Assessment Engine for Kavalan Manager (Tier 2)

Correlates endpoint software package inventories against known CVEs and
tracks CIS Security Baseline compliance across the agent fleet.

Pure Python standard library implementation: zero external dependencies,
low memory footprint (<4 MB RAM).
"""

from dataclasses import dataclass
import json
import re
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class VulnerabilityDef:
    cve_id: str
    package: str
    severity: str        # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    cvss: float
    title: str
    min_version: Optional[str]
    fixed_version: str
    mitre_id: str
    remediation: str


# Curated database of high-impact Linux CVEs frequently targeted by threat actors
KNOWN_LINUX_CVES: List[VulnerabilityDef] = [
    VulnerabilityDef(
        cve_id="CVE-2024-6387",
        package="openssh-server",
        severity="CRITICAL",
        cvss=9.8,
        title="regreSSHion: OpenSSH Remote Unauthenticated Code Execution (RCE)",
        min_version="8.5p1",
        fixed_version="9.8p1",
        mitre_id="T1190",
        remediation="Upgrade openssh-server to >= 9.8p1 or apply vendor security patch."
    ),
    VulnerabilityDef(
        cve_id="CVE-2023-48795",
        package="openssh-server",
        severity="HIGH",
        cvss=7.5,
        title="Terrapin Attack: SSH Transport Protocol Prefix Truncation",
        min_version="1.0",
        fixed_version="9.6p1",
        mitre_id="T1557",
        remediation="Upgrade openssh-server >= 9.6p1 or disable ChaCha20-Poly1305 / CBC ciphers."
    ),
    VulnerabilityDef(
        cve_id="CVE-2021-3156",
        package="sudo",
        severity="CRITICAL",
        cvss=9.3,
        title="Baron Samedit: Sudo Heap-Based Buffer Overflow Local Privilege Escalation",
        min_version="1.8.2",
        fixed_version="1.9.5p2",
        mitre_id="T1068",
        remediation="Update sudo package to version >= 1.9.5p2 (apt update && apt install --only-upgrade sudo)."
    ),
    VulnerabilityDef(
        cve_id="CVE-2021-4034",
        package="policykit-1",
        severity="CRITICAL",
        cvss=9.8,
        title="PwnKit: Local Privilege Escalation in Polkit pkexec",
        min_version="0.96",
        fixed_version="0.105-31",
        mitre_id="T1068",
        remediation="Upgrade policykit-1/polkit or remove SUID bit with chmod 0755 /usr/bin/pkexec."
    ),
    VulnerabilityDef(
        cve_id="CVE-2023-38545",
        package="curl",
        severity="HIGH",
        cvss=7.5,
        title="libcurl SOCKS5 Heap Buffer Overflow",
        min_version="7.69.0",
        fixed_version="8.4.0",
        mitre_id="T1190",
        remediation="Upgrade curl and libcurl4 to >= 8.4.0."
    ),
    VulnerabilityDef(
        cve_id="CVE-2022-0778",
        package="openssl",
        severity="HIGH",
        cvss=7.5,
        title="OpenSSL BN_mod_sqrt Infinite Loop Denial of Service",
        min_version="1.0.2",
        fixed_version="1.1.1n",
        mitre_id="T1499",
        remediation="Upgrade openssl to >= 1.1.1n or >= 3.0.2."
    ),
    VulnerabilityDef(
        cve_id="CVE-2022-37434",
        package="zlib1g",
        severity="HIGH",
        cvss=7.5,
        title="zlib inflateGetHeader Heap-based Buffer Overflow",
        min_version="1.2.2",
        fixed_version="1.2.12-2",
        mitre_id="T1190",
        remediation="Upgrade zlib1g to >= 1.2.12 or latest security update."
    ),
    VulnerabilityDef(
        cve_id="CVE-2024-3094",
        package="xz-utils",
        severity="CRITICAL",
        cvss=10.0,
        title="XZ Utils Backdoor (Malicious Code Execution in OpenSSH)",
        min_version="5.6.0",
        fixed_version="5.6.1-2",
        mitre_id="T1195.002",
        remediation="Immediately downgrade xz-utils to 5.4.x or upgrade to clean upstream version."
    ),
    VulnerabilityDef(
        cve_id="CVE-2023-27320",
        package="nginx",
        severity="MEDIUM",
        cvss=6.5,
        title="Nginx HTTP/2 Protocol Rapid Reset & Stream Handling Vulnerability",
        min_version="1.9.5",
        fixed_version="1.25.3",
        mitre_id="T1499.004",
        remediation="Upgrade nginx to >= 1.25.3 or disable http2 directive if unpatched."
    ),
]


def parse_clean_version(ver_str: str) -> List[int]:
    """Extracts numeric sequence from package version string for safe comparison."""
    # Strip debian epoch e.g. "1:8.9p1" -> "8.9p1"
    if ":" in ver_str:
        ver_str = ver_str.split(":", 1)[1]
    # Strip debian revisions "-1ubuntu1" or "+deb11u1"
    ver_str = re.split(r"[-+~]", ver_str)[0]
    # Extract integer tokens
    numbers = [int(n) for n in re.findall(r"\d+", ver_str)]
    return numbers if numbers else [0]


def is_version_vulnerable(installed: str, min_ver: Optional[str], fixed_ver: str) -> bool:
    """Checks whether installed version satisfies: min_ver <= installed < fixed_ver"""
    inst_nums = parse_clean_version(installed)
    fix_nums = parse_clean_version(fixed_ver)

    # Normalize lengths
    maxlen = max(len(inst_nums), len(fix_nums))
    inst_pad = inst_nums + [0] * (maxlen - len(inst_nums))
    fix_pad = fix_nums + [0] * (maxlen - len(fix_nums))

    # Must be less than fixed version
    if inst_pad >= fix_pad:
        return False

    if min_ver:
        min_nums = parse_clean_version(min_ver)
        min_pad = min_nums + [0] * (maxlen - len(min_nums))
        if inst_pad < min_pad:
            return False

    return True


class VulnerabilityEngine:
    """Manages package CVE matching and CIS Baseline evaluations."""

    def __init__(self, db_conn_factory):
        self.get_db = db_conn_factory
        self.init_tables()

    def init_tables(self):
        con = self.get_db()
        with con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS agent_sca_reports (
                    agent_id TEXT PRIMARY KEY,
                    host TEXT NOT NULL,
                    score REAL NOT NULL,
                    total_checks INTEGER NOT NULL,
                    passed INTEGER NOT NULL,
                    failed INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    checks_json TEXT NOT NULL
                )
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS agent_vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    host TEXT NOT NULL,
                    cve_id TEXT NOT NULL,
                    package TEXT NOT NULL,
                    installed_version TEXT NOT NULL,
                    fixed_version TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    cvss REAL NOT NULL,
                    title TEXT NOT NULL,
                    remediation TEXT NOT NULL,
                    mitre_id TEXT NOT NULL,
                    discovered_at INTEGER NOT NULL,
                    UNIQUE(agent_id, cve_id)
                )
            """)
            con.execute("CREATE INDEX IF NOT EXISTS idx_vuln_agent ON agent_vulnerabilities(agent_id)")
            con.execute("CREATE INDEX IF NOT EXISTS idx_vuln_sev ON agent_vulnerabilities(severity)")

    def save_sca_report(self, agent_id: str, sca_data: Dict[str, Any]) -> Dict[str, Any]:
        con = self.get_db()
        host = sca_data.get("host", f"agent-{agent_id}")
        score = float(sca_data.get("score", 100.0))
        total = int(sca_data.get("total_checks", 0))
        passed = int(sca_data.get("passed", 0))
        failed = int(sca_data.get("failed", 0))
        checks = sca_data.get("checks", [])
        now = int(time.time())

        with con:
            con.execute("""
                INSERT INTO agent_sca_reports (agent_id, host, score, total_checks, passed, failed, updated_at, checks_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    host=excluded.host,
                    score=excluded.score,
                    total_checks=excluded.total_checks,
                    passed=excluded.passed,
                    failed=excluded.failed,
                    updated_at=excluded.updated_at,
                    checks_json=excluded.checks_json
            """, (agent_id, host, score, total, passed, failed, now, json.dumps(checks)))

        return {"status": "ok", "agent_id": agent_id, "score": score, "checks_saved": total}

    def correlate_packages(self, agent_id: str, host: str, packages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Matches agent's installed packages against known CVEs and updates SQLite."""
        con = self.get_db()
        now = int(time.time())
        findings = []

        # Map package name to version
        pkg_map: Dict[str, str] = {}
        for p in packages:
            name = p.get("name", "").lower()
            ver = p.get("version", "")
            if name and ver:
                pkg_map[name] = ver

        # Check against CVE definitions
        for cve in KNOWN_LINUX_CVES:
            target_pkg = cve.package.lower()
            if target_pkg in pkg_map:
                inst_ver = pkg_map[target_pkg]
                if is_version_vulnerable(inst_ver, cve.min_version, cve.fixed_version):
                    findings.append({
                        "agent_id": agent_id,
                        "host": host,
                        "cve_id": cve.cve_id,
                        "package": target_pkg,
                        "installed_version": inst_ver,
                        "fixed_version": cve.fixed_version,
                        "severity": cve.severity,
                        "cvss": cve.cvss,
                        "title": cve.title,
                        "remediation": cve.remediation,
                        "mitre_id": cve.mitre_id,
                        "discovered_at": now
                    })

        with con:
            # Refresh vulnerabilities for this agent
            con.execute("DELETE FROM agent_vulnerabilities WHERE agent_id=?", (agent_id,))
            for f in findings:
                con.execute("""
                    INSERT INTO agent_vulnerabilities (agent_id, host, cve_id, package, installed_version, fixed_version, severity, cvss, title, remediation, mitre_id, discovered_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    f["agent_id"], f["host"], f["cve_id"], f["package"], f["installed_version"],
                    f["fixed_version"], f["severity"], f["cvss"], f["title"], f["remediation"],
                    f["mitre_id"], f["discovered_at"]
                ))

        return findings

    def get_agent_sca(self, agent_id: str) -> Optional[Dict[str, Any]]:
        con = self.get_db()
        row = con.execute("SELECT * FROM agent_sca_reports WHERE agent_id=?", (agent_id,)).fetchone()
        if not row:
            return None
        return {
            "agent_id": row["agent_id"],
            "host": row["host"],
            "score": row["score"],
            "total_checks": row["total_checks"],
            "passed": row["passed"],
            "failed": row["failed"],
            "updated_at": row["updated_at"],
            "checks": json.loads(row["checks_json"]),
        }

    def get_agent_vulnerabilities(self, agent_id: Optional[str] = None) -> List[Dict[str, Any]]:
        con = self.get_db()
        if agent_id:
            rows = con.execute("SELECT * FROM agent_vulnerabilities WHERE agent_id=? ORDER BY cvss DESC", (agent_id,)).fetchall()
        else:
            rows = con.execute("SELECT * FROM agent_vulnerabilities ORDER BY cvss DESC LIMIT 100").fetchall()

        vulns = []
        for r in rows:
            vulns.append({
                "agent_id": r["agent_id"],
                "host": r["host"],
                "cve_id": r["cve_id"],
                "package": r["package"],
                "installed_version": r["installed_version"],
                "fixed_version": r["fixed_version"],
                "severity": r["severity"],
                "cvss": r["cvss"],
                "title": r["title"],
                "remediation": r["remediation"],
                "mitre_id": r["mitre_id"],
                "discovered_at": r["discovered_at"],
            })
        return vulns

    def get_fleet_summary(self) -> Dict[str, Any]:
        con = self.get_db()
        sca_rows = con.execute("SELECT score, passed, failed FROM agent_sca_reports").fetchall()
        avg_score = round(sum(r["score"] for r in sca_rows) / len(sca_rows), 1) if sca_rows else 100.0

        vuln_counts = con.execute("""
            SELECT severity, COUNT(*) as count
            FROM agent_vulnerabilities
            GROUP BY severity
        """).fetchall()

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for r in vuln_counts:
            sev = r["severity"]
            if sev in counts:
                counts[sev] = r["count"]

        total_vulns = sum(counts.values())

        return {
            "avg_sca_score": avg_score,
            "audited_endpoints": len(sca_rows),
            "total_vulnerabilities": total_vulns,
            "counts": counts,
        }

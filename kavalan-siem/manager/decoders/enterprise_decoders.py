"""
enterprise_decoders.py - Enterprise Log Decoders for Kavalan SIEM

Normalizes diverse enterprise log sources into the Common Event Model (CEM):
  1. Windows Security Event Logs (4624, 4625, 4688, 4720) & Sysmon (EID 1, 3, 11)
  2. Cloud Audit Logs: AWS CloudTrail, Microsoft Entra ID / M365, GCP Cloud Audit
  3. Network Infrastructure: DNS Query Logs (Bind9/CoreDNS), Web Proxies (Squid/Zscaler)
  4. Container & Orchestration: Kubernetes API Audit Logs
"""

import json
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from cem import CEMEvent


class WindowsSecurityEventDecoder:
    """Decodes Windows Security Event Logs (4624, 4625, 4688, 4720) and Sysmon."""
    name = "windows_security_events"

    # Regex patterns for text/key-value formatted Windows events
    EID_RE = re.compile(r"\b(?:EventID|Event\[\d+\]|ID)\s*[:=]\s*(?P<eid>\d{1,5})\b", re.IGNORECASE)
    USER_RE = re.compile(r"\b(?:TargetUserName|Account Name|User Name|User)\s*[:=]\s*['\"]?(?P<user>[a-zA-Z0-9_\-\.\$\\]+)['\"]?", re.IGNORECASE)
    IP_RE = re.compile(r"\b(?:IpAddress|Source Network Address|Client IP|SourceIp)\s*[:=]\s*['\"]?(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|::1)['\"]?", re.IGNORECASE)
    PROCESS_RE = re.compile(r"\b(?:NewProcessName|ProcessName|CommandLine|Image)\s*[:=]\s*['\"]?(?P<proc>[^'\";\r\n]+)['\"]?", re.IGNORECASE)

    def match(self, raw_line: str) -> bool:
        if '"EventID"' in raw_line or '"event_id"' in raw_line:
            return True
        return bool(self.EID_RE.search(raw_line) or "Microsoft-Windows-Security-Auditing" in raw_line or "Microsoft-Windows-Sysmon" in raw_line)

    def decode(self, raw_line: str, host: str = "win-host", year: Optional[int] = None) -> Optional[CEMEvent]:
        eid = None
        user = None
        ip = "127.0.0.1"
        proc = None

        if raw_line.strip().startswith("{"):
            try:
                d = json.loads(raw_line)
                eid_val = d.get("EventID") or d.get("event_id")
                if eid_val:
                    eid = int(eid_val)
                    user = d.get("TargetUserName") or d.get("SubjectUserName") or d.get("user")
                    ip = d.get("IpAddress") or d.get("source_ip") or "127.0.0.1"
                    proc = d.get("NewProcessName") or d.get("CommandLine") or d.get("process")
            except Exception:
                pass

        if not eid:
            m_eid = self.EID_RE.search(raw_line)
            if not m_eid:
                return None
            eid = int(m_eid.group("eid"))
            m_user = self.USER_RE.search(raw_line)
            user = m_user.group("user") if m_user else None
            m_ip = self.IP_RE.search(raw_line)
            ip = m_ip.group("ip") if m_ip else "127.0.0.1"
            m_proc = self.PROCESS_RE.search(raw_line)
            proc = m_proc.group("proc") if m_proc else None

        if user and user.endswith("$"):
            user = None  # Filter machine accounts
        if ip in ("-", "::1", ""):
            ip = "127.0.0.1"

        ts = int(time.time())
        meta: Dict[str, Any] = {"event_id": eid, "decoder": self.name}

        if eid == 4624:
            action = "windows_logon_success"
            outcome = "ok"
            status_code = 0
            target = "winlogon"
        elif eid == 4625:
            action = "windows_logon_failure"
            outcome = "fail"
            status_code = 401
            target = "winlogon"
        elif eid == 4688:
            action = f"process_create: {proc or 'unknown'}"
            outcome = "ok"
            status_code = 0
            target = proc or "process"
            meta["process"] = proc
        elif eid == 4720:
            action = f"user_account_created: {user or 'unknown'}"
            outcome = "ok"
            status_code = 0
            target = "sam_security"
        elif eid == 1:  # Sysmon Process Create
            action = f"sysmon_proc_create: {proc or 'unknown'}"
            outcome = "ok"
            status_code = 0
            target = proc or "sysmon"
            meta["process"] = proc
        elif eid == 3:  # Sysmon Network Connect
            action = "sysmon_network_connect"
            outcome = "ok"
            status_code = 0
            target = ip
        else:
            action = f"windows_event_{eid}"
            outcome = "ok"
            status_code = 0
            target = f"event_{eid}"

        return CEMEvent(
            ts=ts,
            host=host,
            source_ip=ip,
            log_type="auth" if eid in (4624, 4625, 4720) else "system",
            action=action,
            target=target,
            outcome=outcome,
            status=status_code,
            user=user,
            raw=raw_line.rstrip("\r\n"),
            meta=meta
        )


class CloudTrailDecoder:
    """Decodes AWS CloudTrail JSON audit logs."""
    name = "aws_cloudtrail"

    def match(self, raw_line: str) -> bool:
        return '"eventSource"' in raw_line and '"eventName"' in raw_line

    def decode(self, raw_line: str, host: str = "aws-cloud", year: Optional[int] = None) -> Optional[CEMEvent]:
        try:
            d = json.loads(raw_line)
        except Exception:
            return None

        event_name = d.get("eventName", "UnknownAction")
        event_source = d.get("eventSource", "aws.service")
        src_ip = d.get("sourceIPAddress", "127.0.0.1")
        error_code = d.get("errorCode")

        user_identity = d.get("userIdentity", {})
        user = user_identity.get("userName") or user_identity.get("principalId") or user_identity.get("arn")

        outcome = "fail" if error_code else "ok"
        status_code = 403 if (error_code and "Unauthorized" in error_code) else (400 if error_code else 200)

        ts_str = d.get("eventTime")
        if ts_str:
            try:
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                ts = int(dt.timestamp())
            except Exception:
                ts = int(time.time())
        else:
            ts = int(time.time())

        return CEMEvent(
            ts=ts,
            host=host,
            source_ip=src_ip,
            log_type="cloud",
            action=f"aws:{event_source}:{event_name}",
            target=event_source,
            outcome=outcome,
            status=status_code,
            user=user,
            raw=raw_line.rstrip("\r\n"),
            meta={
                "aws_region": d.get("awsRegion"),
                "event_source": event_source,
                "event_name": event_name,
                "error_code": error_code,
                "decoder": self.name
            }
        )


class MicrosoftEntraDecoder:
    """Decodes Microsoft Entra ID (Azure AD / M365) Audit and SignIn logs."""
    name = "ms_entra_id"

    def match(self, raw_line: str) -> bool:
        return ('"userPrincipalName"' in raw_line or '"appDisplayName"' in raw_line) and ('"ipAddress"' in raw_line or '"status"' in raw_line)

    def decode(self, raw_line: str, host: str = "azure-entra", year: Optional[int] = None) -> Optional[CEMEvent]:
        try:
            d = json.loads(raw_line)
        except Exception:
            return None

        user = d.get("userPrincipalName") or d.get("userId")
        ip = d.get("ipAddress") or "127.0.0.1"
        activity = d.get("activityDisplayName") or d.get("operationType") or "SignIn"

        status_obj = d.get("status", {})
        error_code = status_obj.get("errorCode") if isinstance(status_obj, dict) else d.get("errorCode")
        outcome = "fail" if error_code and error_code != 0 else "ok"
        status_code = int(error_code) if error_code else 0

        ts_str = d.get("createdDateTime")
        if ts_str:
            try:
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                ts = int(dt.timestamp())
            except Exception:
                ts = int(time.time())
        else:
            ts = int(time.time())

        return CEMEvent(
            ts=ts,
            host=host,
            source_ip=ip,
            log_type="auth",
            action=f"entra:{activity}",
            target="AzureAD",
            outcome=outcome,
            status=status_code,
            user=user,
            raw=raw_line.rstrip("\r\n"),
            meta={
                "app": d.get("appDisplayName"),
                "error_reason": status_obj.get("failureReason") if isinstance(status_obj, dict) else None,
                "decoder": self.name
            }
        )


class DnsLogDecoder:
    """Decodes DNS server query logs (Bind9, CoreDNS, Windows DNS)."""
    name = "dns_query"

    DNS_RE = re.compile(
        r"\bclient\s+@?(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})#?\d*:\s+query:\s+(?P<domain>\S+)\s+IN\s+(?P<qtype>[A-Z0-9]+)\s+.*?\((?P<status>[A-Z]+)\)",
        re.IGNORECASE
    )

    def match(self, raw_line: str) -> bool:
        return "query:" in raw_line and ("IN A" in raw_line or "IN TXT" in raw_line or "IN AAAA" in raw_line or "client" in raw_line)

    def decode(self, raw_line: str, host: str = "dns-01", year: Optional[int] = None) -> Optional[CEMEvent]:
        m = self.DNS_RE.search(raw_line)
        if not m:
            # Fallback simple search
            ip_m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw_line)
            ip = ip_m.group(0) if ip_m else "127.0.0.1"
            domain_m = re.search(r"query:\s+([a-zA-Z0-9_\-\.]+)", raw_line)
            domain = domain_m.group(1) if domain_m else "unknown.domain"
            qtype = "A"
            rcode = "NOERROR"
        else:
            ip = m.group("ip")
            domain = m.group("domain")
            qtype = m.group("qtype")
            rcode = m.group("status")

        outcome = "ok" if rcode in ("NOERROR", "+") else ("fail" if rcode == "NXDOMAIN" else "error")

        return CEMEvent(
            ts=int(time.time()),
            host=host,
            source_ip=ip,
            log_type="dns",
            action=f"dns_query {qtype} {domain}",
            target=domain,
            outcome=outcome,
            status=0 if outcome == "ok" else 1,
            user=None,
            raw=raw_line.rstrip("\r\n"),
            meta={"qtype": qtype, "rcode": rcode, "domain": domain, "decoder": self.name}
        )


class KubernetesAuditDecoder:
    """Decodes Kubernetes API server audit events."""
    name = "k8s_audit"

    def match(self, raw_line: str) -> bool:
        return '"verb"' in raw_line and ('"requestURI"' in raw_line or '"objectRef"' in raw_line)

    def decode(self, raw_line: str, host: str = "k8s-cluster", year: Optional[int] = None) -> Optional[CEMEvent]:
        try:
            d = json.loads(raw_line)
        except Exception:
            return None

        verb = d.get("verb", "get")
        uri = d.get("requestURI", "/")
        user_info = d.get("user", {})
        username = user_info.get("username", "system:anonymous")
        src_ips = d.get("sourceIPs", ["127.0.0.1"])
        ip = src_ips[0] if src_ips else "127.0.0.1"

        resp_status = d.get("responseStatus", {})
        code = resp_status.get("code", 200) if isinstance(resp_status, dict) else 200
        outcome = "ok" if code < 400 else ("denied" if code in (401, 403) else "fail")

        obj_ref = d.get("objectRef", {})
        resource = obj_ref.get("resource", "unknown") if isinstance(obj_ref, dict) else "unknown"
        target = f"{resource}/{obj_ref.get('name', '')}" if isinstance(obj_ref, dict) else uri

        return CEMEvent(
            ts=int(time.time()),
            host=host,
            source_ip=ip,
            log_type="k8s",
            action=f"k8s:{verb} {resource}",
            target=target,
            outcome=outcome,
            status=code,
            user=username,
            raw=raw_line.rstrip("\r\n"),
            meta={"verb": verb, "requestURI": uri, "namespace": obj_ref.get("namespace") if isinstance(obj_ref, dict) else None, "decoder": self.name}
        )

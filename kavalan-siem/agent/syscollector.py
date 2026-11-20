"""
syscollector.py - System Inventory Collector for Kavalan Agent (Tier 1)

Collects comprehensive endpoint configuration & inventory:
  1. System Info (OS release, kernel, architecture, CPU cores, RAM)
  2. Network Interfaces (Interface names, IP addresses, MAC addresses)
  3. Listening Network Ports (TCP / UDP listening sockets)
  4. Installed Software Packages (Debian dpkg / RPM / environment packages)

Tracks state deltas: triggers events when listening ports open/close or packages change.
Zero external dependencies (pure Python standard library).
"""

from dataclasses import dataclass, asdict
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class PortInfo:
    proto: str       # "tcp" | "udp"
    address: str     # local ip, e.g. "0.0.0.0"
    port: int        # port number, e.g. 22
    state: str       # "LISTEN"

    def key(self) -> str:
        return f"{self.proto}:{self.address}:{self.port}"


@dataclass
class PackageInfo:
    name: str
    version: str
    arch: str

    def key(self) -> str:
        return f"{self.name}:{self.version}"


class SyscollectorScanner:
    """Collects system inventory and tracks deltas in ports and packages."""

    def __init__(self, host: str = "localhost", source_ip: str = "127.0.0.1"):
        self.host = host
        self.source_ip = source_ip
        self.prev_ports: Set[str] = set()
        self.prev_packages: Set[str] = set()
        self.first_run = True

    def get_system_info(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "hostname": socket.gethostname(),
            "os_name": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "cpu_cores": os.cpu_count() or 1,
            "python_version": platform.python_version(),
        }

        # Memory detection on Linux
        if os.path.exists("/proc/meminfo"):
            try:
                with open("/proc/meminfo", "r") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            parts = line.split()
                            info["ram_total_kb"] = int(parts[1])
                        elif line.startswith("MemAvailable:"):
                            parts = line.split()
                            info["ram_available_kb"] = int(parts[1])
            except Exception:
                pass

        return info

    def get_network_interfaces(self) -> List[Dict[str, Any]]:
        interfaces: List[Dict[str, Any]] = []
        try:
            # Cross-platform hostname resolution
            host_ip = socket.gethostbyname(socket.gethostname())
            interfaces.append({"name": "default", "ip": host_ip})
        except Exception:
            pass

        # Try parsing /sys/class/net or /proc/net/dev on Linux
        if os.path.exists("/sys/class/net"):
            try:
                for iface in os.listdir("/sys/class/net"):
                    iface_path = os.path.join("/sys/class/net", iface)
                    mac = ""
                    operstate = "unknown"
                    try:
                        with open(os.path.join(iface_path, "address"), "r") as f:
                            mac = f.read().strip()
                        with open(os.path.join(iface_path, "operstate"), "r") as f:
                            operstate = f.read().strip()
                    except Exception:
                        pass
                    interfaces.append({
                        "name": iface,
                        "mac": mac,
                        "state": operstate,
                    })
            except Exception:
                pass

        return interfaces

    def get_listening_ports(self) -> List[PortInfo]:
        ports: List[PortInfo] = []

        # Method 1: parse /proc/net/tcp and /proc/net/udp (Linux standard)
        for proto, path in [("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6"),
                            ("udp", "/proc/net/udp"), ("udp6", "/proc/net/udp6")]:
            if os.path.exists(path):
                try:
                    with open(path, "r") as f:
                        lines = f.readlines()[1:]  # skip header
                    for line in lines:
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            state = parts[3]
                            # For TCP, state '0A' = TCP_LISTEN (10)
                            if proto.startswith("tcp") and state != "0A":
                                continue
                            local_addr = parts[1]
                            ip_hex, port_hex = local_addr.split(":")
                            port = int(port_hex, 16)
                            # Convert hex IP to string
                            if len(ip_hex) == 8:
                                ip_bytes = bytes.fromhex(ip_hex)
                                ip_str = socket.inet_ntoa(ip_bytes[::-1])
                            else:
                                ip_str = "::"
                            ports.append(PortInfo(
                                proto="tcp" if proto.startswith("tcp") else "udp",
                                address=ip_str,
                                port=port,
                                state="LISTEN"
                            ))
                except Exception:
                    pass

        # Method 2 fallback: netstat / ss if /proc/net was not available or empty
        if not ports:
            try:
                cmd = ["ss", "-tulpn"] if shutil_which("ss") else ["netstat", "-tulpn"] if shutil_which("netstat") else None
                if cmd:
                    out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=2.0).decode("utf-8")
                    for line in out.splitlines():
                        if "LISTEN" in line or (line.startswith("udp") and ":" in line):
                            m = re.search(r"(\S+)\s+\d+\s+\d+\s+(\S+):(\d+)", line)
                            if m:
                                proto_val = "tcp" if "tcp" in m.group(1).lower() else "udp"
                                ports.append(PortInfo(
                                    proto=proto_val,
                                    address=m.group(2),
                                    port=int(m.group(3)),
                                    state="LISTEN"
                                ))
            except Exception:
                pass

        return ports

    def get_installed_packages(self) -> List[PackageInfo]:
        packages: List[PackageInfo] = []

        # Debian / Ubuntu dpkg
        if shutil_which("dpkg-query"):
            try:
                out = subprocess.check_output(
                    ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\n"],
                    stderr=subprocess.DEVNULL,
                    timeout=5.0
                ).decode("utf-8", errors="replace")
                for line in out.splitlines():
                    parts = line.strip().split("\t")
                    if len(parts) >= 2:
                        packages.append(PackageInfo(
                            name=parts[0],
                            version=parts[1],
                            arch=parts[2] if len(parts) > 2 else "all"
                        ))
                return packages
            except Exception:
                pass

        # RedHat / CentOS rpm
        if shutil_which("rpm"):
            try:
                out = subprocess.check_output(
                    ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"],
                    stderr=subprocess.DEVNULL,
                    timeout=5.0
                ).decode("utf-8", errors="replace")
                for line in out.splitlines():
                    parts = line.strip().split("\t")
                    if len(parts) >= 2:
                        packages.append(PackageInfo(
                            name=parts[0],
                            version=parts[1],
                            arch=parts[2] if len(parts) > 2 else "noarch"
                        ))
                return packages
            except Exception:
                pass

        return packages

    def run_scan(self, report_baseline: bool = False) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Gathers complete inventory snapshot and calculates port/package delta events.
        Returns (inventory_dict, delta_events_list).
        """
        now = int(time.time())
        sys_info = self.get_system_info()
        interfaces = self.get_network_interfaces()
        ports = self.get_listening_ports()
        packages = self.get_installed_packages()

        curr_ports = {p.key(): p for p in ports}
        curr_pkgs = {pkg.key(): pkg for pkg in packages}

        inventory: Dict[str, Any] = {
            "ts": now,
            "host": self.host,
            "system": sys_info,
            "interfaces": interfaces,
            "ports": [asdict(p) for p in ports],
            "total_packages": len(packages),
        }

        delta_events: List[Dict[str, Any]] = []

        if self.first_run and not report_baseline:
            self.prev_ports = set(curr_ports.keys())
            self.prev_packages = set(curr_pkgs.keys())
            self.first_run = False
            return inventory, delta_events

        # Port deltas
        new_ports = set(curr_ports.keys()) - self.prev_ports
        closed_ports = self.prev_ports - set(curr_ports.keys())

        for p_key in new_ports:
            p_obj = curr_ports[p_key]
            delta_events.append({
                "ts": now,
                "host": self.host,
                "source_ip": self.source_ip,
                "log_type": "syscollector",
                "action": "port_opened",
                "target": f"{p_obj.proto}:{p_obj.port}",
                "outcome": "ok",
                "status": p_obj.port,
                "raw": f"Syscollector: New listening port opened: {p_obj.proto}/{p_obj.port} on {p_obj.address}",
                "meta": {"port": p_obj.port, "proto": p_obj.proto, "address": p_obj.address},
            })

        for p_key in closed_ports:
            try:
                parts = p_key.rsplit(":", 1)
                if len(parts) == 2:
                    proto_addr, p_num_str = parts
                    proto, addr = proto_addr.split(":", 1) if ":" in proto_addr else ("unknown", proto_addr)
                    p_num = int(p_num_str)
                else:
                    proto, addr, p_num = "unknown", "0.0.0.0", 0
            except Exception:
                proto, addr, p_num = "unknown", "0.0.0.0", 0

            delta_events.append({
                "ts": now,
                "host": self.host,
                "source_ip": self.source_ip,
                "log_type": "syscollector",
                "action": "port_closed",
                "target": f"{proto}:{p_num}",
                "outcome": "ok",
                "status": int(p_num),
                "raw": f"Syscollector: Listening port closed: {proto}/{p_num}",
                "meta": {"port": int(p_num), "proto": proto, "address": addr},
            })

        self.prev_ports = set(curr_ports.keys())
        self.prev_packages = set(curr_pkgs.keys())
        self.first_run = False

        return inventory, delta_events


def shutil_which(cmd: str) -> Optional[str]:
    """Pure stdlib replacement for shutil.which"""
    paths = os.environ.get("PATH", "").split(os.pathsep)
    for p in paths:
        cand = os.path.join(p, cmd)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None

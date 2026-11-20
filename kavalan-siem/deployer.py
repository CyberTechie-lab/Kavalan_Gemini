#!/usr/bin/env python3
"""
deployer.py - Kavalan Remote Agent Deployer & Fleet Provisioner

Automates remote installation of Kavalan Endpoint Security Agents to
Ubuntu / Debian Linux servers over SSH or generates one-line curl commands.

Usage:
  # 1. Deploy directly to a remote Ubuntu server over SSH:
  python3 deployer.py --target ubuntu@192.168.1.50 --manager http://192.168.1.10:8910 --name ubuntu-web-01

  # 2. Deploy with custom SSH private key:
  python3 deployer.py --target root@10.0.0.15 --key ~/.ssh/id_ed25519 --manager http://10.0.0.1:8910

  # 3. Print copy-pasteable one-liner for Ubuntu terminal:
  python3 deployer.py --generate-cmd --manager http://192.168.1.10:8910 --name my-server

  # 4. Interactive wizard:
  python3 deployer.py
"""

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

CURRENT_DIR = Path(__file__).resolve().parent
AGENT_DIR = CURRENT_DIR / "agent"
INSTALL_SH = AGENT_DIR / "install.sh"
AGENT_PY = AGENT_DIR / "agent.py"


def check_manager_health(manager_url: str) -> bool:
    """Checks if Kavalan Manager is reachable and responding."""
    url = f"{manager_url.rstrip('/')}/health"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Kavalan-Deployer/1.0"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            return resp.status == 200
    except Exception:
        return False


def wait_for_agent_enrollment(manager_url: str, agent_name: str, timeout: int = 30) -> Optional[Dict]:
    """Polls Manager API until the new agent is enrolled and ACTIVE."""
    url = f"{manager_url.rstrip('/')}/api/agents"
    start = time.time()
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Kavalan-Deployer/1.0"})
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                for a in data.get("agents", []):
                    if a.get("name") == agent_name:
                        return a
        except Exception:
            pass
        time.sleep(1.5)
    return None


def generate_curl_command(manager_url: str, agent_name: Optional[str] = None) -> str:
    """Generates the single-line bash command for Ubuntu installation."""
    mgr = manager_url.rstrip("/")
    name_flag = f" --name {agent_name}" if agent_name else ' --name $(hostname)'
    return f"curl -sSL {mgr}/install.sh | sudo bash -s -- --manager {mgr}{name_flag}"


def deploy_remote_ssh(target: str, manager_url: str, name: Optional[str] = None,
                      ssh_key: Optional[str] = None, port: int = 22) -> bool:
    """Deploys Kavalan Agent to remote server via SSH."""
    print("=" * 68)
    print(" KAVALAN REMOTE AGENT DEPLOYER · UBUNTU / LINUX")
    print("=" * 68)
    print(f"[*] Target Endpoint: {target} (port {port})")
    print(f"[*] Kavalan Manager: {manager_url}")

    agent_name = name or target.split("@")[-1].replace(".", "-")
    print(f"[*] Assigned Name:   {agent_name}")

    # 1. Verify Manager
    print("[*] Validating Manager connectivity...")
    if not check_manager_health(manager_url):
        print(f"[!] Warning: Manager at {manager_url}/health not responding directly.")
        print("    Ensure the target server can reach the Manager's IP and port.")

    # 2. Build SSH command
    ssh_opts = ["-p", str(port), "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10"]
    if ssh_key:
        ssh_opts += ["-i", str(Path(ssh_key).expanduser())]

    # Test basic SSH connectivity
    print(f"[*] Connecting to {target} via SSH...")
    test_cmd = ["ssh"] + ssh_opts + [target, "echo 'SSH_OK'"]
    try:
        res = subprocess.run(test_cmd, capture_output=True, text=True, timeout=15)
        if "SSH_OK" not in res.stdout:
            print(f"[!] Failed to connect to {target}:\n{res.stderr.strip()}", file=sys.stderr)
            return False
        print(f"[+] SSH connection established successfully to {target}.")
    except Exception as e:
        print(f"[!] SSH connection error: {e}", file=sys.stderr)
        return False

    # 3. Execute remote installation
    # Pipe install.sh directly over SSH with sudo
    print("[*] Streaming installer and agent payload to remote endpoint...")
    remote_install_cmd = f"sudo bash -s -- --manager {shlex.quote(manager_url)} --name {shlex.quote(agent_name)}"
    deploy_cmd = ["ssh"] + ssh_opts + [target, remote_install_cmd]

    with open(INSTALL_SH, "rb") as script_in:
        proc = subprocess.Popen(deploy_cmd, stdin=script_in, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in proc.stdout:
            print(f"  [remote] {line.rstrip()}")
        proc.wait()

    if proc.returncode != 0:
        print(f"[!] Remote installation failed with exit code {proc.returncode}.", file=sys.stderr)
        return False

    # 4. Await verification from Manager
    print(f"[*] Waiting for {agent_name} to register with Manager ({manager_url})...")
    agent_info = wait_for_agent_enrollment(manager_url, agent_name, timeout=25)
    if agent_info:
        print("=" * 68)
        print(" [+] DEPLOYMENT CONFIRMED · AGENT ONLINE IN FLEET!")
        print(f"     Agent ID:    {agent_info.get('id')}")
        print(f"     Name:        {agent_info.get('name')}")
        print(f"     IP Address:  {agent_info.get('ip')}")
        print(f"     Status:      {agent_info.get('status').upper()}")
        print(f"     OS Info:     {agent_info.get('os')}")
        print("=" * 68)
        return True
    else:
        print(f"[!] Agent registered or keepalive pending. Check status with:\n    python3 kavalan-siem/kavalan_soc.py status")
        return True


def interactive_wizard():
    print("=" * 68)
    print(" KAVALAN AGENT DEPLOYMENT WIZARD")
    print("=" * 68)
    target = input("Enter remote target (e.g. ubuntu@192.168.1.50): ").strip()
    if not target:
        print("[!] Target required.")
        return
    manager = input("Enter Kavalan Manager URL [default: http://127.0.0.1:8910]: ").strip() or "http://127.0.0.1:8910"
    name = input("Enter agent name [default: auto-detected]: ").strip() or None
    key = input("Enter SSH private key path (optional, leave blank for default): ").strip() or None

    deploy_remote_ssh(target=target, manager_url=manager, name=name, ssh_key=key)


def main():
    parser = argparse.ArgumentParser(description="Kavalan Remote Agent Deployer (Ubuntu / Linux)")
    parser.add_argument("--target", help="Remote SSH target (e.g. ubuntu@192.168.1.50)")
    parser.add_argument("--manager", default="http://127.0.0.1:8910", help="Kavalan Manager URL (default: http://127.0.0.1:8910)")
    parser.add_argument("--name", default=None, help="Agent hostname identifier")
    parser.add_argument("--key", default=None, help="Path to SSH private key (e.g. ~/.ssh/id_rsa)")
    parser.add_argument("--port", type=int, default=22, help="Remote SSH port (default: 22)")
    parser.add_argument("--generate-cmd", action="store_true", help="Print copy-pasteable curl installation command")
    args = parser.parse_args()

    if args.generate_cmd:
        cmd = generate_curl_command(args.manager, args.name)
        print("\nRun this command on your Ubuntu server:")
        print("-" * 68)
        print(cmd)
        print("-" * 68)
        return

    if args.target:
        success = deploy_remote_ssh(
            target=args.target,
            manager_url=args.manager,
            name=args.name,
            ssh_key=args.key,
            port=args.port
        )
        sys.exit(0 if success else 1)
    else:
        interactive_wizard()


if __name__ == "__main__":
    main()

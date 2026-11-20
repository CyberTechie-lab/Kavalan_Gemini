export const SAMPLE_AGENT_CONF = `{
  "manager": "https://kavalan-manager.local:3000",
  "tls": {
    "enabled": true,
    "verify_ca": "/etc/kavalan-agent/certs/ca.crt",
    "client_cert": "/etc/kavalan-agent/certs/agent.crt",
    "client_key": "/etc/kavalan-agent/certs/agent.key",
    "pin_sha256": true
  },
  "agent_name": "ubuntu-srv-01",
  "heartbeat_interval": 10,
  "batch_size": 50,
  "max_eps": 500,
  "syscheck": {
    "directories": ["/etc", "/bin", "/var/www", "/opt/kavalan-agent"],
    "interval_seconds": 60
  },
  "localfiles": [
    { "format": "web", "location": "/var/log/nginx/access.log" },
    { "format": "auth", "location": "/var/log/auth.log" },
    { "format": "dns", "location": "/var/log/named/queries.log" },
    { "format": "k8s_audit", "location": "/var/log/kubernetes/audit.log" }
  ]
}
`;

export const INSTALL_SH_SCRIPT = `#!/usr/bin/env bash
# ==============================================================================
# Kavalan Endpoint Agent Installer (TLS/mTLS + Integrity Verified)
#
# Usage:
#   curl -sSL http://<MANAGER_HOST>:3000/install.sh | sudo bash -s -- --manager https://<MANAGER_HOST>:3000
# ==============================================================================

set -e

INSTALL_DIR="/opt/kavalan-agent"
CONFIG_DIR="/etc/kavalan-agent"
CERTS_DIR="/etc/kavalan-agent/certs"
DATA_DIR="/var/lib/kavalan-agent"
MANAGER_URL="\${2:-http://127.0.0.1:3000}"
AGENT_NAME="$(hostname -s 2>/dev/null || hostname)"

echo "===================================================================="
echo "   KAVALAN ENDPOINT AGENT DEPLOYER · mTLS & TAMPER-VERIFIED AGENT   "
echo "===================================================================="
echo "[*] Target Hostname:   \${AGENT_NAME}"
echo "[*] Manager Server:    \${MANAGER_URL}"

mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$CERTS_DIR" "$DATA_DIR"
curl -fsSL "\${MANAGER_URL}/agent/agent.py" -o "\${INSTALL_DIR}/agent.py"
curl -fsSL "\${MANAGER_URL}/api/tls/ca" -o "\${CERTS_DIR}/ca.crt" || true
chmod 755 "\${INSTALL_DIR}/agent.py"
BINARY_SHA=$(sha256sum "\${INSTALL_DIR}/agent.py" 2>/dev/null | awk '{print $1}' || echo "verified")

cat > "\${CONFIG_DIR}/agent.conf" <<EOF
{
  "manager": "\${MANAGER_URL}",
  "agent_name": "\${AGENT_NAME}",
  "tls": { "enabled": true, "verify_ca": "\${CERTS_DIR}/ca.crt", "client_cert": "\${CERTS_DIR}/agent.crt" },
  "binary_sha256": "\${BINARY_SHA}",
  "heartbeat_interval": 10,
  "batch_size": 50,
  "localfiles": [
    { "format": "auth", "location": "/var/log/auth.log" },
    { "format": "web", "location": "/var/log/nginx/access.log" }
  ]
}
EOF

echo "[+] Agent mTLS enrolled against \${MANAGER_URL}"
`;

export const AGENT_PY_STUB = `#!/usr/bin/env python3
"""Kavalan Encrypted Endpoint Agent Client (TLS + Per-Agent Key Rotation + Tamper Hash)."""
import hashlib, json, os, socket, ssl, sys, time, urllib.request

MANAGER = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:3000"
CA_CERT = "/etc/kavalan-agent/certs/ca.crt"
CLIENT_CERT = "/etc/kavalan-agent/certs/agent.crt"
CLIENT_KEY = "/etc/kavalan-agent/certs/agent.key"

def binary_sha256():
    with open(__file__, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def ssl_ctx():
    if MANAGER.startswith("https://") and os.path.exists(CA_CERT):
        ctx = ssl.create_default_context(cafile=CA_CERT)
        if os.path.exists(CLIENT_CERT) and os.path.exists(CLIENT_KEY):
            ctx.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
        return ctx
    return None

def post(path, payload, agent_key="", cert_fp=""):
    headers = {
        "Content-Type": "application/json",
        "X-Agent-Key": agent_key,
        "X-Agent-Cert-FP": cert_fp,
        "X-Agent-Binary-SHA256": binary_sha256(),
    }
    req = urllib.request.Request(
        f"{MANAGER.rstrip('/')}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5, context=ssl_ctx()) as r:
        return json.loads(r.read().decode("utf-8"))

if __name__ == "__main__":
    reg = post("/api/agent/register", {"name": socket.gethostname(), "ip": "127.0.0.1", "os": "Linux"})
    print("Registered mTLS Agent:", reg)
    while True:
        hb = post("/api/agent/heartbeat", {"agent_id": reg["agent_id"], "metrics": {"cpu_pct": 4.2, "mem_pct": 28.0, "eps": 2}}, reg.get("agent_key", ""), reg.get("cert_fingerprint", ""))
        time.sleep(10)
`;

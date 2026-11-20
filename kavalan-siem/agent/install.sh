#!/usr/bin/env bash
# ==============================================================================
# Kavalan Endpoint Agent Installer (Tier 1) for Ubuntu / Debian Linux
#
# Usage:
#   curl -sSL http://<MANAGER_IP>:8910/install.sh | sudo bash -s -- --manager http://<MANAGER_IP>:8910
#   sudo bash install.sh --manager http://192.168.1.10:8910 --name ubuntu-web-01
#   sudo bash install.sh --uninstall
# ==============================================================================

set -e

# Default settings
INSTALL_DIR="/opt/kavalan-agent"
CONFIG_DIR="/etc/kavalan-agent"
DATA_DIR="/var/lib/kavalan-agent"
SERVICE_NAME="kavalan-agent"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

MANAGER_URL=""
AGENT_NAME=""
CUSTOM_WEB_LOG=""
CUSTOM_AUTH_LOG=""
DO_UNINSTALL=false

# Styling
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "===================================================================="
    echo "      KAVALAN ENDPOINT AGENT DEPLOYER · TIER 1 INSTALLER           "
    echo "       Lightweight AI-Agent Detection & Telemetry Collector        "
    echo "===================================================================="
    echo -e "${NC}"
}

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --manager|-m)
            MANAGER_URL="$2"
            shift 2
            ;;
        --name|-n)
            AGENT_NAME="$2"
            shift 2
            ;;
        --web|-w)
            CUSTOM_WEB_LOG="$2"
            shift 2
            ;;
        --auth|-a)
            CUSTOM_AUTH_LOG="$2"
            shift 2
            ;;
        --dir|-d)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --uninstall|-u)
            DO_UNINSTALL=true
            shift
            ;;
        --help|-h)
            echo "Usage: sudo bash install.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --manager, -m <URL>    Kavalan Manager URL (e.g. http://192.168.1.10:8910)"
            echo "  --name, -n <NAME>      Agent hostname identifier (default: current hostname)"
            echo "  --web, -w <PATH>       Path to web access log (default: auto-detected Nginx/Apache)"
            echo "  --auth, -a <PATH>      Path to SSH/auth log (default: auto-detected /var/log/auth.log)"
            echo "  --dir, -d <PATH>       Target installation path (default: /opt/kavalan-agent)"
            echo "  --uninstall, -u        Remove agent service and configuration completely"
            exit 0
            ;;
        *)
            echo -e "${RED}[!] Unknown argument: $1${NC}"
            exit 1
            ;;
    esac
done

# Root check
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] Error: This installer must be run as root (or with sudo).${NC}"
    exit 1
fi

# Handle Uninstall
if [[ "$DO_UNINSTALL" == true ]]; then
    print_banner
    echo -e "${YELLOW}[*] Stopping and disabling ${SERVICE_NAME}.service...${NC}"
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        systemctl stop "$SERVICE_NAME" || true
    fi
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload || true

    echo -e "${YELLOW}[*] Removing agent directories...${NC}"
    rm -rf "$INSTALL_DIR"
    rm -rf "$CONFIG_DIR"
    rm -rf "$DATA_DIR"

    echo -e "${GREEN}[+] Kavalan Agent completely uninstalled from host.${NC}"
    exit 0
fi

print_banner

# Prompt for manager URL if not provided
if [[ -z "$MANAGER_URL" ]]; then
    echo -e "${YELLOW}[?] Kavalan Manager URL not specified via --manager.${NC}"
    read -rp "    Enter Manager URL (e.g. http://192.168.1.10:8910): " MANAGER_URL
    if [[ -z "$MANAGER_URL" ]]; then
        echo -e "${RED}[!] Manager URL is required to enroll agent. Exiting.${NC}"
        exit 1
    fi
fi

# Strip trailing slash
MANAGER_URL="${MANAGER_URL%/}"

# Determine Agent Name
if [[ -z "$AGENT_NAME" ]]; then
    AGENT_NAME=$(hostname -s 2>/dev/null || hostname)
fi

echo -e "${BLUE}[*] Target Hostname:${NC}   $AGENT_NAME"
echo -e "${BLUE}[*] Manager Server:${NC}    $MANAGER_URL"
echo -e "${BLUE}[*] Install Dir:${NC}       $INSTALL_DIR"

# 1. Check Python 3
echo -e "${BLUE}[*] Checking prerequisites...${NC}"
if ! command -v python3 &>/dev/null; then
    echo -e "${YELLOW}[*] Python 3 not detected. Attempting apt install...${NC}"
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq python3
    else
        echo -e "${RED}[!] Error: Python 3.8+ required. Please install python3 manually.${NC}"
        exit 1
    fi
fi

PYTHON_BIN=$(command -v python3)
PY_VER=$($PYTHON_BIN -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "${GREEN}[+] Found Python $PY_VER at $PYTHON_BIN${NC}"

# 2. Prepare Directories
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$DATA_DIR"
chmod 755 "$INSTALL_DIR"
chmod 750 "$CONFIG_DIR"
chmod 750 "$DATA_DIR"

# 3. Locate or Download Agent Modules
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
AGENT_MODULES=("agent.py" "buffer.py" "executor.py" "syscheck.py" "syscollector.py" "sca.py")

for mod in "${AGENT_MODULES[@]}"; do
    MOD_TARGET="${INSTALL_DIR}/${mod}"
    if [[ -f "${SCRIPT_DIR}/${mod}" ]]; then
        echo -e "${BLUE}[*] Installing ${mod} from local source...${NC}"
        cp "${SCRIPT_DIR}/${mod}" "$MOD_TARGET"
    else
        echo -e "${BLUE}[*] Downloading ${mod} from Manager (${MANAGER_URL}/agent/${mod})...${NC}"
        if command -v curl &>/dev/null; then
            curl -fsSL "${MANAGER_URL}/agent/${mod}" -o "$MOD_TARGET"
        elif command -v wget &>/dev/null; then
            wget -qO "$MOD_TARGET" "${MANAGER_URL}/agent/${mod}"
        else
            echo -e "${RED}[!] Error: Neither curl nor wget available. Please install curl.${NC}"
            exit 1
        fi
    fi
    chmod 755 "$MOD_TARGET"
done

# 4. Detect Ubuntu Log Files & Build Config
echo -e "${BLUE}[*] Auto-discovering Ubuntu server log sources...${NC}"
DETECTED_FILES=()

# Auth logs
if [[ -n "$CUSTOM_AUTH_LOG" ]]; then
    DETECTED_FILES+=("{\"format\": \"auth\", \"location\": \"$CUSTOM_AUTH_LOG\"}")
    echo -e "    ${GREEN}+${NC} Auth Log (custom): $CUSTOM_AUTH_LOG"
elif [[ -f "/var/log/auth.log" ]]; then
    DETECTED_FILES+=("{\"format\": \"auth\", \"location\": \"/var/log/auth.log\"}")
    echo -e "    ${GREEN}+${NC} Auth Log (Ubuntu SSH): /var/log/auth.log"
elif [[ -f "/var/log/secure" ]]; then
    DETECTED_FILES+=("{\"format\": \"auth\", \"location\": \"/var/log/secure\"}")
    echo -e "    ${GREEN}+${NC} Auth Log (RHEL/Secure): /var/log/secure"
fi

# Web logs
if [[ -n "$CUSTOM_WEB_LOG" ]]; then
    DETECTED_FILES+=("{\"format\": \"web\", \"location\": \"$CUSTOM_WEB_LOG\"}")
    echo -e "    ${GREEN}+${NC} Web Log (custom): $CUSTOM_WEB_LOG"
else
    if [[ -f "/var/log/nginx/access.log" ]]; then
        DETECTED_FILES+=("{\"format\": \"web\", \"location\": \"/var/log/nginx/access.log\"}")
        echo -e "    ${GREEN}+${NC} Web Log (Nginx): /var/log/nginx/access.log"
    fi
    if [[ -f "/var/log/apache2/access.log" ]]; then
        DETECTED_FILES+=("{\"format\": \"web\", \"location\": \"/var/log/apache2/access.log\"}")
        echo -e "    ${GREEN}+${NC} Web Log (Apache2): /var/log/apache2/access.log"
    fi
fi

# Fallback default if nothing found on disk yet
if [[ ${#DETECTED_FILES[@]} -eq 0 ]]; then
    echo -e "    ${YELLOW}! No active logs found; configuring default Ubuntu paths (/var/log/auth.log)${NC}"
    DETECTED_FILES+=("{\"format\": \"auth\", \"location\": \"/var/log/auth.log\"}")
fi

# Build JSON array
LOCALFILES_JSON=$(IFS=,; echo "${DETECTED_FILES[*]}")

cat > "${CONFIG_DIR}/agent.conf" <<EOF
{
  "manager": "${MANAGER_URL}",
  "agent_name": "${AGENT_NAME}",
  "heartbeat_interval": 10,
  "batch_size": 50,
  "max_eps": 500,
  "spool_file": "${DATA_DIR}/spool_${AGENT_NAME}.jsonl",
  "syscheck": {
    "directories": ["/etc", "/bin", "/usr/bin", "/var/www"],
    "interval_seconds": 60
  },
  "localfiles": [
    ${LOCALFILES_JSON}
  ]
}
EOF
chmod 640 "${CONFIG_DIR}/agent.conf"
echo -e "${GREEN}[+] Generated configuration: ${CONFIG_DIR}/agent.conf${NC}"

# 5. Create Systemd Service Unit
if command -v systemctl &>/dev/null; then
    echo -e "${BLUE}[*] Creating systemd service unit (${SERVICE_FILE})...${NC}"
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Kavalan Endpoint Security Agent (Tier 1)
Documentation=https://github.com/kavalan-siem
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${PYTHON_BIN} ${INSTALL_DIR}/agent.py --config ${CONFIG_DIR}/agent.conf
Restart=always
RestartSec=5s
TimeoutStopSec=10s
LimitNOFILE=65536
MemoryMax=50M
CPUQuota=20%

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl restart "$SERVICE_NAME"

    echo -e "${BLUE}[*] Checking service status...${NC}"
    sleep 2
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        echo -e "${GREEN}[+] ${SERVICE_NAME}.service is ACTIVE and RUNNING!${NC}"
    else
        echo -e "${RED}[!] Warning: ${SERVICE_NAME} failed to start. Journal output:${NC}"
        journalctl -u "$SERVICE_NAME" -n 20 --no-pager
    fi
else
    echo -e "${YELLOW}[!] Systemd not detected (container environment?). Agent installed at ${INSTALL_DIR}/agent.py${NC}"
fi

echo -e "\n${CYAN}${BOLD}===================================================================="
echo "      KAVALAN AGENT DEPLOYMENT SUCCESSFUL!                         "
echo "====================================================================${NC}"
echo -e " Agent Hostname:   ${BOLD}${AGENT_NAME}${NC}"
echo -e " Manager Server:   ${BOLD}${MANAGER_URL}${NC}"
echo -e " Config File:      ${CONFIG_DIR}/agent.conf"
echo -e " Service Status:   systemctl status ${SERVICE_NAME}"
echo -e " Live Logs:        journalctl -u ${SERVICE_NAME} -f"
echo -e "${CYAN}====================================================================${NC}\n"

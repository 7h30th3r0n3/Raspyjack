#!/bin/bash

# ============================================================================
# Ragnar Advanced Security Tools Installer
# ============================================================================
# This script installs advanced security tools for server-mode features:
# - Traffic Analysis (tcpdump, tshark, ngrep, iftop, nethogs)
# - Advanced Vulnerability Assessment (nuclei, nikto, sqlmap, whatweb)
#
# Run this script after install_ragnar.sh on capable hardware (8GB+ RAM)
# Usage: sudo ./install_advanced_tools.sh
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo ./install_advanced_tools.sh)${NC}"
    exit 1
fi

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║          Ragnar Advanced Security Tools Installer                ║"
echo "║                  Server Mode Features                            ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Detect package manager
if command -v apt-get &> /dev/null; then
    PKG_MGR="apt"
    UPDATE_CMD="apt-get update"
    INSTALL_CMD="apt-get install -y"
elif command -v dnf &> /dev/null; then
    PKG_MGR="dnf"
    UPDATE_CMD="dnf check-update || true"
    INSTALL_CMD="dnf install -y"
elif command -v yum &> /dev/null; then
    PKG_MGR="yum"
    UPDATE_CMD="yum check-update || true"
    INSTALL_CMD="yum install -y"
elif command -v pacman &> /dev/null; then
    PKG_MGR="pacman"
    UPDATE_CMD="pacman -Sy"
    INSTALL_CMD="pacman -S --noconfirm"
else
    echo -e "${RED}Unsupported package manager${NC}"
    exit 1
fi

echo -e "${BLUE}Detected package manager: ${PKG_MGR}${NC}"

# ============================================================================
# INSTALL BASIC DEPENDENCIES
# ============================================================================
echo ""
echo -e "${CYAN}Installing basic dependencies...${NC}"
$UPDATE_CMD
$INSTALL_CMD curl wget unzip git 2>/dev/null || true

# Determine the user running Ragnar (for permissions)
# Check for ragnar user, fall back to current SUDO_USER or 'nobody'
if id "ragnar" &>/dev/null; then
    RAGNAR_USER="ragnar"
elif [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
    RAGNAR_USER="$SUDO_USER"
else
    RAGNAR_USER=""
    echo -e "${YELLOW}Note: No ragnar user found, skipping user-specific permissions${NC}"
fi

if [ -n "$RAGNAR_USER" ]; then
    echo -e "${BLUE}Ragnar user: ${RAGNAR_USER}${NC}"
fi

# Function to check if command exists
check_installed() {
    if command -v "$1" &> /dev/null; then
        echo -e "${GREEN}✓ $1 is installed${NC}"
        return 0
    else
        echo -e "${YELLOW}✗ $1 not found${NC}"
        return 1
    fi
}

# Function to install package
install_pkg() {
    local pkg=$1
    echo -e "${BLUE}Installing $pkg...${NC}"
    $INSTALL_CMD "$pkg" 2>/dev/null || {
        echo -e "${YELLOW}Package $pkg not available via $PKG_MGR${NC}"
        return 1
    }
    return 0
}

# ============================================================================
# TRAFFIC ANALYSIS TOOLS
# ============================================================================
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Installing Traffic Analysis Tools${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"

$UPDATE_CMD

# Core traffic tools
TRAFFIC_TOOLS=("tcpdump" "tshark" "ngrep" "iftop" "nethogs")

for tool in "${TRAFFIC_TOOLS[@]}"; do
    if ! check_installed "$tool"; then
        case $tool in
            tshark)
                # tshark is part of wireshark package
                if [ "$PKG_MGR" = "apt" ]; then
                    # Pre-configure wireshark to allow non-root capture
                    echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections 2>/dev/null || true
                    install_pkg "tshark" || install_pkg "wireshark-cli" || true
                else
                    install_pkg "wireshark-cli" || install_pkg "wireshark" || true
                fi
                ;;
            *)
                install_pkg "$tool" || true
                ;;
        esac
    fi
done

# ============================================================================
# VULNERABILITY ASSESSMENT TOOLS
# ============================================================================
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Installing Vulnerability Assessment Tools${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"

# APT-based tools
VULN_TOOLS=("nikto" "sqlmap" "whatweb" "hydra")

for tool in "${VULN_TOOLS[@]}"; do
    if ! check_installed "$tool"; then
        install_pkg "$tool" || true
    fi
done

# ============================================================================
# NUCLEI INSTALLATION (requires Go or direct binary)
# ============================================================================
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Installing Nuclei (Template-based Scanner)${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"

if check_installed "nuclei"; then
    echo -e "${GREEN}Nuclei already installed, checking for updates...${NC}"
    nuclei -update-templates 2>/dev/null || true
else
    echo -e "${BLUE}Installing Nuclei...${NC}"
    
    # Detect architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64|amd64)
            NUCLEI_ARCH="amd64"
            ;;
        aarch64|arm64)
            NUCLEI_ARCH="arm64"
            ;;
        armv7l|armv8l)
            NUCLEI_ARCH="armv6"
            ;;
        *)
            echo -e "${YELLOW}Unsupported architecture for Nuclei: $ARCH${NC}"
            NUCLEI_ARCH=""
            ;;
    esac
    
    if [ -n "$NUCLEI_ARCH" ]; then
        # Get latest version
        echo -e "${BLUE}Downloading Nuclei for ${NUCLEI_ARCH}...${NC}"
        
        # Try to get latest release URL from GitHub API
        NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/' || echo "3.3.7")
        NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NUCLEI_ARCH}.zip"
        
        TEMP_DIR=$(mktemp -d)
        cd "$TEMP_DIR"
        
        if curl -sL -o nuclei.zip "$NUCLEI_URL"; then
            if unzip -q nuclei.zip 2>/dev/null; then
                chmod +x nuclei
                mv nuclei /usr/local/bin/
                echo -e "${GREEN}✓ Nuclei ${NUCLEI_VERSION} installed successfully${NC}"
                
                # Download templates
                echo -e "${BLUE}Downloading Nuclei templates...${NC}"
                if [ -n "$RAGNAR_USER" ]; then
                    sudo -u "$RAGNAR_USER" nuclei -update-templates 2>/dev/null || nuclei -update-templates 2>/dev/null || true
                else
                    nuclei -update-templates 2>/dev/null || true
                fi
            else
                echo -e "${RED}Failed to extract Nuclei${NC}"
            fi
        else
            echo -e "${RED}Failed to download Nuclei${NC}"
        fi
        
        cd /
        rm -rf "$TEMP_DIR"
    fi
    
    # Fallback: try Go install if available
    if ! check_installed "nuclei" && check_installed "go"; then
        echo -e "${BLUE}Trying Go install method...${NC}"
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true
        
        # Add Go bin to path if nuclei was installed there
        if [ -f "$HOME/go/bin/nuclei" ]; then
            ln -sf "$HOME/go/bin/nuclei" /usr/local/bin/nuclei
        fi
    fi
fi

# ============================================================================
# ZAP (OWASP ZED ATTACK PROXY) INSTALLATION
# ============================================================================
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Installing OWASP ZAP (Zed Attack Proxy)${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"

# Check if running on Raspberry Pi Zero (insufficient resources)
IS_PI_ZERO=false
if grep -qi "Raspberry Pi Zero" /proc/cpuinfo 2>/dev/null; then
    IS_PI_ZERO=true
fi

# Determine Ragnar installation directory (where this script is located)
# Handle both direct execution and sudo execution
if [ -n "${BASH_SOURCE[0]}" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    SCRIPT_DIR="$(pwd)"
fi
RAGNAR_DIR="$SCRIPT_DIR"

# Verify this is actually the Ragnar directory
if [ ! -f "$RAGNAR_DIR/Ragnar.py" ] && [ ! -f "$RAGNAR_DIR/webapp_modern.py" ]; then
    # Fallback to common locations (check in order of likelihood)
    if [ -d "/home/ragnar/Ragnar" ] && [ -f "/home/ragnar/Ragnar/Ragnar.py" ]; then
        RAGNAR_DIR="/home/ragnar/Ragnar"
    elif [ -f "$(pwd)/Ragnar.py" ]; then
        RAGNAR_DIR="$(pwd)"
    elif [ -d "/opt/ragnar" ]; then
        RAGNAR_DIR="/opt/ragnar"
    elif [ -d "/home/ragnar/ragnar" ]; then
        RAGNAR_DIR="/home/ragnar/ragnar"
    else
        echo -e "${RED}ERROR: Could not determine Ragnar installation directory${NC}"
        echo -e "${YELLOW}Please run this script from the Ragnar directory${NC}"
        exit 1
    fi
fi

echo -e "${BLUE}Ragnar directory: ${RAGNAR_DIR}${NC}"

if [ "$IS_PI_ZERO" = true ]; then
    echo -e "${YELLOW}Raspberry Pi Zero detected - skipping ZAP installation (insufficient resources)${NC}"
else
    echo -e "${BLUE}Installing ZAP for server-mode security testing...${NC}"

    # Install OpenJDK 21 JRE (or fallback to 17/11)
    if ! java -version 2>&1 | grep -qE "openjdk.*(21|17|11)"; then
        echo -e "${BLUE}Installing OpenJDK 21 JRE...${NC}"
        install_pkg "openjdk-21-jre" || install_pkg "openjdk-21-jre-headless" || \
        install_pkg "java-21-openjdk" || install_pkg "java-21-openjdk-headless" || {
            echo -e "${YELLOW}Could not install OpenJDK 21, trying OpenJDK 17...${NC}"
            install_pkg "openjdk-17-jre" || install_pkg "openjdk-17-jre-headless" || \
            install_pkg "java-17-openjdk" || install_pkg "java-17-openjdk-headless" || {
                echo -e "${YELLOW}Could not install OpenJDK 17, trying OpenJDK 11...${NC}"
                install_pkg "openjdk-11-jre" || install_pkg "openjdk-11-jre-headless" || \
                install_pkg "java-11-openjdk" || {
                    echo -e "${RED}Failed to install Java - ZAP requires Java 11+${NC}"
                }
            }
        }
    else
        echo -e "${GREEN}✓ Java already installed${NC}"
    fi

    # Download and install ZAP if Java is available
    if command -v java &> /dev/null; then
        ZAP_VERSION="2.17.0"
        # Install ZAP inside Ragnar's tools directory for predictable location
        ZAP_DIR="${RAGNAR_DIR}/tools/zap"
        ZAP_GLOBAL_DIR="/opt/zaproxy"

        if [ ! -d "$ZAP_DIR" ] && [ ! -d "$ZAP_GLOBAL_DIR" ]; then
            echo -e "${BLUE}Downloading ZAP ${ZAP_VERSION}...${NC}"
            TEMP_DIR=$(mktemp -d)
            cd "$TEMP_DIR"

            if wget -q --show-progress "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz"; then
                echo -e "${BLUE}Extracting ZAP...${NC}"
                tar -xzf "ZAP_${ZAP_VERSION}_Linux.tar.gz"

                # Debug: Show paths
                echo -e "${BLUE}RAGNAR_DIR: ${RAGNAR_DIR}${NC}"
                echo -e "${BLUE}ZAP_DIR: ${ZAP_DIR}${NC}"

                # Create tools/zap directory in Ragnar folder
                echo -e "${BLUE}Creating directory: ${ZAP_DIR}${NC}"
                mkdir -p "${RAGNAR_DIR}/tools/zap"

                # Verify directory was created
                if [ ! -d "${RAGNAR_DIR}/tools/zap" ]; then
                    echo -e "${RED}Failed to create ${RAGNAR_DIR}/tools/zap${NC}"
                    ls -la "${RAGNAR_DIR}/tools/"
                    exit 1
                fi

                # Find the extracted ZAP folder and move its contents
                ZAP_EXTRACTED=$(find . -maxdepth 1 -type d -name "ZAP_*" | head -1)
                echo -e "${BLUE}Found extracted folder: ${ZAP_EXTRACTED}${NC}"

                if [ -n "$ZAP_EXTRACTED" ] && [ -d "$ZAP_EXTRACTED" ]; then
                    # Move contents into the zap directory
                    echo -e "${BLUE}Moving contents to ${RAGNAR_DIR}/tools/zap/${NC}"
                    mv "${ZAP_EXTRACTED}"/* "${RAGNAR_DIR}/tools/zap/"
                    rm -rf "$ZAP_EXTRACTED"
                else
                    echo -e "${RED}Could not find extracted ZAP directory${NC}"
                    echo -e "${YELLOW}Contents of temp dir:${NC}"
                    ls -la
                    cd /
                    rm -rf "$TEMP_DIR"
                    exit 1
                fi

                # Set permissions
                chmod +x "${ZAP_DIR}/zap.sh"
                if [ -n "$RAGNAR_USER" ]; then
                    chown -R "${RAGNAR_USER}:${RAGNAR_USER}" "${RAGNAR_DIR}/tools" 2>/dev/null || true
                fi

                # Create global symlink for convenience
                mkdir -p /opt
                ln -sf "$ZAP_DIR" "$ZAP_GLOBAL_DIR" 2>/dev/null || true

                # Create wrapper script in /usr/local/bin
                cat > /usr/local/bin/zap.sh << EOF
#!/bin/bash
${ZAP_DIR}/zap.sh "\$@"
EOF
                chmod +x /usr/local/bin/zap.sh

                # Also create 'zap' alias
                cat > /usr/local/bin/zap << EOF
#!/bin/bash
${ZAP_DIR}/zap.sh "\$@"
EOF
                chmod +x /usr/local/bin/zap

                echo -e "${GREEN}✓ ZAP ${ZAP_VERSION} installed successfully${NC}"
                echo -e "${BLUE}  Location: ${ZAP_DIR}${NC}"
                echo -e "${BLUE}  Commands: zap, zap.sh${NC}"
            else
                echo -e "${RED}Failed to download ZAP${NC}"
            fi

            cd /
            rm -rf "$TEMP_DIR"
        else
            if [ -d "$ZAP_DIR" ]; then
                echo -e "${GREEN}✓ ZAP already installed at ${ZAP_DIR}${NC}"
            else
                echo -e "${GREEN}✓ ZAP already installed at ${ZAP_GLOBAL_DIR}${NC}"
            fi
        fi
    else
        echo -e "${YELLOW}Java not available - skipping ZAP installation${NC}"
    fi
fi

# ============================================================================
# NMAP VULNERABILITY SCRIPTS
# ============================================================================
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Installing Nmap Vulnerability Scripts${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"

NMAP_SCRIPTS_DIR="/usr/share/nmap/scripts"

if [ -d "$NMAP_SCRIPTS_DIR" ]; then
    # vulners.nse
    if [ ! -f "$NMAP_SCRIPTS_DIR/vulners.nse" ]; then
        echo -e "${BLUE}Downloading vulners.nse...${NC}"
        curl -sL -o "$NMAP_SCRIPTS_DIR/vulners.nse" \
            "https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse" && \
            echo -e "${GREEN}✓ vulners.nse installed${NC}" || \
            echo -e "${YELLOW}Failed to download vulners.nse${NC}"
    else
        echo -e "${GREEN}✓ vulners.nse already installed${NC}"
    fi
    
    # vulscan
    if [ ! -d "$NMAP_SCRIPTS_DIR/vulscan" ]; then
        echo -e "${BLUE}Downloading vulscan...${NC}"
        git clone --depth 1 https://github.com/scipag/vulscan.git "$NMAP_SCRIPTS_DIR/vulscan" 2>/dev/null && \
            echo -e "${GREEN}✓ vulscan installed${NC}" || \
            echo -e "${YELLOW}Failed to download vulscan${NC}"
    else
        echo -e "${GREEN}✓ vulscan already installed${NC}"
    fi
    
    # Update nmap script database
    echo -e "${BLUE}Updating nmap script database...${NC}"
    nmap --script-updatedb 2>/dev/null || true
else
    echo -e "${YELLOW}Nmap scripts directory not found${NC}"
fi

# ============================================================================
# CONFIGURE PERMISSIONS
# ============================================================================
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Configuring Permissions${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"

# Only configure sudo permissions if we have a valid user
if [ -n "$RAGNAR_USER" ]; then
    # Find actual paths for tools (may vary by distro)
    TCPDUMP_PATH=$(which tcpdump 2>/dev/null || echo "/usr/bin/tcpdump")
    TSHARK_PATH=$(which tshark 2>/dev/null || echo "/usr/bin/tshark")
    IFTOP_PATH=$(which iftop 2>/dev/null || echo "/usr/sbin/iftop")
    NETHOGS_PATH=$(which nethogs 2>/dev/null || echo "/usr/sbin/nethogs")
    NIKTO_PATH=$(which nikto 2>/dev/null || echo "/usr/bin/nikto")
    SQLMAP_PATH=$(which sqlmap 2>/dev/null || echo "/usr/bin/sqlmap")
    NUCLEI_PATH=$(which nuclei 2>/dev/null || echo "/usr/local/bin/nuclei")

    # Allow user to run tcpdump without password
    SUDOERS_FILE="/etc/sudoers.d/ragnar-traffic"
    echo -e "${BLUE}Configuring sudo permissions for traffic capture...${NC}"
    cat > "$SUDOERS_FILE" << EOF
# Allow ${RAGNAR_USER} user to run traffic analysis tools without password
${RAGNAR_USER} ALL=(ALL) NOPASSWD: ${TCPDUMP_PATH}
${RAGNAR_USER} ALL=(ALL) NOPASSWD: ${TSHARK_PATH}
${RAGNAR_USER} ALL=(ALL) NOPASSWD: ${IFTOP_PATH}
${RAGNAR_USER} ALL=(ALL) NOPASSWD: ${NETHOGS_PATH}
EOF
    chmod 440 "$SUDOERS_FILE"
    echo -e "${GREEN}✓ Traffic capture permissions configured for ${RAGNAR_USER}${NC}"

    # Allow user to run vuln scanners
    SUDOERS_FILE="/etc/sudoers.d/ragnar-vuln"
    echo -e "${BLUE}Configuring sudo permissions for vulnerability scanners...${NC}"
    cat > "$SUDOERS_FILE" << EOF
# Allow ${RAGNAR_USER} user to run vulnerability scanners without password
${RAGNAR_USER} ALL=(ALL) NOPASSWD: ${NIKTO_PATH}
${RAGNAR_USER} ALL=(ALL) NOPASSWD: ${SQLMAP_PATH}
${RAGNAR_USER} ALL=(ALL) NOPASSWD: ${NUCLEI_PATH}
EOF
    chmod 440 "$SUDOERS_FILE"
    echo -e "${GREEN}✓ Vulnerability scanner permissions configured for ${RAGNAR_USER}${NC}"
else
    echo -e "${YELLOW}Skipping sudo permissions (no user detected)${NC}"
    echo -e "${YELLOW}You may need to run tools with sudo manually${NC}"
fi

# ============================================================================
# FINAL STATUS CHECK
# ============================================================================
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Installation Summary${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"

echo ""
echo -e "${BLUE}Traffic Analysis Tools:${NC}"
for tool in tcpdump tshark ngrep iftop nethogs; do
    check_installed "$tool"
done

echo ""
echo -e "${BLUE}Vulnerability Assessment Tools:${NC}"
for tool in nmap nikto sqlmap whatweb hydra nuclei; do
    check_installed "$tool"
done

echo ""
echo -e "${BLUE}Web Application Security:${NC}"
check_installed "java"
if [ -f "${RAGNAR_DIR}/tools/zap/zap.sh" ] || [ -f "/opt/zaproxy/zap.sh" ] || check_installed "zap" 2>/dev/null; then
    echo -e "${GREEN}✓ OWASP ZAP is installed${NC}"
    if [ -f "${RAGNAR_DIR}/tools/zap/zap.sh" ]; then
        echo -e "${BLUE}  Location: ${RAGNAR_DIR}/tools/zap/${NC}"
    fi
else
    echo -e "${YELLOW}✗ OWASP ZAP not installed${NC}"
fi

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Advanced tools installation complete!${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Note: Restart Ragnar for changes to take effect:${NC}"
echo -e "  sudo systemctl restart ragnar"
echo ""

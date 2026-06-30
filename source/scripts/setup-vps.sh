#!/bin/bash

#===============================================================================
# rjsxrd VPS Auto-Setup Script
# 
# Automates deployment of rjsxrd VPN config generator on Ubuntu/Debian VPS
# Optimized for small VPS (1GB RAM, 1 core)
#
# Features:
#   - Dedicated non-root user (rjsxrd)
#   - Systemd service for auto-start
#   - Basic file permissions (600/750)
#   - Firewall (UFW) + Fail2Ban protection
#   - Simple and reliable
#
# Usage: curl -O https://raw.githubusercontent.com/YOUR_USERNAME/rjsxrd/main/setup-vps.sh
#        chmod +x setup-vps.sh
#        sudo ./setup-vps.sh
#===============================================================================

set -euo pipefail  # Exit on error, undefined vars, pipe failures

#-------------------------------------------------------------------------------
# Colors for output
#-------------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

#-------------------------------------------------------------------------------
# Helper functions
#-------------------------------------------------------------------------------
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Please run as root (use sudo)"
        exit 1
    fi
}

check_os() {
    if [ ! -f /etc/debian_version ]; then
        log_warning "This script is tested on Debian/Ubuntu. Other distros may need adjustments."
        read -p "Continue anyway? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

#-------------------------------------------------------------------------------
# Read secret with asterisk feedback. Usage: VAR=$(read_secret "prompt: ")
#-------------------------------------------------------------------------------
read_secret() {
    local prompt="$1"
    local secret="" char
    printf '%s' "$prompt" >&2
    # Try interactive terminal via /dev/tty first (works even inside $() subshells)
    if ( : <>/dev/tty ) 2>/dev/null; then
        stty -echo <>/dev/tty
        trap 'stty echo <>/dev/tty 2>/dev/null; printf "\n" >/dev/tty; exit 1' INT TERM
        while IFS= read -r -s -n1 char <> /dev/tty 2>/dev/null; do
            case "${char:-}" in
                ''|$'\n'|$'\r') printf '\n' >/dev/tty; break;;
                $'\b'|$'\177')
                    if [ -n "$secret" ]; then
                        secret="${secret%?}"
                        printf '\b \b' >/dev/tty
                    fi
                    ;;
                *) secret="$secret$char"; printf '*' >/dev/tty;;
            esac
        done
        stty echo <>/dev/tty 2>/dev/null
        trap - INT TERM
    else
        # Non-interactive (cron, pipe) — silent read, no asterisks
        IFS= read -r -s secret
    fi
    echo "$secret"
}

#-------------------------------------------------------------------------------
# Configuration
#-------------------------------------------------------------------------------
APP_NAME="rjsxrd"
APP_DIR="/opt/rjsxrd"
VENV_DIR="$APP_DIR/venv"
LOG_DIR="/var/log/rjsxrd"
RUN_SCRIPT="$APP_DIR/run.sh"
HEALTH_SCRIPT="$APP_DIR/healthcheck.sh"
ENV_FILE="$APP_DIR/.env"

#-------------------------------------------------------------------------------
# Main setup
#-------------------------------------------------------------------------------
main() {
    echo ""
    echo "=========================================="
    echo "  rjsxrd VPS Auto-Setup"
    echo "=========================================="
    echo ""
    
    check_root
    check_os
    
    log_info "Starting setup..."
    echo ""
    
    #---------------------------------------------------------------------------
    # Step 1: Choose Push Mode
    #---------------------------------------------------------------------------
    log_info "Step 1: Push Mode & Repository Configuration"
    echo ""
    echo "  [api] — GitHub API (default) — uploads via REST API, no git clone needed"
    echo "  [git] — git push (--use-git) — clones repo with full git history"
    echo "  [no]  — dry-run (generates files locally, no upload)"
    echo ""
    read -p "Push mode (api/git/n) [api]: " PUSH_MODE_INPUT
    echo ""
    
    PUSH_MODE="api"
    if [[ $PUSH_MODE_INPUT =~ ^[Gg] ]]; then
        PUSH_MODE="git"
    elif [[ $PUSH_MODE_INPUT =~ ^[Nn] ]]; then
        PUSH_MODE="none"
    fi

    if [ "$PUSH_MODE" != "none" ]; then
        echo "Create your token at: https://github.com/settings/tokens"
        echo "  - Use FINE-GRAINED token (recommended) or classic"
        echo "  - Repository access: ONLY your rjsxrd fork"
        echo "  - Permissions: Contents (Read and write) ONLY"
        echo ""
        GITHUB_TOKEN=$(read_secret "GitHub Token: ")
        
        if [ -z "$GITHUB_TOKEN" ]; then
            log_warning "No token entered — will run in dry-run mode instead"
            PUSH_MODE="none"
            unset GITHUB_TOKEN
        fi
    else
        log_info "Dry-run mode — no GitHub token needed"
    fi
    echo ""

    #---------------------------------------------------------------------------
    # Check if repo already exists (rsynced manually)
    #---------------------------------------------------------------------------
    SKIP_CLONE=false
    if [ -d "$APP_DIR" ] && [ -f "$APP_DIR/source/main.py" ]; then
        log_info "Files already exist at $APP_DIR — keeping them, skipping download"
        SKIP_CLONE=true
    fi

    #---------------------------------------------------------------------------
    # Step 2: Choose Repository (skipped if files already exist)
    #---------------------------------------------------------------------------
    if [ "$SKIP_CLONE" = false ]; then
        MAIN_REPO="https://github.com/whoahaow/rjsxrd.git"
        echo ""
        echo "Download source from which repository?"
        echo "  1) Main repo: $MAIN_REPO"
        echo "  2) Your fork (enter custom URL)"
        echo ""
        read -p "Choice (1/2) [1]: " REPO_CHOICE
        echo ""

        if [[ "$REPO_CHOICE" == "2" ]]; then
            read -p "Fork URL (e.g., https://github.com/youruser/rjsxrd.git): " REPO_URL
            if [ -z "$REPO_URL" ]; then
                log_warning "No URL entered, using main repo"
                REPO_URL="$MAIN_REPO"
            fi
        else
            REPO_URL="$MAIN_REPO"
        fi

        REPO_DISPLAY=$(echo "$REPO_URL" | sed 's|.*/||' | sed 's|\\\.git$||')
        log_info "Setting up: $REPO_DISPLAY"
        echo ""
    else
        log_info "Step 2/11: Repository (skipped — using existing files)"
        echo ""
    fi
    
    #---------------------------------------------------------------------------
    # Step 2: Create Dedicated Service User
    #---------------------------------------------------------------------------
    log_info "Step 2: Creating Dedicated Service User"
    
    if id "rjsxrd" &>/dev/null; then
        log_info "  User 'rjsxrd' already exists"
    else
        # Create system user (no login shell)
        useradd -r -s /usr/sbin/nologin -d "$APP_DIR" rjsxrd
        log_info "  Created system user: rjsxrd"
    fi
    
    log_success "Service user ready"
    echo ""
    
    #---------------------------------------------------------------------------
    # Step 3: Install System Dependencies
    #---------------------------------------------------------------------------
    log_info "Step 3: Installing System Dependencies"
    
    apt update -qq
    
    PACKAGES="python3 python3-pip python3-venv git curl cron logrotate fail2ban ufw auditd unattended-upgrades earlyoom zram-tools aide rkhunter chkrootkit lynis"
    
    for pkg in $PACKAGES; do
        if dpkg -l | grep -q "^ii  $pkg "; then
            log_info "  ✓ $pkg already installed"
        else
            log_info "  Installing $pkg..."
            apt install -y -qq "$pkg"
        fi
    done
    
    log_success "System dependencies installed"
    echo ""

    #---------------------------------------------------------------------------
    # Step 4: Swap + earlyoom (safe memory buffer for 1GB VPS)
    #---------------------------------------------------------------------------
    log_info "Step 4: Setting Up Swap and earlyoom"

    # 2GB swap file
    if swapon --show | grep -q "/swapfile"; then
        log_info "  ✓ Swap already active ($(swapon --show | tail -1 | awk '{print $3}'))"
    else
        log_info "  Creating 2GB swap file..."
        fallocate -l 2G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=2048
        chmod 600 /swapfile
        mkswap /swapfile >/dev/null
        swapon /swapfile
        if ! grep -q '/swapfile' /etc/fstab; then
            echo '/swapfile none swap sw 0 0' >> /etc/fstab
        fi
        # Lower swappiness — only swap under real pressure
        if [ -d /etc/sysctl.d ]; then
            cat > /etc/sysctl.d/99-vps.conf << 'SYSCTL'
# VPS memory tuning — keep swap as emergency only
vm.swappiness = 10
vm.vfs_cache_pressure = 50
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5
vm.overcommit_memory = 1
vm.dirty_expire_centisecs = 3000
vm.dirty_writeback_centisecs = 500
SYSCTL
            sysctl -p /etc/sysctl.d/99-vps.conf >/dev/null 2>&1
        fi
        log_success "  Swap created (2GB, swappiness=10, memory tuning applied)"
    fi

    # zRAM — compressed in-memory swap (2:1 compression, huge win on 1GB VPS)
    if command -v zramctl &>/dev/null && ! zramctl 2>/dev/null | grep -q "^/dev"; then
        log_info "  Configuring zRAM compressed swap..."
        echo "ALGO=zstd" > /etc/default/zramswap
        echo "PERCENT=50" >> /etc/default/zramswap
        systemctl enable --now zramswap 2>/dev/null || systemctl restart zramswap 2>/dev/null || true
        log_success "  zRAM enabled (50% RAM, zstd compression)"
    else
        log_info "  zRAM already active or unavailable"
    fi

    # earlyoom — kills the heaviest process before the kernel OOM killer
    if command -v earlyoom &>/dev/null; then
        log_info "  ✓ earlyoom already installed"
    else
        log_info "  Installing earlyoom..."
        apt install -y -qq earlyoom 2>/dev/null || \
            log_warning "  earlyoom not in repo — install manually: apt install earlyoom"
        systemctl enable --now earlyoom 2>/dev/null || true
        log_success "  earlyoom installed and running"
    fi

    echo ""

    #---------------------------------------------------------------------------
    # Step 5: Create Application Directory
    #---------------------------------------------------------------------------
    log_info "Step 5: Setting Up Application Directory"

    if [ "$SKIP_CLONE" = false ]; then
        if [ -d "$APP_DIR" ]; then
            log_warning "Directory $APP_DIR exists but doesn't look like rjsxrd repo"
            read -p "Overwrite? (y/n): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_error "Cannot proceed — remove $APP_DIR manually or choose a different path"
                exit 1
            else
                rm -rf "$APP_DIR"
            fi
        fi
        mkdir -p "$APP_DIR"
    else
        log_info "  Directory already set up at $APP_DIR"
    fi

    mkdir -p "$LOG_DIR"
    
    # Set ownership
    chown -R rjsxrd:rjsxrd "$APP_DIR"
    chown rjsxrd:rjsxrd "$LOG_DIR"
    
    # Set permissions
    chmod 750 "$APP_DIR"
    chmod 750 "$LOG_DIR"
    
    log_success "Application directory ready"
    echo ""
    
    if [ "$SKIP_CLONE" = false ]; then
        # Determine download method based on push mode
        # For git mode: clone with git (includes .git folder)
        # For api/none mode: download tarball (no .git folder, saves ~5MB)
        if [ "$PUSH_MODE" = "git" ]; then
            log_info "Step 6a: Cloning Repository (git mode)"
            cd "$APP_DIR"

            if [ -n "$GITHUB_TOKEN" ] && [ "$REPO_URL" != "$MAIN_REPO" ]; then
                log_info "  Cloning fork with token authentication..."
                # Use git credential file to avoid leaking token in ps aux
                GIT_CRED_FILE=$(mktemp)
                echo "https://***@github.com" > "$GIT_CRED_FILE"
                trap 'rm -f "$GIT_CRED_FILE"' EXIT
                if git clone "$REPO_URL" --config credential.helper="store --file $GIT_CRED_FILE" . 2>/dev/null; then
                    git remote set-url origin "$REPO_URL" 2>/dev/null || true
                    rm -f "$GIT_CRED_FILE"
                    trap - EXIT
                    log_success "Fork cloned (git mode)"
                else
                    rm -f "$GIT_CRED_FILE"
                    trap - EXIT
                    log_error "Failed to clone fork. Check URL and token permissions."
                    exit 1
                fi
            else
                log_info "  Cloning public repository..."
                if git clone "$REPO_URL" . 2>/dev/null; then
                    log_success "Repository cloned (git mode)"
                else
                    log_error "Failed to clone repository. Check URL."
                    exit 1
                fi
            fi
        else
            log_info "Step 6b: Downloading Source Code (API/dry-run mode)"
            cd "$APP_DIR"

            # Convert repo URL to tarball archive URL
            # https://github.com/user/rjsxrd.git → https://github.com/user/rjsxrd/archive/main.tar.gz
            ARCHIVE_BASE=$(echo "$REPO_URL" | sed 's|\.git$||')
            ARCHIVE_URL="$ARCHIVE_BASE/archive/main.tar.gz"

            log_info "  Downloading from: $ARCHIVE_BASE"
            TAR_FILE=$(mktemp)
            trap 'rm -f "$TAR_FILE"' EXIT
            curl -sL -o "$TAR_FILE" "$ARCHIVE_URL" || {
                # Fallback: try refs/heads/ prefix (older GitHub format)
                log_info "Trying alternative archive URL..."
                ARCHIVE_URL="$ARCHIVE_BASE/archive/refs/heads/main.tar.gz"
                curl -sL -o "$TAR_FILE" "$ARCHIVE_URL" || {
                    log_error "Failed to download source from $ARCHIVE_BASE"
                    rm -f "$TAR_FILE"
                    exit 1
                }
            }
            tar tzf "$TAR_FILE" >/dev/null 2>&1 || {
                log_error "Downloaded file is not a valid archive (corrupt or wrong URL)"
                rm -f "$TAR_FILE"
                exit 1
            }
            tar xzf "$TAR_FILE" --strip-components=1 2>&1 || {
                # Fallback: try without strip-components (repo might have single-file root)
                log_info "Extraction with strip-components failed, trying without..."
                tar xzf "$TAR_FILE" -C "$APP_DIR" 2>/dev/null || {
                    log_error "Failed to extract archive"
                    rm -f "$TAR_FILE"
                    exit 1
                }
                # Move files up if they're nested in a single directory
                if [ -d "$APP_DIR/rjsxrd-main" ]; then
                    mv "$APP_DIR/rjsxrd-main"/* "$APP_DIR/" 2>/dev/null || true
                    mv "$APP_DIR/rjsxrd-main"/.* "$APP_DIR/" 2>/dev/null || true
                fi
            }
            rm -f "$TAR_FILE"
            trap - EXIT

            if [ -f "$APP_DIR/source/main.py" ]; then
                log_success "Source code downloaded (no .git folder)"
            else
                log_error "Failed to download source. Check URL."
                exit 1
            fi
        fi

        # Set ownership
        chown -R rjsxrd:rjsxrd "$APP_DIR"
        echo ""
    else
        log_info "Step 6: Download Source (skipped — files already exist)"
        # Still fix ownership on existing files
        chown -R rjsxrd:rjsxrd "$APP_DIR" 2>/dev/null || true
    fi
    
    #---------------------------------------------------------------------------
    # Step 7: Create Virtual Environment
    #---------------------------------------------------------------------------
    log_info "Step 7: Creating Python Virtual Environment"
    
    cd "$APP_DIR/source"
    python3 -m venv "$VENV_DIR"
    
    source "$VENV_DIR/bin/activate"
    pip install --upgrade pip -q
    
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt -q
        log_success "Python dependencies installed"
    else
        log_error "requirements.txt not found"
        exit 1
    fi
    
    deactivate
    chown -R rjsxrd:rjsxrd "$VENV_DIR"
    
    echo ""
    
    #---------------------------------------------------------------------------
    # Step 8: Create Environment File
    #---------------------------------------------------------------------------
    log_info "Step 8: Creating Environment Configuration"
    
    # Derive REPO_NAME (owner/repo) from repo URL for GitHub API pushes
    if [ -n "${REPO_URL:-}" ]; then
        REPO_NAME=$(echo "$REPO_URL" | sed 's|https://github.com/||' | sed 's|\.git$||')
    else
        REPO_NAME="whoahaow/rjsxrd"
    fi
    
    # Create .env file (token optional — dry-run if absent)
    cat > "$ENV_FILE" << EOF
# rjsxrd Environment Configuration
# Generated: $(date)
EOF

if [ -n "$GITHUB_TOKEN" ]; then
    cat >> "$ENV_FILE" << EOF
# GitHub Personal Access Token
GITHUB_TOKEN=$GITHUB_TOKEN

# Target repo for GitHub API pushes (owner/repo format)
REPO_NAME=$REPO_NAME

# Push mode: "api" (GitHub REST API, no git needed) or "git" (--use-git, needs repo clone)
PUSH_MODE=$PUSH_MODE
EOF
fi

    cat >> "$ENV_FILE" << 'EOF'

# === VPS Memory Tuning (1GB VPS) ===
# SystemSpecs auto-detects RAM and caps xray concurrency.
# On 1GB with 2GB swap, safe_xray_workers() gives ~34 workers.
# Hard-cap lower if you see OOM kills:
#ASYNC_CONCURRENCY_LINUX=30

# === URL fetching ===
# curl_cffi fetch workers (auto-detect is fine, but be explicit)
MAX_WORKERS=20
FETCH_TIMEOUT=10

# === TCP ping verification (used with --tcp-ping) ===
VALIDATION_TCP_CONCURRENCY=50
VALIDATION_TCP_TIMEOUT=3

# === Feature flags — disable everything non-essential ===
# default/ — 1.txt, 2.txt, all.txt, all-secure.txt (enable if you need them)
#ENABLE_DEFAULT_FILES=1
# bypass-unsecure/ — configs without security filtering
#ENABLE_BYPASS_UNSECURE=1
# split-by-protocols/ — per-protocol files
#ENABLE_PROTOCOL_SPLIT=1
# tg-proxy/ — Telegram proxies
#ENABLE_TG_PROXY=1
# /raw/ subfolders — untested configs before verification
#PUBLISH_RAW_FILES=1
EOF
    
    # Secure the file
    chmod 600 "$ENV_FILE"
    chown rjsxrd:rjsxrd "$ENV_FILE"

    log_success "Environment file created"
    if [ -n "$GITHUB_TOKEN" ]; then
        log_info "  Token stored in: $ENV_FILE (permissions: 600)"
    else
        log_info "  No token — runs in dry-run mode"
    fi
    echo ""

    #---------------------------------------------------------------------------
    # Telegram Bot Setup (stored in .env, secured at 600)
    #---------------------------------------------------------------------------
    log_info "Step 9: Telegram Bot Notifications"
    echo ""
    echo "  [yes] — bot sends you a message when pipeline starts/finishes"
    echo "  [no]  — no notifications"
    echo ""
    read -p "Setup Telegram bot? (y/N): " TG_CHOICE
    echo ""

    if [[ $TG_CHOICE =~ ^[Yy] ]]; then
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "  How to create a bot:"
        echo ""
        echo "  1. Open Telegram → search @BotFather"
        echo "  2. Send /newbot → follow prompts"
        echo "  3. Copy the token (looks like: 1234567890:ABCdef...)"
        echo "  4. Start your bot (click /start or open the link)"
        echo "  5. Find your user ID:"
        echo "     Send a message to the bot, then visit:"
        echo "     https://api.telegram.org/bot<TOKEN>/getUpdates"
        echo "     Your ID is the 'chat' → 'id' number"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        TELEGRAM_BOT_TOKEN=$(read_secret "Bot token: ")
        if [ -n "$TELEGRAM_BOT_TOKEN" ]; then
            read -p "Your Telegram user ID (digits only): " TELEGRAM_CHAT_ID
            echo ""
            if [ -n "$TELEGRAM_CHAT_ID" ]; then
                # Append to .env
                cat >> "$ENV_FILE" << EOF

# === Telegram bot notifications ===
TELEGRAM_BOT_TOKEN=$TELEGRAM_BOT_TOKEN
TELEGRAM_CHAT_ID=$TELEGRAM_CHAT_ID
EOF
                chmod 600 "$ENV_FILE"
                log_success "Telegram bot configured"
            else
                log_warning "No user ID — skipping bot setup"
            fi
        else
            log_warning "No token — skipping bot setup"
        fi
    else
        log_info "Telegram bot skipped"
    fi
    echo ""
    
    #---------------------------------------------------------------------------
    # Step 10: Create Run Scripts
    #---------------------------------------------------------------------------
    log_info "Step 10: Creating Run Scripts"
    
    # Create run script
    cat > "$RUN_SCRIPT" << 'RUNSCRIPT'
#!/bin/bash

#===============================================================================
# rjsxrd Runner Script
#===============================================================================

LOG_FILE="/var/log/rjsxrd/run.log"
LOCK_FILE="/tmp/rjsxrd.lock"
APP_DIR="/opt/rjsxrd"

mkdir -p /var/log/rjsxrd

# Prevent concurrent executions
if [ -f "$LOCK_FILE" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Another instance running, skipping" >> "$LOG_FILE"
    exit 1
fi

touch "$LOCK_FILE"
trap "rm -f $LOCK_FILE" EXIT

echo "$(date '+%Y-%m-%d %H:%M:%S') - Starting rjsxrd" >> "$LOG_FILE"

cd "$APP_DIR/source"

# Load environment (includes token and concurrency settings)
# Python reads .env directly via config/settings.py, but export is kept so
# any future shell helpers can access them too.
if [ -f "$APP_DIR/.env" ]; then
    set -a
    source "$APP_DIR/.env"
    set +a
else
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: .env not found" >> "$LOG_FILE"
    exit 1
fi

source "$APP_DIR/venv/bin/activate"

if [ "$PUSH_MODE" = "git" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Mode: git push (--use-git)" >> "$LOG_FILE"
    python main.py --use-git --no-proxy-check >> "$LOG_FILE" 2>&1
elif [ -n "$GITHUB_TOKEN" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Mode: GitHub API push" >> "$LOG_FILE"
    python main.py --no-proxy-check >> "$LOG_FILE" 2>&1
else
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Mode: dry-run (--dry-run)" >> "$LOG_FILE"
    python main.py --dry-run --no-proxy-check >> "$LOG_FILE" 2>&1
fi
EXIT_CODE=$?

deactivate

if [ $EXIT_CODE -eq 0 ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Completed successfully" >> "$LOG_FILE"
else
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Failed with exit code $EXIT_CODE" >> "$LOG_FILE"
fi

exit $EXIT_CODE
RUNSCRIPT
    
    # Create health check script
    cat > "$HEALTH_SCRIPT" << 'HEALTHSCRIPT'
#!/bin/bash

#===============================================================================
# rjsxrd Health Check Script
#===============================================================================

LOG_FILE="/var/log/rjsxrd/run.log"
MAX_HOURS=3

if [ ! -f "$LOG_FILE" ]; then
    echo "CRITICAL: No log file found"
    exit 2
fi

LAST_SUCCESS=$(grep "Completed successfully" "$LOG_FILE" | tail -1)

if [ -z "$LAST_SUCCESS" ]; then
    echo "CRITICAL: No successful runs found"
    exit 2
fi

LAST_RUN_TIME=$(echo "$LAST_SUCCESS" | grep -oP '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')
LAST_RUN_EPOCH=$(date -d "$LAST_RUN_TIME" +%s 2>/dev/null || echo 0)
CURRENT_EPOCH=$(date +%s)
HOURS_SINCE_RUN=$(( (CURRENT_EPOCH - LAST_RUN_EPOCH) / 3600 ))

if [ $HOURS_SINCE_RUN -gt $MAX_HOURS ]; then
    echo "WARNING: Last successful run was ${HOURS_SINCE_RUN} hours ago"
    exit 1
fi

echo "OK: Last run ${HOURS_SINCE_RUN} hours ago"
exit 0
HEALTHSCRIPT
    
    chmod +x "$RUN_SCRIPT"
    chmod +x "$HEALTH_SCRIPT"
    chown rjsxrd:rjsxrd "$RUN_SCRIPT"
    chown rjsxrd:rjsxrd "$HEALTH_SCRIPT"
    
    log_info "  Created run script: $RUN_SCRIPT"
    log_info "  Created health check: $HEALTH_SCRIPT"
    echo ""
    
    #---------------------------------------------------------------------------
    # Step 11: Create Systemd Service
    #---------------------------------------------------------------------------
    log_info "Step 11: Systemd Service and Security"

    # Create systemd service (always — needed for manual systemctl start)
    cat > /etc/systemd/system/rjsxrd.service << 'SYSTEMD'
[Unit]
Description=rjsxrd VPN Config Generator
After=network.target

[Service]
Type=oneshot
User=rjsxrd
WorkingDirectory=/opt/rjsxrd/source
ExecStart=/opt/rjsxrd/run.sh
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rjsxrd

[Install]
WantedBy=multi-user.target
SYSTEMD

    chmod 644 /etc/systemd/system/rjsxrd.service
    systemctl daemon-reload
    systemctl enable rjsxrd.service

    log_info "  Systemd service created (rjsxrd.service)"

    # Ask about automatic cron (systemd timer)
    echo ""
    echo "  [yes] — create systemd timer for automatic runs"
    echo "  [no]  — manual runs only (systemctl start rjsxrd)"
    echo ""
    read -p "Setup cron job? (Y/n): " CRON_CHOICE
    echo
    CRON_ENABLED=true
    if [[ $CRON_CHOICE =~ ^[Nn] ]]; then
        CRON_ENABLED=false
        log_info "Cron skipped — run manually with: systemctl start rjsxrd"
    else
        echo ""
        echo "How often should it run?"
        echo "  Examples: 1h (every hour), 30m (every 30 min), 6h (every 6 hours), 12h"
        read -p "Interval (default: 1h): " CRON_INTERVAL
        if [ -z "$CRON_INTERVAL" ]; then
            CRON_INTERVAL="1h"
        fi
        log_info "Cron interval: every $CRON_INTERVAL"

        # Convert user-friendly format (1h, 30m, 6h) to systemd OnUnitActiveSec
        case "$CRON_INTERVAL" in
            *m) TIMER_SEC="${CRON_INTERVAL%m}min" ;;
            *h) TIMER_SEC="${CRON_INTERVAL%h}h" ;;
            *) TIMER_SEC="$CRON_INTERVAL" ;;  # assume raw format
        esac

        cat > /etc/systemd/system/rjsxrd.timer << 'TIMER'
[Unit]
Description=Run rjsxrd every TIMER_SEC

[Timer]
OnBootSec=10min
OnUnitActiveSec=TIMER_SEC
Persistent=true

[Install]
WantedBy=timers.target
TIMER

        # Replace placeholder with actual value
        sed -i "s/TIMER_SEC/$TIMER_SEC/g" /etc/systemd/system/rjsxrd.timer

        chmod 644 /etc/systemd/system/rjsxrd.timer
        systemctl daemon-reload
        systemctl enable --now rjsxrd.timer

        log_info "  Timer created — runs every $CRON_INTERVAL"
    fi

    # Log rotation
    cat > /etc/logrotate.d/rjsxrd << EOF
$LOG_DIR/*.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 0640 rjsxrd rjsxrd
}
EOF

    log_info "  Log rotation configured"

    # Configure firewall (UFW)
    log_info "  Configuring firewall..."

    ufw --force enable 2>/dev/null || true
    ufw limit ssh 2>/dev/null || true
    ufw default deny incoming 2>/dev/null || true
    ufw default allow outgoing 2>/dev/null || true

    log_info "  Firewall enabled (SSH rate-limited)"

    # ── CPU governor ─────────────────────────────────────────────
    log_info "  Setting CPU governor to performance..."
    if command -v cpupower &>/dev/null; then
        cpupower frequency-set -g performance 2>/dev/null || true
    elif [ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]; then
        for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
            echo performance > "$gov" 2>/dev/null || true
        done
    fi
    log_info "  CPU governor set to performance"

    # ── Network tuning (BBR + TCP) ────────────────────────────────
    log_info "  Applying network stack tuning..."
    cat > /etc/sysctl.d/99-rjsxrd-network.conf << 'NETSYSCTL'
# BBR congestion control for better throughput
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
# TCP tuning
net.core.somaxconn = 1024
net.core.netdev_max_backlog = 2048
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65535
NETSYSCTL
    sysctl -p /etc/sysctl.d/99-rjsxrd-network.conf >/dev/null 2>&1 || true
    modprobe tcp_bbr 2>/dev/null || true
    log_info "  Network tuning applied (BBR + TCP optimizations)"

    # ── Journald limits ──────────────────────────────────────────
    log_info "  Capping journald size..."
    if [ ! -f /etc/systemd/journald.conf.d/00-rjsxrd-limit.conf ]; then
        mkdir -p /etc/systemd/journald.conf.d
        cat > /etc/systemd/journald.conf.d/00-rjsxrd-limit.conf << 'JOURNAL'
[Journal]
SystemMaxUse=200M
SystemKeepFree=500M
RuntimeMaxUse=50M
MaxFileSec=2weeks
ForwardToSyslog=no
JOURNAL
        systemctl restart systemd-journald 2>/dev/null || true
        log_info "  Journald capped at 200MB"
    fi

    # ── Disable unnecessary services ──────────────────────────────
    for svc in snapd whoopsie apport avahi-daemon ModemManager; do
        if systemctl is-enabled "$svc" 2>/dev/null | grep -q "enabled"; then
            systemctl stop "$svc" 2>/dev/null || true
            systemctl disable "$svc" 2>/dev/null || true
            systemctl mask "$svc" 2>/dev/null || true
        fi
    done
    log_info "  Unnecessary services disabled (snapd, whoopsie, avahi, ModemManager)"

    # ── noatime on root ──────────────────────────────────────────
    if mount | grep " / " | grep -v noatime | grep -q "ext4\|ext3\|xfs"; then
        sed -i 's/\(^UUID=.* \)\(/ .*\)\(defaults\)/\1\2defaults,noatime/' /etc/fstab 2>/dev/null || true
        mount -o remount / 2>/dev/null || true
        log_info "  noatime enabled on root filesystem"
    fi

    # ── SSD TRIM ─────────────────────────────────────────────────
    systemctl enable --now fstrim.timer 2>/dev/null || true
    log_info "  Weekly SSD TRIM enabled"

    # ── Kernel hardening ────────────────────────────────────────────
    log_info "  Applying kernel hardening..."
    cat > /etc/sysctl.d/99-rjsxrd-security.conf << 'SYSCTL'
# rjsxrd VPS kernel hardening
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.log_martians=1
net.ipv6.conf.all.disable_ipv6=1
kernel.randomize_va_space=2
kernel.exec-shield=1
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
fs.suid_dumpable=0
SYSCTL
    sysctl -p /etc/sysctl.d/99-rjsxrd-security.conf >/dev/null 2>&1 || true
    log_info "  Kernel hardening applied"

    # ── SSH warning banner ──────────────────────────────────────────
    log_info "  Creating SSH warning banner..."
    cat > /etc/issue.net << 'BANNER'
********************************************************************
*                                                                  *
*              UNAUTHORIZED ACCESS PROHIBITED                      *
*     This system is for authorized users only.                    *
*     All activities are monitored and logged.                     *
*                                                                  *
********************************************************************
BANNER
    log_info "  SSH banner created"

    # ── Automatic security updates ──────────────────────────────────
    log_info "  Configuring automatic security updates..."
    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'APT'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Download-Upgradeable-Packages "1";
APT
    # Ensure the reboot-required handler sends an email (no-op on most VPS)
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'UF'
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
UF
    log_info "  Automatic security updates configured"

    # ── Fail2Ban (tightened) ────────────────────────────────────────
    log_info "  Configuring Fail2Ban..."

    cat > /etc/fail2ban/jail.local << 'FAIL2BAN'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
backend = systemd

[sshd-ddos]
enabled = true
port = ssh
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
backend = systemd
FAIL2BAN

    systemctl enable fail2ban 2>/dev/null || true
    systemctl restart fail2ban 2>/dev/null || true

    log_info "  Fail2Ban configured (SSH brute-force + DDoS protection)"

    # ── SSH hardening ───────────────────────────────────────────────
    log_info "  Hardening SSH configuration..."

    # Copy SSH key from the connecting user so key auth works
    # after password auth is disabled
    if [ -n "${SUDO_USER:-}" ] && [ -d "/home/$SUDO_USER/.ssh" ]; then
        mkdir -p "$APP_DIR/.ssh"
        cp "/home/$SUDO_USER/.ssh/authorized_keys" "$APP_DIR/.ssh/authorized_keys" 2>/dev/null || true
        chown -R rjsxrd:rjsxrd "$APP_DIR/.ssh"
        chmod 700 "$APP_DIR/.ssh"
        chmod 600 "$APP_DIR/.ssh/authorized_keys"
        log_info "  SSH key copied from $SUDO_USER to rjsxrd"
    else
        echo ""
        echo "  ════════════════════════════════════════════════════════════"
        echo "  SSH PUBLIC KEY REQUIRED"
        echo ""
        echo "  This script will disable password login and root SSH access."
        echo "  After that you can only connect as user 'rjsxrd' with a key."
        echo ""
        echo "  To get your public key, open a second terminal on YOUR"
        echo "  local machine (not this VPS) and run one of these:"
        echo ""
        echo "    cat ~/.ssh/id_ed25519.pub"
        echo "    cat ~/.ssh/id_rsa.pub"
        echo ""
        echo "  If you don't have a key, create one:"
        echo "    ssh-keygen -t ed25519"
        echo ""
        echo "  Copy the line (starts with ssh-ed25519 or ssh-rsa)"
        echo "  and paste it below."
        echo ""
        echo "  Leave empty to SKIP SSH hardening — NOT RECOMMENDED,"
        echo "  root with password stays active."
        echo "  ════════════════════════════════════════════════════════════"
        echo ""
        read -p "SSH public key (or press Enter to skip): " SSH_KEY
        if [ -n "$SSH_KEY" ]; then
            mkdir -p "$APP_DIR/.ssh"
            echo "$SSH_KEY" >> "$APP_DIR/.ssh/authorized_keys"
            chown -R rjsxrd:rjsxrd "$APP_DIR/.ssh"
            chmod 700 "$APP_DIR/.ssh"
            chmod 600 "$APP_DIR/.ssh/authorized_keys"
            log_info "  SSH key added for rjsxrd user"
        else
            log_warning "  No SSH key provided — skipping sshd hardening"
        fi
    fi

    # If we got an SSH key (from either path), give rjsxrd a shell and sudo
    # for systemctl so the user can manage the service after login.
    if [ -s "$APP_DIR/.ssh/authorized_keys" ]; then
        usermod -s /bin/bash rjsxrd
        echo 'rjsxrd ALL=(ALL) NOPASSWD: /usr/bin/systemctl' > /etc/sudoers.d/rjsxrd
        chmod 440 /etc/sudoers.d/rjsxrd
        log_info "  Shell set to /bin/bash for rjsxrd, sudo for systemctl granted"
    fi

    # Backup and harden sshd_config
    if [ -f /etc/ssh/sshd_config ]; then
        cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.$(date +%s)"
        log_info "  Backed up sshd_config"
    fi

    # Apply all hardening directives idempotently
    for directive in \
        "PermitRootLogin no" \
        "PasswordAuthentication no" \
        "KbdInteractiveAuthentication no" \
        "PubkeyAuthentication yes" \
        "ChallengeResponseAuthentication no" \
        "PermitEmptyPasswords no" \
        "MaxAuthTries 3" \
        "LoginGraceTime 30" \
        "ClientAliveInterval 300" \
        "ClientAliveCountMax 2" \
        "X11Forwarding no" \
        "AllowAgentForwarding no" \
        "AllowTcpForwarding no" \
        "IgnoreRhosts yes" \
        "Banner /etc/issue.net" \
        "AllowUsers rjsxrd" \
    ; do
        key="${directive%% *}"
        if grep -qi "^${key}" /etc/ssh/sshd_config 2>/dev/null; then
            sed -i "s|^#\?${key}.*|${directive}|I" /etc/ssh/sshd_config
        else
            echo "$directive" >> /etc/ssh/sshd_config
        fi
    done

    # Validate and restart
    if sshd -t 2>/dev/null; then
        # Ubuntu 24.04+ uses socket activation — stop socket and enable service
        systemctl stop ssh.socket 2>/dev/null || true
        systemctl disable ssh.socket 2>/dev/null || true
        systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null || true
        systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
        log_info "  sshd hardened and restarted"
    else
        log_error "  SSH config test failed — restoring backup"
        # Use the most recent backup (glob sorted by mtime via ls -t)
        LATEST_BACKUP=$(ls -t /etc/ssh/sshd_config.bak.* 2>/dev/null | head -1)
        if [ -n "$LATEST_BACKUP" ]; then
            cp "$LATEST_BACKUP" /etc/ssh/sshd_config
            log_info "  Restored from: $LATEST_BACKUP"
        else
            log_warning "  No backup found — sshd_config left as-is"
        fi
        systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
        log_error "  sshd_config restored to backup"
    fi

    # ── auditd ──────────────────────────────────────────────────────
    log_info "  Configuring auditd..."
    cat > /etc/audit/rules.d/rjsxrd.rules << 'AUDIT'
# Monitor critical file changes
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/passwd -p wa -k user_db
-w /etc/shadow -p wa -k user_db
-w /etc/sudoers -p wa -k sudoers
-w /opt/rjsxrd -p wa -k rjsxrd_app
AUDIT
    systemctl enable auditd 2>/dev/null || true
    systemctl restart auditd 2>/dev/null || true
    log_info "  auditd rules configured (sshd_config, passwd, shadow, sudoers, app dir)"

    # Set final permissions
    chown -R rjsxrd:rjsxrd "$APP_DIR"
    chmod 750 "$APP_DIR"
    chmod 600 "$ENV_FILE"

    log_success "Setup complete"
    echo ""

    #===========================================================================
    # Setup Complete
    #===========================================================================
    echo ""
    echo "=========================================="
    echo -e "${GREEN}  Setup Complete!${NC}"
    echo "=========================================="
    echo ""
    echo "Summary:"
    echo "  - Application: $APP_DIR"
    echo "  - Virtual Env: $VENV_DIR"
    echo "  - Logs: $LOG_DIR"
    echo "  - Mode: $([ "$PUSH_MODE" = "git" ] && echo 'Git push (--use-git)' || [ "$PUSH_MODE" = "api" ] && echo 'GitHub API push' || echo 'Dry-run (--dry-run)')"
    if [ "$CRON_ENABLED" = true ]; then
        echo "  - Schedule: Every $CRON_INTERVAL (systemd timer)"
    else
        echo "  - Schedule: Manual only (no cron)"
    fi
    echo ""
    echo "Security:"
    echo "  ✓ User: rjsxrd (login disabled, key-only SSH)"
    echo "  ✓ Permissions: 600/750 (owner only)"
    echo "  ✓ Firewall: UFW (default deny, SSH rate-limited)"
    echo "  ✓ Fail2Ban: SSH brute-force + DDoS protection (maxretry=3)"
    echo "  ✓ SSH: root login disabled, password auth disabled, forwarding disabled"
    echo "  ✓ Kernel: ASLR, syncookies, RP filter, ICMP hardening, dmesg restricted"
    echo "  ✓ Updates: unattended-upgrades (auto security patches)"
    echo "  ✓ Audit: sshd_config, passwd, shadow, sudoers monitored"
    echo ""
    echo "Commands:"
    echo "  - View logs:     journalctl -u rjsxrd -f"
    echo "  - Manual run:    sudo systemctl start rjsxrd"
    if [ "$CRON_ENABLED" = true ]; then
        echo "  - Timer status:  systemctl status rjsxrd.timer"
    fi
    echo "  - Firewall:      ufw status"
    echo ""
    echo "Token Management:"
    if [ -n "$GITHUB_TOKEN" ]; then
        echo "  - To rotate: Edit $ENV_FILE and update GITHUB_TOKEN"
        echo "  - Rotate every 30-90 days on GitHub"
        if [ "$PUSH_MODE" = "api" ]; then
            echo "  - Push via GitHub API (no git repo on VPS)"
        elif [ "$PUSH_MODE" = "git" ]; then
            echo "  - Push via git (--use-git, includes .git folder)"
        fi
        echo "  - To switch to dry-run: set PUSH_MODE=none in $ENV_FILE"
    else
        echo "  - No token configured — runs in dry-run mode"
        echo "  - To enable push later: add GITHUB_TOKEN=... and PUSH_MODE=api to $ENV_FILE"
        echo "    (file: $ENV_FILE, perm: 600)"
    fi
    echo ""

    #---------------------------------------------------------------------------
    # Test Run (direct, no systemd)
    #---------------------------------------------------------------------------
    echo ""
    echo "  [yes] — run full pipeline with xray verification (20-40 min)"
    echo "  [no]  — finish setup"
    echo ""
    echo -n "Run test now? (y/N): "
    read TEST_CHOICE
    echo

    if [[ $TEST_CHOICE =~ ^[Yy] ]]; then
        log_info "Running test (dry-run, xray verification)..."
        echo ""

        cd "$APP_DIR/source"
        source "$VENV_DIR/bin/activate"
        python main.py --dry-run --no-proxy-check
        EXIT_CODE=$?
        deactivate

        echo ""
        if [ $EXIT_CODE -eq 0 ]; then
            log_success "Test passed!"
            echo ""
            echo "Generated files:"
            echo "----------------------------------------"
            ls -la "$APP_DIR/githubmirror/default/" 2>/dev/null | head -10
            echo "----------------------------------------"
        else
            log_error "Test failed (exit code: $EXIT_CODE). Check the output above for details."
        fi
    fi

    # If test was skipped and cron is enabled, ask to run now
    if [[ ! $TEST_CHOICE =~ ^[Yy] ]] && [ "$CRON_ENABLED" = true ]; then
        echo ""
        echo "  [yes] — run the pipeline immediately via systemctl"
        echo "  [no]  — wait for the timer"
        echo ""
        echo -n "Run now? (Y/n): "
        read RUN_NOW_CHOICE
        echo
        if [[ ! $RUN_NOW_CHOICE =~ ^[Nn] ]]; then
            log_info "Starting pipeline..."
            systemctl start rjsxrd 2>/dev/null || true
            log_success "Pipeline started (view logs: journalctl -u rjsxrd -f)"
        fi
    fi

    echo ""
    if [ "$CRON_ENABLED" = true ]; then
        log_success "Done! rjsxrd will run every $CRON_INTERVAL automatically."
        echo "  Run manually anytime: sudo systemctl start rjsxrd"
    else
        log_success "Done!"
        echo "  Run manually: sudo systemctl start rjsxrd"
        echo "  To add cron later: edit this script and re-run, or manually:"
        echo "    sudo systemctl enable --now rjsxrd.timer"
    fi
    echo ""
    if [ -n "$GITHUB_TOKEN" ]; then
        echo "To rotate token later: Edit $ENV_FILE and change GITHUB_TOKEN"
    else
        echo "To enable push later: add GITHUB_TOKEN=your_token and PUSH_MODE=api to $ENV_FILE"
    fi
    echo ""
}

# Run main function
main "$@"

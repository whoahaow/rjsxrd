"""Configuration settings for VPN config generator."""
import os
import re
from dotenv import load_dotenv, find_dotenv

# Load .env from project root (searches up from cwd)
# Must be before any os.environ.get() calls below
load_dotenv(find_dotenv(usecwd=True))

from utils.logger import log


# Lazy-load caches for file-based configuration
_SNI_DOMAINS_CACHE = None
_MANUAL_SERVERS_CACHE = None


def _validate_int_env(var_name: str, default: int, min_val: int, max_val: int) -> int:
    """Validate integer environment variable with bounds checking.
    
    Args:
        var_name: Environment variable name
        default: Default value if not set or invalid
        min_val: Minimum allowed value
        max_val: Maximum allowed value
        
    Returns:
        Validated integer value within bounds
    """
    try:
        value = int(os.environ.get(var_name, str(default)))
        if value < min_val or value > max_val:
            log(f"Warning: {var_name}={value} out of range [{min_val}, {max_val}], using {default}")
            return default
        return value
    except ValueError:
        log(f"Warning: Invalid {var_name}='{os.environ.get(var_name, '')}', using default {default}")
        return default


def _validate_github_token(token: str) -> str:
    """Validate GitHub token format.
    
    Args:
        token: GitHub token to validate
        
    Returns:
        Cleaned token or empty string if invalid
    """
    if not token:
        return ""
    
    # Strip whitespace
    token = token.strip()
    
    # Check for suspicious characters
    if '\n' in token or '\r' in token:
        log("Warning: GitHub token contains newline characters, cleaning...")
        token = token.replace('\n', '').replace('\r', '')
    
    # Basic format validation (GitHub tokens are alphanumeric with underscores/hyphens)
    if not re.match(r'^[a-zA-Z0-9_\-]+$', token):
        log("Warning: GitHub token has unexpected format (may contain invalid characters)")
    
    # Warn if token looks too short
    if len(token) < 10:
        log(f"Warning: GitHub token seems too short ({len(token)} chars)")
    
    return token


# Repository settings
GITHUB_TOKEN = _validate_github_token(
    os.environ.get("MY_TOKEN", "") or os.environ.get("GITHUB_TOKEN", "")
)
REPO_NAME = os.environ.get("REPO_NAME", "whoahaow/rjsxrd")

# Validate REPO_NAME format
if not re.match(r'^[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+$', REPO_NAME):
    log(f"Warning: REPO_NAME '{REPO_NAME}' has unexpected format (expected owner/repo)")

# URL sources — lazy-loaded from URLS.txt on first access
_URLS_CONFIG = None

def get_urls_config() -> tuple[list[str], list[str], list[str], list[str]]:
    """Parse URLS.txt once and cache results. Returns (URLS, URLS_EXTRA_BYPASS, URLS_YAML, TELEGRAM_PROXY_URLS)."""
    global _URLS_CONFIG
    if _URLS_CONFIG is None:
        _URLS_CONFIG = parse_urls_file()
    return _URLS_CONFIG


def __getattr__(name) -> list[str]:
    if name in ('URLS', 'URLS_EXTRA_BYPASS', 'URLS_YAML', 'TELEGRAM_PROXY_URLS'):
        (urls, extra, yaml, tg) = get_urls_config()
        mapping = {'URLS': urls, 'URLS_EXTRA_BYPASS': extra, 'URLS_YAML': yaml, 'TELEGRAM_PROXY_URLS': tg}
        return mapping[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

def parse_urls_file() -> tuple[list[str], list[str], list[str], list[str]]:
    """Parse URLS.txt file with section markers."""
    urls = []
    urls_extra_bypass = []
    urls_yaml = []
    telegram_proxy_urls = []
    
    config_dir = os.path.dirname(__file__)
    urls_file = os.path.join(config_dir, 'URLS.txt')
    
    current_section = 'default'  # Default section
    
    try:
        with open(urls_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                
                # Skip empty lines
                if not line:
                    continue
                
                # Check for section markers
                if line.startswith('# '):
                    section_name = line[2:].strip().lower()
                    if 'yaml' in section_name:
                        current_section = 'yaml'
                    elif 'telegram' in section_name or 'tg' in section_name:
                        current_section = 'telegram'
                    elif 'extra' in section_name or 'bypass' in section_name:
                        current_section = 'extra_bypass'
                    else:
                        current_section = 'default'
                    continue
                
                # Skip pure comment lines (not section markers)
                if line.startswith('#'):
                    continue
                
                # Add URL to current section
                if current_section == 'default':
                    urls.append(line)
                elif current_section == 'extra_bypass':
                    urls_extra_bypass.append(line)
                elif current_section == 'yaml':
                    urls_yaml.append(line)
                elif current_section == 'telegram':
                    telegram_proxy_urls.append(line)
                    
    except FileNotFoundError:
        log("URLS.txt file not found!")
    
    return urls, urls_extra_bypass, urls_yaml, telegram_proxy_urls


def get_manual_servers() -> list[str]:
    """Lazy-load manual server configs from servers.txt with caching."""
    global _MANUAL_SERVERS_CACHE
    if _MANUAL_SERVERS_CACHE is None:
        servers = []
        try:
            with open(os.path.join(os.path.dirname(__file__), 'servers.txt'), 'r', encoding='utf-8') as f:
                servers = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            log("servers.txt file not found!")
            servers = []
        _MANUAL_SERVERS_CACHE = servers
    return _MANUAL_SERVERS_CACHE


# Manual server configs from servers.txt — eager load for backward compat
MANUAL_SERVERS = get_manual_servers()

# Telegram proxy sources URLs — lazy-loaded via __getattr__ from URLS.txt (telegram section)

# SNI domains for filtering - Russian white-list bypass
def load_sni_domains() -> list[str]:
    """Load SNI domains from whitelist-all.txt file."""
    config_dir = os.path.dirname(__file__)  # Get the directory of the current file
    whitelist_path = os.path.join(config_dir, 'whitelist-all.txt')
    try:
        with open(whitelist_path, 'r', encoding='utf-8') as f:
            domains = [line.strip() for line in f if line.strip()]
        return domains
    except FileNotFoundError:
        log(f"whitelist-all.txt not found at {whitelist_path}, using empty list")
        return []

def get_sni_domains() -> list[str]:
    """Lazy-load SNI domains from whitelist-all.txt with caching."""
    global _SNI_DOMAINS_CACHE
    if _SNI_DOMAINS_CACHE is None:
        _SNI_DOMAINS_CACHE = load_sni_domains()
    return _SNI_DOMAINS_CACHE


SNI_DOMAINS = get_sni_domains()

# Other settings
DEFAULT_MAX_WORKERS = _validate_int_env("MAX_WORKERS", 50, 1, 200)
FETCH_TIMEOUT = _validate_int_env("FETCH_TIMEOUT", 5, 3, 30)
FETCH_MAX_ATTEMPTS = _validate_int_env("FETCH_MAX_ATTEMPTS", 3, 1, 5)

# Validation concurrency settings
VALIDATION_TCP_CONCURRENCY = _validate_int_env("VALIDATION_TCP_CONCURRENCY", 300, 10, 500)
VALIDATION_HTTP_CONCURRENCY = _validate_int_env("VALIDATION_HTTP_CONCURRENCY", 20, 5, 100)
VALIDATION_MAX_WORKERS = _validate_int_env("VALIDATION_MAX_WORKERS", 200, 50, 1000)

# Validation timeout settings (seconds)
VALIDATION_TCP_TIMEOUT = float(_validate_int_env("VALIDATION_TCP_TIMEOUT", 3, 1, 30))
VALIDATION_HTTP_TIMEOUT = float(_validate_int_env("VALIDATION_HTTP_TIMEOUT", 5, 2, 60))

# Test URL(s) for Xray ping verification.
# Comma-separated list. Default: single URL for speed.
# Other commonly-used test URLs (for reference):
#   https://www.google.com/generate_204
#   https://www.youtube.com/generate_204
#   https://cp.cloudflare.com/
#   http://www.msftconnecttest.com/connecttest.txt
_TEST_PING_URLS_RAW = os.environ.get("TEST_PING_URLS", "https://www.gstatic.com/generate_204")
TEST_PING_URLS = [u.strip() for u in _TEST_PING_URLS_RAW.split(",") if u.strip()]

# TLS fingerprint for Xray outbound connections.
# Options: chrome, firefox, safari, edge, randomized, iCloud, ...
TLS_FINGERPRINT = os.environ.get("TLS_FINGERPRINT", "chrome")

# TLS fragment (stealth) — splits TLS Client Hello into small TCP segments
# to evade Deep Packet Inspection. Enabled by default for better test reliability.
ENABLE_FRAGMENT = os.environ.get("ENABLE_FRAGMENT", "true").lower() in ("true", "1", "yes")
FRAGMENT_PACKETS = os.environ.get("FRAGMENT_PACKETS", "tlshello")
FRAGMENT_LENGTH = os.environ.get("FRAGMENT_LENGTH", "100-200")
FRAGMENT_INTERVAL = os.environ.get("FRAGMENT_INTERVAL", "10-20")

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/138.0.0.0 Safari/537.36"
)

# Daily date-rotating source patterns (used by daily_repo_fetcher)
# {YYYY}, {MM}, {DD}, {YYYYMMDD} are substituted with current/fallback dates
DAILY_DATE_PATTERNS = [
    # Original free-nodes repo
    "https://raw.githubusercontent.com/free-nodes/v2rayfree/refs/heads/main/v2{YYYYMMDD}1",
    "https://raw.githubusercontent.com/free-nodes/v2rayfree/refs/heads/main/v2{YYYYMMDD}2",
    # free.datiya.com — daily rotating subscriptions
    "https://free.datiya.com/uploads/{YYYYMMDD}-v2ray.txt",
    "https://free.datiya.com/uploads/{YYYYMMDD}-clash.yaml",
    # nodefree / oneclash — daily rotating Chinese sources
    "https://node.nodefree.me/{YYYY}/{MM}/{YYYYMMDD}.txt",
    "https://oss.oneclash.cc/{YYYY}/{MM}/{YYYYMMDD}.txt",
    # From Leon406 subpools dynamic section
    "https://nodefree.githubrowcontent.com/{YYYY}/{MM}/{YYYYMMDD}.txt",
    "https://v2rayshare.githubrowcontent.com/{YYYY}/{MM}/{YYYYMMDD}.txt",
    "https://node.freeclashnode.com/uploads/{YYYY}/{MM}/0-{YYYYMMDD}.txt",
    "https://node.freeclashnode.com/uploads/{YYYY}/{MM}/1-{YYYYMMDD}.txt",
    "https://node.freeclashnode.com/uploads/{YYYY}/{MM}/2-{YYYYMMDD}.txt",
    "https://node.freeclashnode.com/uploads/{YYYY}/{MM}/3-{YYYYMMDD}.txt",
    "https://node.freeclashnode.com/uploads/{YYYY}/{MM}/4-{YYYYMMDD}.txt",
    "https://a.nodeshare.xyz/uploads/{YYYY}/{M}/{YYYYMMDD}.txt",
]

# Async testing concurrency settings
# Windows has higher process overhead, so lower concurrency prevents system freeze
# Linux/WSL can handle higher concurrency but each xray process takes ~30-80MB RAM.
# 150 concurrent × 50MB ≈ 7.5GB peak. Use env vars to override:
#   ASYNC_CONCURRENCY_LINUX=100   YAML_HTTP_TIMEOUT=8   python3 main.py
ASYNC_CONCURRENCY_WIN32 = _validate_int_env("ASYNC_CONCURRENCY_WIN32", 50, 10, 500)
ASYNC_CONCURRENCY_LINUX = _validate_int_env("ASYNC_CONCURRENCY_LINUX", 300, 50, 1000)

# === Output generation flags ===
# Control which folders are created and uploaded.
# Set True to enable, False to skip.
ENABLE_DEFAULT_FILES = False   # default/ — 1.txt, 2.txt, all.txt, all-secure.txt
ENABLE_BYPASS_UNSECURE = False # bypass-unsecure/ — configs without security filtering
ENABLE_PROTOCOL_SPLIT = False  # split-by-protocols/ — per-protocol files
ENABLE_TG_PROXY = False        # tg-proxy/ — Telegram proxies (disabled by default)
PUBLISH_RAW_FILES = False      # /raw/ subfolders — untested configs before verification

# === File size limits ===
MAX_FILE_SIZE_MB = 49.0        # Max per-file before splitting (GitHub ~50MB limit)
MAX_CONFIGS_PER_FILE = 300     # Max configs per numbered file
MAX_NUMBERED_DEFAULT_FILES = 26  # Cap on numbered default/ files (1.txt, 2.txt, ...). Was hardcoded in create_numbered_default_files before 2026-06-16.

# === Xray-core port ranges (env-overridable) ===
XRAY_PORTS = {
    "base": _validate_int_env("XRAY_BASE_PORT", 20000, 1024, 65535),
    "batch_end": _validate_int_env("XRAY_BATCH_PORT_END", 21999, 1024, 65535),
    "chain_start": _validate_int_env("XRAY_CHAIN_PORT_START", 22000, 1024, 65535),
    "chain_end": _validate_int_env("XRAY_CHAIN_PORT_END", 23999, 1024, 65535),
    "persistent_start": _validate_int_env("XRAY_PERSISTENT_PORT_START", 24000, 1024, 65535),
}
XRAY_BASE_PORT = XRAY_PORTS["base"]
XRAY_BATCH_PORT_END = XRAY_PORTS["batch_end"]
XRAY_CHAIN_PORT_START = XRAY_PORTS["chain_start"]
XRAY_CHAIN_PORT_END = XRAY_PORTS["chain_end"]
XRAY_PERSISTENT_PORT_START = XRAY_PORTS["persistent_start"]
XRAY_PORT_MAX_ATTEMPTS = _validate_int_env("XRAY_PORT_MAX_ATTEMPTS", 10, 1, 100)

# === Xray process lifecycle (env-overridable) ===
# XRAY_STARTUP_TIMEOUT: max seconds to wait for xray to bind SOCKS port (default 3)
XRAY_LIFECYCLE = {
    "startup_timeout": float(_validate_int_env("XRAY_STARTUP_TIMEOUT", 3, 1, 30)),
    "kill_timeout": _validate_int_env("XRAY_PROCESS_KILL_TIMEOUT", 3, 1, 30),
    "force_kill_timeout": _validate_int_env("XRAY_PROCESS_FORCE_KILL_TIMEOUT", 2, 1, 15),
}
XRAY_STARTUP_TIMEOUT = XRAY_LIFECYCLE["startup_timeout"]
XRAY_PROCESS_KILL_TIMEOUT = XRAY_LIFECYCLE["kill_timeout"]
XRAY_PROCESS_FORCE_KILL_TIMEOUT = XRAY_LIFECYCLE["force_kill_timeout"]

# Memory-per-xray estimate for auto-limiting (MB per process)
# xray-core takes ~15-30MB idle, spikes to ~50MB during TLS handshake
_ESTIMATED_MEM_PER_XRAY_MB = 50

# === Validation concurrency ===
V2RAYN_MAX_CONCURRENCY = 1000  # Reference: v2rayN SpeedTestPageSize
MAX_SAFE_CONCURRENCY = 500     # Conservative cap to avoid resource exhaustion

# === Logging ===
LOG_TRUNCATE_LENGTH = 200
LOG_ERROR_SAMPLE_LENGTH = 1500
LOG_XRAY_ERROR_LENGTH = 3000
TEMP_FILE_PERMISSIONS = 0o600  # Owner read/write only

# === Proxy chain ===
MIN_CHAIN_HOPS = 2
CHAIN_TRANSPORT_WHITELIST = ["ws", "httpupgrade"]
CHAIN_SECURITY_REQUIRED = "tls"
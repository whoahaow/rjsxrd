"""Configuration settings for VPN config generator."""

import os
from datetime import datetime
import zoneinfo

# Repository settings
GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "whoahaow/rjsxrd"  # Updated repository name

# Time settings
ZONE = zoneinfo.ZoneInfo("Europe/Moscow")
THISTIME = datetime.now(ZONE)
OFFSET = THISTIME.strftime("%H:%M | %d.%m.%Y")

# URL sources
URLS = []
try:
    with open(os.path.join(os.path.dirname(__file__), 'URLS.txt'), 'r', encoding='utf-8') as f:
        URLS = [line.strip() for line in f if line.strip()]
except FileNotFoundError:
    print("URLS.txt file not found!")
    URLS = []  # Fallback to empty list
# SNI domains for filtering - Russian white-list bypass
def load_sni_domains():
    """Load SNI domains from whitelist-all.txt file."""
    config_dir = os.path.dirname(__file__)  # Get the directory of the current file
    whitelist_path = os.path.join(config_dir, 'whitelist-all.txt')
    try:
        with open(whitelist_path, 'r', encoding='utf-8') as f:
            domains = [line.strip() for line in f if line.strip()]
        return domains
    except FileNotFoundError:
        print(f"whitelist-all.txt not found at {whitelist_path}, using empty list")
        return []

SNI_DOMAINS = load_sni_domains()

# Split configuration
MAX_SERVERS_PER_FILE = 300

# Other settings
DEFAULT_MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "16"))
CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/138.0.0.0 Safari/537.36"
)
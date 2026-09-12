"""Scrapes VPN configs from sstap.org/node-real-time-update/ page."""

import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fetchers.fetcher import fetch_data
from utils.file_utils import prepare_config_content
from utils.logger import log

SSTAP_URL = "https://sstap.org/node-real-time-update/"

CONFIG_PATTERNS = [
    r'vless://[^\s<>"\'\\]+',
    r'vmess://[^\s<>"\'\\]+',
    r'ss://[^\s<>"\'\\]+',
    r'trojan://[^\s<>"\'\\]+',
    r'hysteria://[^\s<>"\'\\]+',
    r'hysteria2://[^\s<>"\'\\]+',
    r'hy2://[^\s<>"\'\\]+',
    r'tuic://[^\s<>"\'\\]+',
]


def scrape_sstap_configs() -> list[str]:
    result = fetch_data(SSTAP_URL, timeout=15)
    if not result.success:
        log(f"sstap.org fetch failed: {result.error}")
        return []

    raw_keys = []
    for pattern in CONFIG_PATTERNS:
        raw_keys.extend(re.findall(pattern, result.text))

    seen = set()
    unique = []
    for k in raw_keys:
        if k not in seen:
            seen.add(k)
            unique.append(k)

    configs = prepare_config_content("\n".join(unique))
    log(f"sstap.org: {len(configs)} configs scraped ({len(unique)} raw keys)")
    return configs

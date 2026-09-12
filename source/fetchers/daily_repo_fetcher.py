"""Module for fetching VPN configs from daily-updated repositories with date patterns."""

import base64
import concurrent.futures
import datetime
import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fetchers.fetcher import fetch_data
from utils.executor_cache import ExecutorCache
from utils.file_utils import prepare_config_content
from utils.logger import log


def _substitute_date_pattern(pattern: str, date: datetime.date) -> str:
    return pattern \
        .replace("{YYYY}", date.strftime("%Y")) \
        .replace("{MM}", date.strftime("%m")) \
        .replace("{M}", str(date.month)) \
        .replace("{DD}", date.strftime("%d")) \
        .replace("{YYYYMMDD}", date.strftime("%Y%m%d"))


def _is_yaml_url(url: str) -> bool:
    return url.endswith(('.yaml', '.yml'))


def _decode_if_base64(content: str) -> str:
    try:
        decoded_bytes = base64.b64decode(content.strip())
        decoded = decoded_bytes.decode('utf-8', errors='ignore')
        if any(p in decoded for p in ['vless://', 'vmess://', 'trojan://', 'ss://', 'ssr://', 'hysteria://', 'hy2://', 'tuic://']):
            return decoded
    except (ValueError, TypeError, UnicodeDecodeError):
        pass
    return content


def _fetch_single_url(url: str) -> tuple[str, list[str] | None]:
    result = fetch_data(url, timeout=7)
    if not result.success:
        return (url, None)

    content = result.text
    if not content.strip():
        return (url, None)

    if _is_yaml_url(url):
        from fetchers.yaml_converter import convert_yaml_to_vpn_configs
        configs = convert_yaml_to_vpn_configs(content)
        return (url, configs)

    decoded = _decode_if_base64(content)
    configs = prepare_config_content(decoded if decoded != content else content)

    if configs:
        return (url, configs)
    return (url, None)


def generate_dated_urls(patterns: list[str], date: datetime.date) -> list[str]:
    return [_substitute_date_pattern(p, date) for p in patterns]


# Quoted: threading.Lock is a factory function before Python 3.13, so the
# PEP 604 union is not runtime-evaluable at function-definition time.
def fetch_configs_from_daily_repo(
    patterns: list[str],
    lookback_days: int = 7,
    max_workers: int = 100,
    seen: set | None = None,
    seen_lock: "threading.Lock | None" = None,
) -> list[str]:
    today = datetime.date.today()
    dates_to_try = [today, today + datetime.timedelta(days=1)]
    dates_to_try.extend(today - datetime.timedelta(days=i) for i in range(1, lookback_days + 1))

    all_urls = [u for d in dates_to_try for u in generate_dated_urls(patterns, d)]
    log(f"Fetching {len(all_urls)} URLs from {len(patterns)} patterns across {len(dates_to_try)} dates ({max_workers} workers)...")

    all_configs = []
    executor = ExecutorCache.get('daily_repo_fetch', max_workers=max_workers)
    future_to_url = {executor.submit(_fetch_single_url, url): url for url in all_urls}
    for future in concurrent.futures.as_completed(future_to_url):
        _, configs = future.result()
        if configs:
            # Global dedup at fetch time — same upstream content returned
            # across multiple dates (yesterday + day before) won't inflate.
            if seen is not None and seen_lock is not None:
                unique = []
                with seen_lock:
                    for cfg in configs:
                        if cfg and cfg not in seen:
                            seen.add(cfg)
                            unique.append(cfg)
                all_configs.extend(unique)
            else:
                all_configs.extend(configs)

    log(f"Daily repos complete: {len(all_configs)} configs")
    return all_configs

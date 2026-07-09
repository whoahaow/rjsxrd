"""Config processing module — pipeline orchestration.

Core of the config generation pipeline. Defines ConfigPipeline (11 named stages)
and process_all_configs() entry point. Helper utilities (base64 decode, dedup,
flag resolution, path building) live in utils/config_helpers.py.
"""
from __future__ import annotations
import os
import sys
import time
import gc
import concurrent.futures
import base64
import re
import glob
from typing import List, Tuple, Optional, Dict, Callable
import threading
from collections import defaultdict
import math
from typing import Any

from utils.config_helpers import (
    natural_sort_key, resolve_flag, add_unique,
    path_in_output, try_decode_base64_content,
)
from utils.config_tagger import ConfigTagger
from config.settings import (URLS, URLS_EXTRA_BYPASS, URLS_YAML, MANUAL_SERVERS,
    DEFAULT_MAX_WORKERS, TELEGRAM_PROXY_URLS,
    VALIDATION_TCP_TIMEOUT, VALIDATION_HTTP_TIMEOUT, DAILY_DATE_PATTERNS,
    ENABLE_DEFAULT_FILES, ENABLE_BYPASS_UNSECURE, ENABLE_PROTOCOL_SPLIT,
    ENABLE_TG_PROXY, PUBLISH_RAW_FILES,
    MAX_FILE_SIZE_MB, MAX_CONFIGS_PER_FILE, MAX_NUMBERED_DEFAULT_FILES,
    GITHUB_TOKEN)
from fetchers.fetcher import fetch_data
from fetchers.daily_repo_fetcher import fetch_configs_from_daily_repo
from fetchers.sstap_scraper import scrape_sstap_configs
from fetchers.upstream_aggregator import fetch_upstream_dynamic_configs
from utils.file_utils import (prepare_config_content,
    apply_sni_cidr_filter, split_and_replace_file as split_file_by_size)
from utils.security_filter import filter_secure_configs, has_insecure_setting
from utils.logger import log
from utils.url_stats import URLStats
from utils.executor_cache import ExecutorCache
from utils.file_writer import (
    get_subscription_header, write_configs_file, stream_write_configs_file,
    _write_config_chunk, split_configs_to_files, append_remark_suffix,
    _write_numbered_file, create_numbered_default_files, _write_protocol_file,
)
from utils.bypass_builder import create_working_config_files


def _fetch_and_process_urls(
    urls: List[str],
    *,
    target_all: List[str],
    target_extra: List[str],
    numbered_configs_with_urls: List[Tuple[List[str], str]],
    all_mtproto: List[str],
    all_socks5: List[str],
    global_seen: set,
    global_seen_lock: threading.Lock,
    stats: Optional[URLStats],
    scraper: Optional[Any],
    yaml_converter=None,
    label: str = "URLs",
    add_to_all: bool = True,
    add_to_extra: bool = False,
    tagger=None,
    token: Optional[str] = None,
) -> None:
    """Fetch URLs in parallel, dedup in-memory (set), dispatch to lists.

    NOTE: This function mutates its collector arguments in place:
      - target_all / target_extra — extended with new unique configs
      - numbered_configs_with_urls — appended (configs, label) tuples
      - all_mtproto / all_socks5 — extended with Telegram proxies
      - global_seen — populated with seen config hashes for dedup

    Returns None — all results communicated via mutation.

    Args:
        urls: URLs to fetch
        token: Optional Bearer token for GitHub-authenticated requests.
    """
    if not urls:
        return
    log(f"Fetching {len(urls)} {label} in parallel...")
    executor = ExecutorCache.get('url_fetch', max_workers=min(DEFAULT_MAX_WORKERS, max(1, len(urls))))
    future_to_url = {executor.submit(fetch_data, url, token=token): url for url in urls}
    for future in concurrent.futures.as_completed(future_to_url):
        result = future.result()
        corresponding_url = future_to_url[future]
        if stats:
            stats.record_fetch(corresponding_url, result.success, result.status_code, result.error)

        if not result.success:
            log(f"Failed fetch {corresponding_url[:80]}: {result.error[:80]}")
            continue

        if yaml_converter is not None:
            vpn_configs = yaml_converter(result.text)
            configs = vpn_configs if vpn_configs else []
        else:
            configs = prepare_config_content(result.text)
            if not configs:
                decoded_content = try_decode_base64_content(result.text)
                if decoded_content:
                    log(f"Auto-detected base64 format for {corresponding_url[:80]}...")
                    configs = prepare_config_content(decoded_content)

        unique_configs: List[str] = []
        added = add_unique(configs, unique_configs, global_seen, global_seen_lock)
        if added < len(configs):
            log(f"  {corresponding_url[:60]}: {added}/{len(configs)} new (rest already seen)")

        if stats:
            stats.record_config_yield(corresponding_url, raw=len(unique_configs))

        if not unique_configs:
            result.text = ""
            continue

        if tagger is not None:
            source_label = label if label == corresponding_url else f"{label}:{corresponding_url[:60]}"
            tagger.tag_batch(unique_configs, source=source_label)

        if add_to_all:
            target_all.extend(unique_configs)
        if add_to_extra:
            target_extra.extend(unique_configs)
        numbered_configs_with_urls.append((unique_configs, corresponding_url))

        if scraper:
            try:
                mtproto, socks5 = scraper.extract_proxies(result.text)
                all_mtproto.extend(mtproto)
                all_socks5.extend(socks5)
            except (ValueError, TypeError, IndexError) as e:
                log(f"  telegram scrape failed for {corresponding_url[:60]}: {type(e).__name__}: {str(e)[:80]}")

        result.text = ""


def download_all_configs(output_dir: str = "../githubmirror",
                         scan_for_telegram_proxies: bool = False,
                         stats: Optional[URLStats] = None,
                         flag_overrides: Optional[dict] = None,
                         tagger=None) -> Tuple[List[str], List[str], List[Tuple[List[str], str]], List[str], List[str], float]:
    """Downloads all configs from all sources into in-memory lists."""
    fetch_start_time = time.time()
    all_configs = []
    extra_bypass_configs = []
    numbered_configs_with_urls = []
    all_mtproto_proxies = []
    all_socks5_proxies = []

    global_seen: set = set()
    global_seen_lock = threading.Lock()

    os.makedirs(path_in_output(output_dir, "bypass"), exist_ok=True)
    os.makedirs("../qr-codes", exist_ok=True)
    if resolve_flag('ENABLE_DEFAULT_FILES', flag_overrides, ENABLE_DEFAULT_FILES):
        os.makedirs(path_in_output(output_dir, "default"), exist_ok=True)
    if resolve_flag('ENABLE_BYPASS_UNSECURE', flag_overrides, ENABLE_BYPASS_UNSECURE):
        os.makedirs(path_in_output(output_dir, "bypass-unsecure"), exist_ok=True)
    if resolve_flag('ENABLE_PROTOCOL_SPLIT', flag_overrides, ENABLE_PROTOCOL_SPLIT):
        os.makedirs(path_in_output(output_dir, "split-by-protocols"), exist_ok=True)
    if resolve_flag('ENABLE_TG_PROXY', flag_overrides, ENABLE_TG_PROXY):
        os.makedirs(path_in_output(output_dir, "tg-proxy"), exist_ok=True)

    from fetchers.telegram_proxy_scraper import TelegramProxyScraper
    scraper = TelegramProxyScraper() if scan_for_telegram_proxies else None

    # Prepare GitHub token for authenticated requests (reduces rate limiting)
    _fetch_token = GITHUB_TOKEN if GITHUB_TOKEN else None

    _fetch_and_process_urls(
        URLS, target_all=all_configs, target_extra=extra_bypass_configs,
        numbered_configs_with_urls=numbered_configs_with_urls,
        all_mtproto=all_mtproto_proxies, all_socks5=all_socks5_proxies,
        global_seen=global_seen, global_seen_lock=global_seen_lock,
        stats=stats, scraper=scraper, label="URLs",
        add_to_all=True, add_to_extra=False, tagger=tagger,
        token=_fetch_token)

    _fetch_and_process_urls(
        URLS_EXTRA_BYPASS, target_all=all_configs, target_extra=extra_bypass_configs,
        numbered_configs_with_urls=numbered_configs_with_urls,
        all_mtproto=all_mtproto_proxies, all_socks5=all_socks5_proxies,
        global_seen=global_seen, global_seen_lock=global_seen_lock,
        stats=stats, scraper=scraper, label="extra bypass URLs",
        add_to_all=False, add_to_extra=True, tagger=tagger,
        token=_fetch_token)

    if URLS_YAML:
        from fetchers.yaml_converter import convert_yaml_to_vpn_configs
        _fetch_and_process_urls(
            URLS_YAML, target_all=all_configs, target_extra=extra_bypass_configs,
            numbered_configs_with_urls=numbered_configs_with_urls,
            all_mtproto=all_mtproto_proxies, all_socks5=all_socks5_proxies,
            global_seen=global_seen, global_seen_lock=global_seen_lock,
            stats=stats, scraper=scraper,
            yaml_converter=convert_yaml_to_vpn_configs, label="YAML URLs",
            add_to_all=True, add_to_extra=False, tagger=tagger,
            token=_fetch_token)

    try:
        daily_configs = fetch_configs_from_daily_repo(patterns=DAILY_DATE_PATTERNS, seen=global_seen, seen_lock=global_seen_lock)
        if daily_configs:
            all_configs.extend(daily_configs)
            numbered_configs_with_urls.append((daily_configs, "DAILY_REPO"))
            if tagger is not None:
                tagger.tag_batch(daily_configs, source="DAILY_REPO")
            log(f"Downloaded {len(daily_configs)} configs from daily-updated repository")
        if scraper and daily_configs:
            try:
                daily_content = "\n".join(daily_configs)
                mtproto, socks5 = scraper.extract_proxies(daily_content)
                all_mtproto_proxies.extend(mtproto)
                all_socks5_proxies.extend(socks5)
            except (ValueError, TypeError, IndexError):
                pass
    except (OSError, ValueError) as e:
        log(f"Error downloading from daily-updated repository: {str(e)[:200]}...")

    try:
        sstap_configs = scrape_sstap_configs()
        if sstap_configs:
            unique_configs = []
            add_unique(sstap_configs, unique_configs, global_seen, global_seen_lock)
            if unique_configs:
                all_configs.extend(unique_configs)
                numbered_configs_with_urls.append((unique_configs, "SSTAP_ORG"))
                if tagger is not None:
                    tagger.tag_batch(unique_configs, source="SSTAP_ORG")
    except (OSError, ValueError) as e:
        log(f"Error scraping sstap.org: {str(e)[:200]}...")

    try:
        upstream_configs = fetch_upstream_dynamic_configs(seen=global_seen, seen_lock=global_seen_lock)
        if upstream_configs:
            all_configs.extend(upstream_configs)
            numbered_configs_with_urls.append((upstream_configs, "UPSTREAM_AGGREGATOR"))
            if tagger is not None:
                tagger.tag_batch(upstream_configs, source="UPSTREAM_AGGREGATOR")
    except (OSError, ValueError) as e:
        log(f"Error fetching upstream dynamic configs: {str(e)[:200]}...")

    if MANUAL_SERVERS:
        manual_configs = prepare_config_content("\n".join(MANUAL_SERVERS))
        unique_configs = []
        add_unique(manual_configs, unique_configs, global_seen, global_seen_lock)
        if unique_configs:
            all_configs.extend(unique_configs)
            numbered_configs_with_urls.append((unique_configs, "MANUAL_SERVERS"))
            if tagger is not None:
                tagger.tag_batch(unique_configs, source="MANUAL_SERVERS")
            log(f"Added {len(unique_configs)} manual configs from servers.txt")

    # Free global_seen — no longer needed after download
    del global_seen, global_seen_lock

    total_downloaded = sum(len(cfgs) for cfgs, _ in numbered_configs_with_urls)
    fetch_elapsed = time.time() - fetch_start_time
    log(f"DOWNLOAD COMPLETE: {total_downloaded} configs from {len(numbered_configs_with_urls)} sources in {fetch_elapsed:.2f}s")

    if scan_for_telegram_proxies:
        all_mtproto_proxies = scraper.deduplicate_proxies(all_mtproto_proxies)
        all_socks5_proxies = scraper.deduplicate_proxies(all_socks5_proxies)
        log(f"Scanned URLs for Telegram proxies: {len(all_mtproto_proxies)} MTProto, {len(all_socks5_proxies)} SOCKS5")
        return all_configs, extra_bypass_configs, numbered_configs_with_urls, all_mtproto_proxies, all_socks5_proxies, fetch_elapsed
    else:
        return all_configs, extra_bypass_configs, numbered_configs_with_urls, all_mtproto_proxies, all_socks5_proxies, fetch_elapsed


def _write_subscription_file(configs: List[str], label: str, output_dir: str = "../githubmirror", max_size_mb: float = 49.0) -> List[str]:
    """Write a subscription file (all.txt / all-secure.txt), splitting if oversized.

    Args:
        configs: Configs to write.
        label: File label — used for filename ("all", "all-secure") and header.
        output_dir: Base output directory.
        max_size_mb: Max file size before splitting.

    Returns:
        List of created file paths.
    """
    filepath = path_in_output(output_dir, "default", f"{label}.txt")
    estimated_size = sum(len(cfg) + 1 for cfg in configs)
    max_size_bytes = int(max_size_mb * 1024 * 1024)
    if estimated_size > max_size_bytes:
        log(f"Estimated size ({estimated_size / (1024*1024):.2f} MB) exceeds limit, splitting directly")
        num_files_needed = math.ceil(estimated_size / max_size_bytes)
        max_cfg_per_file = max(1, len(configs) // num_files_needed)
        return split_configs_to_files(configs, path_in_output(output_dir, "default"), label, max_configs_per_file=max_cfg_per_file)
    try:
        header = get_subscription_header(label, config_count=len(configs))
        write_configs_file(filepath, configs, header)
        log(f"Created {filepath} with {len(configs)} unique configs ({label})")
        return split_file_by_size(filepath, max_size_mb)
    except OSError as e:
        log(f"Error creating {label}.txt: {e}")
        return []


def create_all_configs_file(all_configs: List[str], output_dir: str = "../githubmirror", max_size_mb: float = 49.0) -> List[str]:
    """Creates the all.txt file with all unique configs. Splits if file exceeds size limit."""
    return _write_subscription_file(all_configs, "all", output_dir, max_size_mb)


def create_secure_configs_file(all_configs: List[str], output_dir: str = "../githubmirror", max_size_mb: float = 49.0) -> List[str]:
    """Creates the all-secure.txt file with only secure configs. Splits if file exceeds size limit."""
    secure_configs = filter_secure_configs(all_configs)
    return _write_subscription_file(secure_configs, "all-secure", output_dir, max_size_mb)


def create_protocol_split_files(all_configs: List[str], output_dir: str = '../githubmirror',
                                 max_size_mb: float = 49.0) -> List[Tuple[str, str]]:
    '''Creates protocol-specific files in the split-by-protocols folder, both secure and unsecure versions.'''
    from utils.file_utils import SUPPORTED_PROTOCOLS
    protocols = list(SUPPORTED_PROTOCOLS)
    protocol_set = frozenset(protocols)
    protocol_configs: dict = {protocol: [] for protocol in protocols}
    protocol_secure_configs: dict = {protocol: [] for protocol in protocols}
    for config in all_configs:
        sep_idx = config.find('://')
        if sep_idx <= 0:
            continue
        scheme = config[:sep_idx].lower()
        if scheme not in protocol_set:
            continue
        protocol_configs[scheme].append(config)
        if not has_insecure_setting(config):
            protocol_secure_configs[scheme].append(config)

    write_tasks = []
    for protocol, configs in protocol_configs.items():
        if configs:
            write_tasks.append((protocol, configs, output_dir, max_size_mb, False))
    for protocol, configs in protocol_secure_configs.items():
        if configs:
            write_tasks.append((protocol, configs, output_dir, max_size_mb, True))

    all_file_pairs = []
    executor = ExecutorCache.get('write_tasks', max_workers=min(8, len(write_tasks)))
    results = list(executor.map(_write_protocol_file, write_tasks))
    for file_pairs in results:
        all_file_pairs.extend(file_pairs)
    return all_file_pairs


class ConfigPipeline:
    """Orchestrates the full config generation pipeline as named stages."""

    def __init__(self, output_dir: str = "../githubmirror",
                 skip_xray: bool = False,
                 tcp_ping: bool = False,
                 verbose: bool = False,
                 flag_overrides: Optional[dict] = None,
                 upload_fn: Optional[Callable[[str, str], None]] = None) -> None:
        self.output_dir = output_dir
        self.skip_xray = skip_xray
        self.tcp_ping = tcp_ping
        self.verbose = verbose
        self.flag_overrides = flag_overrides
        self.upload_fn = upload_fn

        self.enable_default_files = resolve_flag('ENABLE_DEFAULT_FILES', flag_overrides, ENABLE_DEFAULT_FILES)
        self.enable_bypass_unsecure = resolve_flag('ENABLE_BYPASS_UNSECURE', flag_overrides, ENABLE_BYPASS_UNSECURE)
        self.enable_protocol_split = resolve_flag('ENABLE_PROTOCOL_SPLIT', flag_overrides, ENABLE_PROTOCOL_SPLIT)
        self.enable_tg_proxy = resolve_flag('ENABLE_TG_PROXY', flag_overrides, ENABLE_TG_PROXY)
        self.publish_raw_files = resolve_flag('PUBLISH_RAW_FILES', flag_overrides, PUBLISH_RAW_FILES)

        self.stats = URLStats()
        self.timing: Dict[str, float] = {}
        self.file_pairs: List[Tuple[str, str]] = []
        self.config_to_sources: Optional[Dict[str, List[str]]] = None

        # In-memory storage (freed before verification)
        self.all_configs: List[str] = []
        self.extra_bypass_configs: List[str] = []
        self.numbered_configs_with_urls: List[Tuple[List[str], str]] = []
        self.mtproto_proxies: List[str] = []
        self.socks5_proxies: List[str] = []
        self._sni_cidr_filtered: List[str] = []
        self._tagger = ConfigTagger()

    def stage_download(self) -> float:
        """Download configs from all sources + scan for Telegram proxies."""
        log("Downloading all configs from all sources (with Telegram proxy scanning)...")
        start = time.time()
        result = download_all_configs(
            self.output_dir, scan_for_telegram_proxies=True,
            stats=self.stats, flag_overrides=self.flag_overrides,
            tagger=self._tagger)
        (self.all_configs, self.extra_bypass_configs,
         self.numbered_configs_with_urls,
         self.mtproto_proxies, self.socks5_proxies, fetch_elapsed) = result
        elapsed = time.time() - start
        log(f"Downloaded {len(self.all_configs)} total configs, "
            f"{len(self.extra_bypass_configs)} extra bypass configs, "
            f"and {len(self.numbered_configs_with_urls)} sources for numbered files")
        log(f"Found {len(self.mtproto_proxies)} MTProto and "
            f"{len(self.socks5_proxies)} SOCKS5 Telegram proxies during download")
        return elapsed

    def stage_default_files(self) -> float:
        """Create numbered default files + all.txt + all-secure.txt."""
        if not self.enable_default_files:
            return 0.0
        log("Creating numbered default files...")
        self.numbered_default_files = create_numbered_default_files(
            self.numbered_configs_with_urls, self.output_dir)
        log("Creating all.txt file...")
        s = time.time()
        self.all_txt_files = create_all_configs_file(self.all_configs, self.output_dir)
        all_txt_elapsed = time.time() - s
        log("Creating all-secure.txt file...")
        s = time.time()
        self.all_secure_txt_files = create_secure_configs_file(self.all_configs, self.output_dir)
        all_secure_elapsed = time.time() - s
        return all_txt_elapsed + all_secure_elapsed

    def stage_bypass_raw(self) -> float:
        """Apply SNI/CIDR + security filter, write bypass raw files."""
        log("Creating bypass raw file...")
        start = time.time()
        manual_server_configs = []
        for _cfgs, _src in self.numbered_configs_with_urls:
            if _src == "MANUAL_SERVERS":
                manual_server_configs = list(_cfgs)
        log("Applying SNI/CIDR filter to main configs...")
        try:
            sni_cidr_filtered = apply_sni_cidr_filter(self.all_configs, filter_secure=False)
            if manual_server_configs:
                sni_cidr_set = set(sni_cidr_filtered)
                for cfg in manual_server_configs:
                    if cfg not in sni_cidr_set:
                        sni_cidr_filtered.append(cfg)
            log(f"SNI/CIDR filtered main configs: {len(sni_cidr_filtered)}")
            log(f"Adding {len(self.extra_bypass_configs)} extra bypass configs...")
            all_bypass = sni_cidr_filtered + self.extra_bypass_configs
            log("Filtering secure bypass configs...")
            self.secure_bypass = filter_secure_configs(all_bypass)
            log(f"Secure bypass configs: {len(self.secure_bypass)}")
        except (OSError, ValueError, RuntimeError) as e:
            log(f"Error in SNI/CIDR filter or secure filtering: {e}")
            self.secure_bypass = []
            sni_cidr_filtered = []
            self._sni_cidr_filtered = []
            return time.time() - start
        for configs, source_url in self.numbered_configs_with_urls:
            source_secure = filter_secure_configs(configs)
            self.stats.record_config_yield(source_url, raw=len(configs), secure=len(source_secure))
        bypass_raw_path = path_in_output(self.output_dir, "bypass", "raw", "bypass-all-raw.txt")
        try:
            header = get_subscription_header("bypass-all-raw", config_count=len(self.secure_bypass))
            log(f"Writing bypass raw file ({len(self.secure_bypass)} configs)...")
            stream_write_configs_file(bypass_raw_path, self.secure_bypass, header, add_suffix=False)
            log(f"Created {bypass_raw_path} with {len(self.secure_bypass)} unique secure bypass configs")
            self.bypass_raw_files = split_file_by_size(bypass_raw_path, max_size_mb=MAX_FILE_SIZE_MB)
        except OSError as e:
            log(f"Error creating bypass-all-raw.txt: {e}")
            self.bypass_raw_files = []
        self._sni_cidr_filtered = sni_cidr_filtered
        return time.time() - start

    def stage_bypass_unsecure_raw(self) -> float:
        """Create bypass-unsecure raw files (gated by enable_bypass_unsecure)."""
        if not self.enable_bypass_unsecure:
            self.bypass_unsecure_raw_files = []
            return 0.0
        log("Creating bypass-unsecure raw file...")
        start = time.time()
        all_unsecure = self._sni_cidr_filtered + self.extra_bypass_configs
        log(f"Total bypass-unsecure configs: {len(all_unsecure)}")
        unsecure_path = path_in_output(self.output_dir, "bypass-unsecure", "raw", "bypass-unsecure-all-raw.txt")
        try:
            header = get_subscription_header("bypass-unsecure-all-raw", config_count=len(all_unsecure))
            stream_write_configs_file(unsecure_path, all_unsecure, header, add_suffix=False)
            log(f"Created {unsecure_path} with {len(all_unsecure)} configs")
            self.bypass_unsecure_raw_files = split_file_by_size(unsecure_path, max_size_mb=MAX_FILE_SIZE_MB)
        except OSError as e:
            log(f"Error creating bypass-unsecure-all-raw.txt: {e}")
            self.bypass_unsecure_raw_files = []
        return time.time() - start

    def stage_protocol_split(self) -> float:
        """Split configs by protocol (gated by enable_protocol_split)."""
        if not self.enable_protocol_split:
            self.protocol_files = []
            return 0.0
        log("Creating protocol-specific files...")
        all_protocol = self.all_configs + self.extra_bypass_configs
        self.protocol_files = create_protocol_split_files(all_protocol, self.output_dir)
        return 0.0

    def stage_telegram_proxy(self) -> float:
        """Process and verify Telegram proxies (gated by enable_tg_proxy)."""
        if not self.enable_tg_proxy:
            self.telegram_proxy_files = []
            return 0.0
        log("Processing Telegram proxies...")
        start = time.time()
        try:
            processor = TelegramProxyProcessor(self.output_dir)
            manual_mtproto, manual_socks5 = processor.load_manual_proxies()
            if manual_mtproto:
                self.mtproto_proxies = list(set(self.mtproto_proxies + manual_mtproto))
            if manual_socks5:
                self.socks5_proxies = list(set(self.socks5_proxies + manual_socks5))
            if TELEGRAM_PROXY_URLS:
                tg_mtproto, tg_socks5 = processor.scan_urls_for_proxies(TELEGRAM_PROXY_URLS)
                if tg_mtproto:
                    self.mtproto_proxies = list(set(self.mtproto_proxies + tg_mtproto))
                if tg_socks5:
                    self.socks5_proxies = list(set(self.socks5_proxies + tg_socks5))
            self.telegram_proxy_files = processor.create_proxy_files(
                self.mtproto_proxies, self.socks5_proxies,
                verify_mtproto=True, verify_socks5=True, max_workers=200)
        except (OSError, ValueError, RuntimeError) as e:
            log(f"Error processing Telegram proxies: {e}")
            self.telegram_proxy_files = []
        return time.time() - start

    def stage_build_file_pairs(self) -> None:
        """Collect all output files into self.file_pairs for upload."""
        self.file_pairs = []
        if self.enable_default_files:
            for f in self.numbered_default_files:
                self.file_pairs.append((f, f"githubmirror/default/{os.path.basename(f)}"))
            for f in self.all_txt_files:
                if f:
                    self.file_pairs.append((f, f"githubmirror/default/{os.path.basename(f)}"))
            for f in self.all_secure_txt_files:
                if f:
                    self.file_pairs.append((f, f"githubmirror/default/{os.path.basename(f)}"))
        if self.publish_raw_files:
            for f in self.bypass_raw_files:
                if f:
                    self.file_pairs.append((f, f"githubmirror/bypass/raw/{os.path.basename(f)}"))
        if self.enable_bypass_unsecure and self.publish_raw_files:
            for f in self.bypass_unsecure_raw_files:
                if f:
                    self.file_pairs.append((f, f"githubmirror/bypass-unsecure/raw/{os.path.basename(f)}"))
        if self.enable_protocol_split:
            self.file_pairs.extend(self.protocol_files)
        if self.enable_tg_proxy:
            for f in self.telegram_proxy_files:
                self.file_pairs.append((f, f"githubmirror/tg-proxy/{os.path.basename(f)}"))

    def stage_build_config_sources(self) -> None:
        """Build config→sources mapping for verification stats."""
        self.config_to_sources = defaultdict(list)
        for configs, source_url in self.numbered_configs_with_urls:
            for cfg in configs:
                self.config_to_sources[cfg].append(source_url)

    def stage_verify(self) -> float:
        """Run Xray or TCP verification on bypass configs."""
        if self.skip_xray and not self.tcp_ping:
            log("Skipping config verification (--skip-xray)")
            self.verified_bypass_files = []
            self.verified_bypass_unsecure_files = []
            return 0.0
        mode = "TCP ping" if self.tcp_ping else "Xray"
        log(f"Creating verified working config files ({mode} mode)...")
        start = time.time()
        if not self.enable_bypass_unsecure:
            unsecure_raw_dir = path_in_output(self.output_dir, "bypass-unsecure", "raw")
            if os.path.isdir(unsecure_raw_dir):
                import shutil
                shutil.rmtree(unsecure_raw_dir, ignore_errors=True)
        self.verified_bypass_files, self.verified_bypass_unsecure_files = create_working_config_files(
            self.output_dir, tcp_ping=self.tcp_ping,
            config_to_sources=self.config_to_sources,
            stats=self.stats, verbose=self.verbose,
            upload_file=self.upload_fn)
        # Bypass-N.txt already uploaded progressively during verification
        # (every 300 working configs via write_progressive_bypass_files).
        # Skip re-adding them to file_pairs to avoid double upload.
        # bypass-all.txt is still added — it's only written once at the end.
        bypass_all_path = path_in_output(self.output_dir, "bypass", "bypass-all.txt")
        if os.path.exists(bypass_all_path):
            self.file_pairs.append((bypass_all_path, "githubmirror/bypass/bypass-all.txt"))
        return time.time() - start

    def stage_verified_unsecure(self) -> None:
        """Append verified bypass-unsecure files to file_pairs (gated)."""
        if not self.enable_bypass_unsecure:
            return
        # bypass-unsecure-N.txt already uploaded progressively during verification.
        # Only bypass-unsecure-all.txt needs final upload.
        unsecure_all_path = path_in_output(self.output_dir, "bypass-unsecure", "bypass-unsecure-all.txt")
        if os.path.exists(unsecure_all_path):
            self.file_pairs.append((unsecure_all_path, "githubmirror/bypass-unsecure/bypass-unsecure-all.txt"))

    def stage_report(self) -> None:
        """Print timing, cleanup dead URLs, print health report, flush stats."""
        overall = time.time() - self._overall_start
        log("")
        log("=" * 60)
        log("TIMING SUMMARY")
        log("=" * 60)
        stages = [
            ("Fetching URLs", self.timing.get('fetch', 0)),
            ("Default files", self.timing.get('defaults', 0)),
            ("Bypass raw", self.timing.get('bypass_raw', 0)),
            ("Bypass-unsecure raw", self.timing.get('bypass_unsecure_raw', 0)),
            ("Protocol split", self.timing.get('protocol_split', 0)),
            ("Telegram proxy", self.timing.get('tg_proxy', 0)),
            ("Verification", self.timing.get('verify', 0)),
        ]
        for name, elapsed in stages:
            if elapsed is not None:
                log(f"{name:30s} {elapsed:>8.2f}s")
        log("-" * 60)
        log(f"{'OVERALL TOTAL':30s} {overall:>8.2f}s")
        log("=" * 60)
        log("")
        self.stats.remove_dead_from_urls_txt()
        self.stats.remove_dead_from_servers_txt()
        self.stats.print_report()
        self.stats.flush()

    def _free_download_data(self) -> None:
        """Free tagger after download stages."""
        if hasattr(self, '_tagger') and self._tagger is not None:
            self._tagger.reset()
            del self._tagger
            self._tagger = None
        gc.collect()

    def _free_pre_verify_data(self) -> None:
        """Free all config lists before verification (frees ~150MB)."""
        for attr in ('all_configs', 'extra_bypass_configs',
                     'numbered_configs_with_urls', '_sni_cidr_filtered',
                     'mtproto_proxies', 'socks5_proxies'):
            if hasattr(self, attr):
                try:
                    delattr(self, attr)
                except AttributeError:
                    pass
        gc.collect()

    def run(self) -> List[Tuple[str, str]]:
        """Execute all pipeline stages in order. Returns file_pairs."""
        self._overall_start = time.time()
        self.timing['fetch'] = self.stage_download()
        self.timing['defaults'] = self.stage_default_files()
        self.timing['bypass_raw'] = self.stage_bypass_raw()
        self.timing['bypass_unsecure_raw'] = self.stage_bypass_unsecure_raw()
        self._free_download_data()
        self.timing['protocol_split'] = self.stage_protocol_split()
        self.timing['tg_proxy'] = self.stage_telegram_proxy()
        self.stage_build_file_pairs()
        self.stage_build_config_sources()
        # Upload pre-verify files (defaults, raw, protocols, tg proxies)
        if self.upload_fn:
            for local, remote in self.file_pairs:
                try:
                    self.upload_fn(local, remote)
                except (OSError, IOError, RuntimeError) as e:
                    log(f"Pre-verify upload warning for {remote}: {e}")
        self._free_pre_verify_data()
        self.timing['verify'] = self.stage_verify()
        self.stage_verified_unsecure()
        self.stage_report()
        # Source config files may have been cleaned (dead URLs removed).
        # Upload them so the cleanup persists and doesn't repeat every run.
        self.file_pairs.append(("source/config/URLS.txt", "source/config/URLS.txt"))
        self.file_pairs.append(("source/config/servers.txt", "source/config/servers.txt"))
        return self.file_pairs


def process_all_configs(output_dir: str = "../githubmirror", skip_xray: bool = False,
                         tcp_ping: bool = False, verbose: bool = False,
                         flag_overrides: Optional[dict] = None,
                         upload_fn: Optional[Callable[[str, str], None]] = None) -> List[Tuple[str, str]]:
    """Main processing function that orchestrates the entire config generation process.

    Args:
        output_dir: Output directory for generated files
        skip_xray: Skip Xray-core download/use (TCP-only verification)
        tcp_ping: Use TCP ping instead of Xray-core (faster, less accurate)
        verbose: Enable verbose logging
        flag_overrides: Optional dict overriding the 5 feature flags from
                        config/settings.py.
        upload_fn: Optional callback for progressive upload during pipeline.
                   Called with (local_path, remote_path) for each file.
    """
    pipeline = ConfigPipeline(
        output_dir=output_dir, skip_xray=skip_xray,
        tcp_ping=tcp_ping, verbose=verbose,
        flag_overrides=flag_overrides,
        upload_fn=upload_fn)
    return pipeline.run()

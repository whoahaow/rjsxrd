"""Config processing module for filtering and creating special configs."""

import os
import re
import base64
import json
import concurrent.futures
from typing import List, Set
from config.settings import SNI_DOMAINS, EXTRA_URLS_FOR_BYPASS, MAX_SERVERS_PER_FILE
from fetchers.fetcher import fetch_data
from utils.file_utils import extract_host_port, deduplicate_configs, prepare_config_content
from utils.logger import log


def create_filtered_configs(output_dir: str = "../githubmirror") -> List[str]:
    """
    Creates filtered configs for SNI/CIDR bypass in the bypass folder.
    Also creates bypass-all.txt with all SNI/CIDR bypass servers.
    Returns a list of created file paths.
    """
    # Optimize domain list by removing redundant domains
    sorted_domains = sorted(SNI_DOMAINS, key=len)
    optimized_domains = []

    for d in sorted_domains:
        is_redundant = False
        for existing in optimized_domains:
            if existing in d:
                is_redundant = True
                break
        if not is_redundant:
            optimized_domains.append(d)

    # Compile Regex
    try:
        pattern_str = r"(?:" + "|".join(re.escape(d) for d in optimized_domains) + r")"
        sni_regex = re.compile(pattern_str)
    except Exception as e:
        log(f"Ошибка компиляции Regex: {e}")
        return []

    def _process_file_filtering(file_idx: int) -> List[str]:
        """Process a single file to filter configs by SNI domains."""
        # Look for files in the default subdirectory
        local_path = f"{output_dir}/default/{file_idx}.txt"
        filtered_lines = []
        if not os.path.exists(local_path):
            return filtered_lines

        try:
            with open(local_path, "r", encoding="utf-8") as file:
                content = file.read()

            # Force separation of configs that might be glued together
            content = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', content)
            lines = content.splitlines()

            for line in lines:
                line = line.strip()
                if not line:
                    continue
                # Quick check with optimized Regex
                if sni_regex.search(line):
                    filtered_lines.append(line)
        except Exception:
            pass
        return filtered_lines

    all_configs = []

    # Process original config files for SNI filtering
    from config.settings import URLS
    max_workers = min(16, os.cpu_count() + 4)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_process_file_filtering, i) for i in range(1, len(URLS) + 1)]
        for future in concurrent.futures.as_completed(futures):
            all_configs.extend(future.result())

    # Load configs from additional sources (no SNI filtering, only deduplication)
    def _load_extra_configs(url: str) -> List[str]:
        """Load configs from additional source without SNI check."""
        try:
            data = fetch_data(url)
            # Force separation of glued configs
            data = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', data)
            lines = data.splitlines()
            configs = []
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    configs.append(line)
            return configs
        except Exception as e:
            short_msg = str(e)
            if len(short_msg) > 200:
                short_msg = short_msg[:200] + "…"
            log(f"Ошибка при загрузке {url}: {short_msg}")
            return []

    extra_configs = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(EXTRA_URLS_FOR_BYPASS))) as executor:
        futures = [executor.submit(_load_extra_configs, url) for url in EXTRA_URLS_FOR_BYPASS]
        for future in concurrent.futures.as_completed(futures):
            extra_configs.extend(future.result())

    all_configs.extend(extra_configs)

    # Deduplicate all configs
    unique_configs = deduplicate_configs(all_configs)

    # Create bypass-all.txt with all unique configs in the bypass folder
    all_txt_path = f"{output_dir}/bypass/bypass-all.txt"
    try:
        with open(all_txt_path, "w", encoding="utf-8") as file:
            file.write("\n".join(unique_configs))
        log(f"Создан файл {all_txt_path} с {len(unique_configs)} конфигами")
    except Exception as e:
        log(f"Ошибка при сохранении {all_txt_path}: {e}")

    # Split into multiple files if needed (starting after the original files)
    created_files = []

    # Split into chunks of MAX_SERVERS_PER_FILE configs each
    from config.settings import URLS
    chunks = [unique_configs[i:i + MAX_SERVERS_PER_FILE]
             for i in range(0, len(unique_configs), MAX_SERVERS_PER_FILE)]

    # Create bypass files named bypass-1.txt, bypass-2.txt, etc.
    for idx, chunk in enumerate(chunks, 1):  # Start from 1 instead of original config count
        bypass_filename = f"{output_dir}/bypass/bypass-{idx}.txt"
        try:
            with open(bypass_filename, "w", encoding="utf-8") as file:
                file.write("\n".join(chunk))
            log(f"Создан файл {bypass_filename} с {len(chunk)} конфигами")
            created_files.append(bypass_filename)
        except Exception as e:
            log(f"Ошибка при сохранении {bypass_filename}: {e}")

    # Add bypass-all.txt to the list of created files to be uploaded
    created_files.append(all_txt_path)

    return created_files
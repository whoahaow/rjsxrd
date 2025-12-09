"""Config processing module for filtering and creating special configs."""

import os
import re
import base64
import json
import concurrent.futures
from typing import List, Set
from config.settings import SNI_DOMAINS, EXTRA_URLS_FOR_26, MAX_SERVERS_PER_FILE
from fetchers.fetcher import fetch_data
from utils.file_utils import extract_host_port, deduplicate_configs, prepare_config_content
from utils.logger import log


def create_filtered_configs(output_dir: str = "../githubmirror") -> List[str]:
    """
    Creates filtered configs for SNI/CIDR bypass (file 26 and split versions).
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
        local_path = f"{output_dir}/{file_idx}.txt"
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

    # Process files 1-25 for SNI filtering
    max_workers = min(16, os.cpu_count() + 4)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_process_file_filtering, i) for i in range(1, 26)]
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
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(EXTRA_URLS_FOR_26))) as executor:
        futures = [executor.submit(_load_extra_configs, url) for url in EXTRA_URLS_FOR_26]
        for future in concurrent.futures.as_completed(futures):
            extra_configs.extend(future.result())

    all_configs.extend(extra_configs)

    # Deduplicate all configs
    unique_configs = deduplicate_configs(all_configs)
    
    # Split into multiple files if needed
    created_files = []

    # Split into chunks of MAX_SERVERS_PER_FILE configs each
    chunks = [unique_configs[i:i + MAX_SERVERS_PER_FILE]
             for i in range(0, len(unique_configs), MAX_SERVERS_PER_FILE)]

    for idx, chunk in enumerate(chunks, 26):  # Start from 26.txt
        filename = f"{output_dir}/{idx}.txt"
        try:
            with open(filename, "w", encoding="utf-8") as file:
                file.write("\n".join(chunk))
            log(f"Создан файл {filename} с {len(chunk)} конфигами")
            created_files.append(filename)
        except Exception as e:
            log(f"Ошибка при сохранении {filename}: {e}")

    return created_files
"""Config processing module for filtering and creating special configs."""

import os
import re
import base64
import json
import concurrent.futures
from typing import List, Set
from config.settings import SNI_DOMAINS, URLS, EXTRA_URLS_FOR_BYPASS, URLS_BASE64, MAX_SERVERS_PER_FILE
from fetchers.fetcher import fetch_data
from utils.file_utils import extract_host_port, deduplicate_configs, prepare_config_content, filter_secure_configs, load_cidr_whitelist, is_ip_in_cidr_whitelist, extract_ip_from_config
from utils.logger import log


def is_valid_vpn_config_url(line: str) -> bool:
    """Check if a line is a valid VPN config URL by verifying it starts with a known protocol followed by ://"""
    line = line.strip()
    # Check if the line starts with one of the known VPN protocols followed by ://
    return bool(re.match(r'^(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2|hy2)://', line, re.IGNORECASE))


def create_filtered_configs(output_dir: str = "../githubmirror") -> List[str]:
    """
    Creates filtered configs for SNI/CIDR bypass in the bypass folder.
    Also creates bypass-all.txt with all SNI/CIDR bypass servers.
    Returns a list of created file paths.
    """
    # Load CIDR whitelist
    cidr_whitelist = load_cidr_whitelist()

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
        """Process a single file to filter configs by SNI domains and CIDR."""
        # Look for files in the default subdirectory
        local_path = f"{output_dir}/default/{file_idx}.txt"
        filtered_lines = []
        if not os.path.exists(local_path):
            return filtered_lines

        try:
            with open(local_path, "r", encoding="utf-8") as file:
                content = file.read()

            # Force separation of configs that might be glued together
            content = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2|hy2)://', r'\n\1://', content)
            lines = content.splitlines()

            for line in lines:
                line = line.strip()
                if not line:
                    continue
                # Check for SNI domains
                if sni_regex.search(line):
                    # Only add the line if it's a valid VPN config URL
                    if is_valid_vpn_config_url(line):
                        filtered_lines.append(line)
                # Check for CIDR matching
                elif cidr_whitelist:
                    ip = extract_ip_from_config(line)
                    if ip and is_ip_in_cidr_whitelist(ip, cidr_whitelist):
                        # Only add the line if it's a valid VPN config URL
                        if is_valid_vpn_config_url(line):
                            filtered_lines.append(line)
        except Exception:
            pass
        # Filter out insecure configs
        return filter_secure_configs(filtered_lines)

    all_configs = []

    # Process original config files for SNI/CIDR filtering
    max_workers = min(16, os.cpu_count() + 4)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_process_file_filtering, i) for i in range(1, len(URLS) + 1)]
        for future in concurrent.futures.as_completed(futures):
            all_configs.extend(future.result())

    # Load configs from additional sources (no SNI/CIDR filtering, only deduplication)
    def _load_extra_configs(url: str) -> List[str]:
        """Load configs from additional source without SNI/CIDR check."""
        try:
            data = fetch_data(url)
            # Force separation of glued configs
            data = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2|hy2)://', r'\n\1://', data)
            lines = data.splitlines()
            configs = []
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#') and is_valid_vpn_config_url(line):
                    configs.append(line)
            # Filter out insecure configs from extra sources
            return filter_secure_configs(configs)
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

    # Load configs from base64-encoded subscriptions
    def _load_base64_configs(url: str) -> List[str]:
        """Load configs from base64-encoded subscription and apply SNI/CIDR filtering like regular configs."""
        try:
            data = fetch_data(url)
            # Decode base64 content
            try:
                # Remove any whitespace and decode the base64 content
                decoded_bytes = base64.b64decode(data.strip())
                decoded_content = decoded_bytes.decode('utf-8')
            except Exception as e:
                log(f"Ошибка декодирования base64 для {url}: {str(e)}")
                return []

            # Force separation of glued configs in the decoded content
            decoded_content = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2|hy2)://', r'\n\1://', decoded_content)
            lines = decoded_content.splitlines()
            filtered_configs = []

            for line in lines:
                line = line.strip()
                if not line:
                    continue
                # Apply SNI filtering (same logic as in _process_file_filtering)
                if sni_regex.search(line):
                    # Only add the line if it's a valid VPN config URL
                    if is_valid_vpn_config_url(line):
                        filtered_configs.append(line)
                # Check for CIDR matching
                elif cidr_whitelist:
                    ip = extract_ip_from_config(line)
                    if ip and is_ip_in_cidr_whitelist(ip, cidr_whitelist):
                        # Only add the line if it's a valid VPN config URL
                        if is_valid_vpn_config_url(line):
                            filtered_configs.append(line)

            # Filter out insecure configs from base64 sources
            return filter_secure_configs(filtered_configs)
        except Exception as e:
            short_msg = str(e)
            if len(short_msg) > 200:
                short_msg = short_msg[:200] + "…"
            log(f"Ошибка при загрузке base64-саба {url}: {short_msg}")
            return []

    base64_configs = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(URLS_BASE64))) as executor:
        futures = [executor.submit(_load_base64_configs, url) for url in URLS_BASE64]
        for future in concurrent.futures.as_completed(futures):
            base64_configs.extend(future.result())

    all_configs.extend(base64_configs)

    # Filter out configs with insecure settings for bypass configs
    secure_configs = filter_secure_configs(all_configs)

    # Deduplicate all configs
    unique_configs = deduplicate_configs(secure_configs)

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

    # Create unsecure bypass configs (without secure filtering)
    unsecure_files = create_unsecure_filtered_configs(output_dir)
    created_files.extend(unsecure_files)

    return created_files


def create_unsecure_filtered_configs(output_dir: str = "../githubmirror") -> List[str]:
    """
    Creates unfiltered configs for SNI/CIDR bypass in the bypass-unsecure folder.
    These configs do NOT go through secure filtering (allowing insecure configs).
    Also creates bypass-unsecure-all.txt with all SNI/CIDR bypass servers without secure filtering.
    Returns a list of created file paths.
    """
    # Load CIDR whitelist
    cidr_whitelist = load_cidr_whitelist()

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
        log(f"Ошибка компиляции Regex для unsecure: {e}")
        return []

    def _process_file_filtering_unsecure(file_idx: int) -> List[str]:
        """Process a single file to filter configs by SNI domains and CIDR without secure filtering."""
        # Look for files in the default subdirectory
        local_path = f"{output_dir}/default/{file_idx}.txt"
        filtered_lines = []
        if not os.path.exists(local_path):
            return filtered_lines

        try:
            with open(local_path, "r", encoding="utf-8") as file:
                content = file.read()

            # Force separation of configs that might be glued together
            content = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2|hy2)://', r'\n\1://', content)
            lines = content.splitlines()

            for line in lines:
                line = line.strip()
                if not line:
                    continue
                # Check for SNI domains
                if sni_regex.search(line):
                    # Only add the line if it's a valid VPN config URL
                    if is_valid_vpn_config_url(line):
                        filtered_lines.append(line)
                # Check for CIDR matching
                elif cidr_whitelist:
                    ip = extract_ip_from_config(line)
                    if ip and is_ip_in_cidr_whitelist(ip, cidr_whitelist):
                        # Only add the line if it's a valid VPN config URL
                        if is_valid_vpn_config_url(line):
                            filtered_lines.append(line)
        except Exception:
            pass
        # DO NOT filter out insecure configs - return all configs
        return filtered_lines

    all_configs = []

    # Process original config files for SNI/CIDR filtering without secure filtering
    max_workers = min(16, os.cpu_count() + 4)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_process_file_filtering_unsecure, i) for i in range(1, len(URLS) + 1)]
        for future in concurrent.futures.as_completed(futures):
            all_configs.extend(future.result())

    # Load configs from additional sources (no SNI/CIDR filtering, only deduplication)
    def _load_extra_configs_unsecure(url: str) -> List[str]:
        """Load configs from additional source without SNI/CIDR check or secure filtering."""
        try:
            data = fetch_data(url)
            # Force separation of glued configs
            data = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2|hy2)://', r'\n\1://', data)
            lines = data.splitlines()
            configs = []
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#') and is_valid_vpn_config_url(line):
                    configs.append(line)
            # DO NOT filter out insecure configs from extra sources - return all
            return configs
        except Exception as e:
            short_msg = str(e)
            if len(short_msg) > 200:
                short_msg = short_msg[:200] + "…"
            log(f"Ошибка при загрузке unsecure {url}: {short_msg}")
            return []

    extra_configs = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(EXTRA_URLS_FOR_BYPASS))) as executor:
        futures = [executor.submit(_load_extra_configs_unsecure, url) for url in EXTRA_URLS_FOR_BYPASS]
        for future in concurrent.futures.as_completed(futures):
            extra_configs.extend(future.result())

    all_configs.extend(extra_configs)

    # Load configs from base64-encoded subscriptions
    def _load_base64_configs_unsecure(url: str) -> List[str]:
        """Load configs from base64-encoded subscription and apply SNI/CIDR filtering without secure filtering."""
        try:
            data = fetch_data(url)
            # Decode base64 content
            try:
                # Remove any whitespace and decode the base64 content
                decoded_bytes = base64.b64decode(data.strip())
                decoded_content = decoded_bytes.decode('utf-8')
            except Exception as e:
                log(f"Ошибка декодирования base64 для unsecure {url}: {str(e)}")
                return []

            # Force separation of glued configs in the decoded content
            decoded_content = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2|hy2)://', r'\n\1://', decoded_content)
            lines = decoded_content.splitlines()
            filtered_configs = []

            for line in lines:
                line = line.strip()
                if not line:
                    continue
                # Apply SNI filtering (same logic as in _process_file_filtering_unsecure)
                if sni_regex.search(line):
                    # Only add the line if it's a valid VPN config URL
                    if is_valid_vpn_config_url(line):
                        filtered_configs.append(line)
                # Check for CIDR matching
                elif cidr_whitelist:
                    ip = extract_ip_from_config(line)
                    if ip and is_ip_in_cidr_whitelist(ip, cidr_whitelist):
                        # Only add the line if it's a valid VPN config URL
                        if is_valid_vpn_config_url(line):
                            filtered_configs.append(line)

            # DO NOT filter out insecure configs from base64 sources - return all
            return filtered_configs
        except Exception as e:
            short_msg = str(e)
            if len(short_msg) > 200:
                short_msg = short_msg[:200] + "…"
            log(f"Ошибка при загрузке unsecure base64-саба {url}: {short_msg}")
            return []

    base64_configs = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(URLS_BASE64))) as executor:
        futures = [executor.submit(_load_base64_configs_unsecure, url) for url in URLS_BASE64]
        for future in concurrent.futures.as_completed(futures):
            base64_configs.extend(future.result())

    all_configs.extend(base64_configs)

    # DO NOT filter out configs with insecure settings - keep all configs
    unsecure_configs = all_configs

    # Deduplicate all configs
    unique_configs = deduplicate_configs(unsecure_configs)

    # Create bypass-unsecure-all.txt with all unique configs in the bypass-unsecure folder
    all_txt_path = f"{output_dir}/bypass-unsecure/bypass-unsecure-all.txt"
    try:
        with open(all_txt_path, "w", encoding="utf-8") as file:
            file.write("\n".join(unique_configs))
        log(f"Создан файл {all_txt_path} с {len(unique_configs)} конфигами (unsecure)")
    except Exception as e:
        log(f"Ошибка при сохранении {all_txt_path}: {e}")

    # Split into multiple files if needed
    created_files = []

    # Split into chunks of MAX_SERVERS_PER_FILE configs each
    chunks = [unique_configs[i:i + MAX_SERVERS_PER_FILE]
             for i in range(0, len(unique_configs), MAX_SERVERS_PER_FILE)]

    # Create bypass-unsecure files named bypass-unsecure-1.txt, bypass-unsecure-2.txt, etc.
    for idx, chunk in enumerate(chunks, 1):
        bypass_filename = f"{output_dir}/bypass-unsecure/bypass-unsecure-{idx}.txt"
        try:
            with open(bypass_filename, "w", encoding="utf-8") as file:
                file.write("\n".join(chunk))
            log(f"Создан файл {bypass_filename} с {len(chunk)} конфигами (unsecure)")
            created_files.append(bypass_filename)
        except Exception as e:
            log(f"Ошибка при сохранении {bypass_filename}: {e}")

    # Add bypass-unsecure-all.txt to the list of created files to be uploaded
    created_files.append(all_txt_path)

    return created_files
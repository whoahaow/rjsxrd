"""Main module for VPN config generator."""

import os
import sys
import concurrent.futures
import argparse
import base64
from typing import List, Tuple, Optional

# Add the source directory to the path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from config.settings import URLS, URLS_BASE64, EXTRA_URLS_FOR_BYPASS, DEFAULT_MAX_WORKERS
from fetchers.fetcher import fetch_data, build_session
from utils.file_utils import save_to_local_file, load_from_local_file, split_config_file
from utils.logger import log
from utils.github_handler import GitHubHandler
from processors.config_processor import create_filtered_configs


def download_and_save(idx: int, output_dir: str = "../githubmirror") -> Optional[Tuple[str, str]]:
    """Downloads and saves a single config file from URLS."""
    url = URLS[idx]
    # Create default subdirectory if it doesn't exist
    default_dir = f"{output_dir}/default"
    os.makedirs(default_dir, exist_ok=True)
    local_path = f"{default_dir}/{idx + 1}.txt"

    try:
        data = fetch_data(url)

        # Check if content changed before saving
        if os.path.exists(local_path):
            try:
                with open(local_path, "r", encoding="utf-8") as f_old:
                    old_data = f_old.read()
                if old_data == data:
                    log(f"Изменений для {local_path} нет (локально). Пропуск загрузки в GitHub.")
                    return None
            except Exception:
                pass

        save_to_local_file(local_path, data)
        return local_path, f"githubmirror/default/{idx + 1}.txt"
    except Exception as e:
        short_msg = str(e)
        if len(short_msg) > 200:
            short_msg = short_msg[:200] + "…"
        log(f"Ошибка при скачивании {url}: {short_msg}")
        return None


def download_and_save_base64(idx: int, output_dir: str = "../githubmirror") -> Optional[Tuple[str, str]]:
    """Downloads and saves a single base64-encoded config file, decoding it before saving."""
    url = URLS_BASE64[idx]
    # Create default subdirectory if it doesn't exist
    default_dir = f"{output_dir}/default"
    os.makedirs(default_dir, exist_ok=True)
    # Start numbering after the regular URLs
    file_number = len(URLS) + idx + 1
    local_path = f"{default_dir}/{file_number}.txt"

    try:
        data = fetch_data(url)

        # Decode base64 content
        try:
            decoded_bytes = base64.b64decode(data.strip())
            decoded_content = decoded_bytes.decode('utf-8')
        except Exception as e:
            log(f"Ошибка декодирования base64 для {url}: {str(e)}")
            return None

        # Check if content changed before saving
        if os.path.exists(local_path):
            try:
                with open(local_path, "r", encoding="utf-8") as f_old:
                    old_data = f_old.read()
                if old_data == decoded_content:
                    log(f"Изменений для {local_path} нет (локально). Пропуск загрузки в GitHub.")
                    return None
            except Exception:
                pass

        save_to_local_file(local_path, decoded_content)
        return local_path, f"githubmirror/default/{file_number}.txt"
    except Exception as e:
        short_msg = str(e)
        if len(short_msg) > 200:
            short_msg = short_msg[:200] + "…"
        log(f"Ошибка при скачивании base64 {url}: {short_msg}")
        return None


def download_and_save_extra(idx: int, output_dir: str = "../githubmirror") -> Optional[Tuple[str, str]]:
    """Downloads and saves a single config file from EXTRA_URLS_FOR_BYPASS."""
    url = EXTRA_URLS_FOR_BYPASS[idx]
    # Create default subdirectory if it doesn't exist
    default_dir = f"{output_dir}/default"
    os.makedirs(default_dir, exist_ok=True)
    # Start numbering after the regular URLs and base64 URLs
    file_number = len(URLS) + len(URLS_BASE64) + idx + 1
    local_path = f"{default_dir}/{file_number}.txt"

    try:
        data = fetch_data(url)

        # Check if content changed before saving
        if os.path.exists(local_path):
            try:
                with open(local_path, "r", encoding="utf-8") as f_old:
                    old_data = f_old.read()
                if old_data == data:
                    log(f"Изменений для {local_path} нет (локально). Пропуск загрузки в GitHub.")
                    return None
            except Exception:
                pass

        save_to_local_file(local_path, data)
        return local_path, f"githubmirror/default/{file_number}.txt"
    except Exception as e:
        short_msg = str(e)
        if len(short_msg) > 200:
            short_msg = short_msg[:200] + "…"
        log(f"Ошибка при скачивании extra {url}: {short_msg}")
        return None


def upload_configs_to_github(file_pairs: list, github_handler: GitHubHandler, dry_run: bool = False):
    """Uploads config files to GitHub."""
    max_workers_upload = max(2, min(6, len(file_pairs)))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers_upload) as upload_pool:
        upload_futures = []

        for local_path, remote_path in file_pairs:
            if dry_run:
                log(f"Dry-run: пропускаем загрузку {remote_path} (локальный путь {local_path})")
            else:
                upload_futures.append(
                    upload_pool.submit(github_handler.upload_file, local_path, remote_path)
                )

        for uf in concurrent.futures.as_completed(upload_futures):
            _ = uf.result()


def create_default_all_file(output_dir: str = "../githubmirror") -> Optional[Tuple[str, str]]:
    """Creates an all.txt file in the default folder containing all unique configs from all default txt files."""
    from utils.file_utils import deduplicate_configs, prepare_config_content
    import re

    default_dir = f"{output_dir}/default"
    all_configs = []

    # Get all .txt files in the default directory
    if not os.path.exists(default_dir):
        log(f"Директория {default_dir} не существует")
        return None

    txt_files = [f for f in os.listdir(default_dir) if f.endswith('.txt') and f != 'all.txt']  # Exclude all.txt if it already exists

    for txt_file in txt_files:
        file_path = os.path.join(default_dir, txt_file)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Prepare and normalize config content
            configs = prepare_config_content(content)
            all_configs.extend(configs)
        except Exception as e:
            log(f"Ошибка при чтении файла {file_path}: {e}")
            continue

    # Deduplicate all configs
    unique_configs = deduplicate_configs(all_configs)

    # Create the all.txt file
    all_txt_path = os.path.join(default_dir, "all.txt")
    try:
        with open(all_txt_path, "w", encoding="utf-8") as f:
            f.write("\n".join(unique_configs))
        log(f"Создан файл {all_txt_path} с {len(unique_configs)} уникальными конфигами")

        # Return the file pair for upload
        return all_txt_path, "githubmirror/default/all.txt"
    except Exception as e:
        log(f"Ошибка при создании all.txt: {e}")
        return None


def create_default_all_secure_file(output_dir: str = "../githubmirror") -> Optional[Tuple[str, str]]:
    """Creates an all-secure.txt file in the default folder containing only secure configs from all default txt files."""
    from utils.file_utils import deduplicate_configs, prepare_config_content, has_insecure_setting
    import re

    default_dir = f"{output_dir}/default"
    all_configs = []

    # Get all .txt files in the default directory
    if not os.path.exists(default_dir):
        log(f"Директория {default_dir} не существует")
        return None

    txt_files = [f for f in os.listdir(default_dir) if f.endswith('.txt') and f not in ['all.txt', 'all-secure.txt']]  # Exclude both all.txt and all-secure.txt if it already exists

    for txt_file in txt_files:
        file_path = os.path.join(default_dir, txt_file)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Prepare and normalize config content
            configs = prepare_config_content(content)
            all_configs.extend(configs)
        except Exception as e:
            log(f"Ошибка при чтении файла {file_path}: {e}")
            continue

    # Filter out insecure configs
    secure_configs = [config for config in all_configs if not has_insecure_setting(config)]

    # Deduplicate secure configs
    unique_secure_configs = deduplicate_configs(secure_configs)

    # Create the all-secure.txt file
    all_secure_txt_path = os.path.join(default_dir, "all-secure.txt")
    try:
        with open(all_secure_txt_path, "w", encoding="utf-8") as f:
            f.write("\n".join(unique_secure_configs))
        log(f"Создан файл {all_secure_txt_path} с {len(unique_secure_configs)} уникальными безопасными конфигами")

        # Return the file pair for upload
        return all_secure_txt_path, "githubmirror/default/all-secure.txt"
    except Exception as e:
        log(f"Ошибка при создании all-secure.txt: {e}")
        return None


def create_protocol_split_files(output_dir: str = "../githubmirror") -> List[Tuple[str, str]]:
    """Creates protocol-specific files in the split-by-protocols folder, both secure and unsecure versions."""
    from utils.file_utils import prepare_config_content, has_insecure_setting
    import re

    # Include configs from all relevant directories
    source_dirs = [
        f"{output_dir}/default",
        f"{output_dir}/bypass",
        f"{output_dir}/bypass-unsecure"
    ]

    split_dir = f"{output_dir}/split-by-protocols"

    # Create the split-by-protocols directory
    os.makedirs(split_dir, exist_ok=True)

    all_configs = []

    # Get all .txt files from all source directories
    for source_dir in source_dirs:
        if not os.path.exists(source_dir):
            log(f"Директория {source_dir} не существует")
            continue

        txt_files = [f for f in os.listdir(source_dir) if f.endswith('.txt') and f not in ['all.txt', 'all-secure.txt', 'bypass-all.txt', 'bypass-unsecure-all.txt']]

        for txt_file in txt_files:
            file_path = os.path.join(source_dir, txt_file)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                # Prepare and normalize config content
                configs = prepare_config_content(content)
                all_configs.extend(configs)
            except Exception as e:
                log(f"Ошибка при чтении файла {file_path}: {e}")
                continue

    # Define supported protocols
    protocols = ['vless', 'vmess', 'trojan', 'ss', 'ssr', 'tuic', 'hysteria', 'hysteria2', 'hy2']

    # Separate configs by protocol and security
    protocol_configs = {protocol: [] for protocol in protocols}
    protocol_secure_configs = {protocol: [] for protocol in protocols}

    for config in all_configs:
        # Determine the protocol from the config line
        config_lower = config.lower()
        matched_protocol = None

        for protocol in protocols:
            if config_lower.startswith(f"{protocol}://"):
                matched_protocol = protocol
                break

        if matched_protocol:
            # Add to unsecure version (all configs for this protocol)
            protocol_configs[matched_protocol].append(config)

            # Add to secure version only if it's secure
            if not has_insecure_setting(config):
                protocol_secure_configs[matched_protocol].append(config)

    # Create file pairs for upload
    file_pairs = []

    # Create unsecure protocol files (all configs for each protocol)
    for protocol, configs in protocol_configs.items():
        if configs:  # Only create file if there are configs for this protocol
            filename = f"{protocol}.txt"
            filepath = os.path.join(split_dir, filename)

            # Remove duplicates while preserving order
            unique_configs = list(dict.fromkeys(configs))  # Remove duplicates while preserving order

            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write("\n".join(unique_configs))
                log(f"Создан файл {filepath} с {len(unique_configs)} конфигами ({protocol})")

                file_pairs.append((filepath, f"githubmirror/split-by-protocols/{filename}"))
            except Exception as e:
                log(f"Ошибка при создании {filepath}: {e}")

    # Create secure protocol files (only secure configs for each protocol)
    for protocol, configs in protocol_secure_configs.items():
        if configs:  # Only create file if there are secure configs for this protocol
            filename = f"{protocol}-secure.txt"
            filepath = os.path.join(split_dir, filename)

            # Remove duplicates while preserving order
            unique_configs = list(dict.fromkeys(configs))  # Remove duplicates while preserving order

            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write("\n".join(unique_configs))
                log(f"Создан файл {filepath} с {len(unique_configs)} безопасными конфигами ({protocol})")

                file_pairs.append((filepath, f"githubmirror/split-by-protocols/{filename}"))
            except Exception as e:
                log(f"Ошибка при создании {filepath}: {e}")

    return file_pairs


def main(dry_run: bool = False, output_dir: str = "../githubmirror"):
    """Main execution function."""
    # Create output directories at project root level (one level up from source)
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(f"{output_dir}/default", exist_ok=True)  # For original config files
    os.makedirs(f"{output_dir}/bypass", exist_ok=True)   # For bypass config files
    os.makedirs(f"{output_dir}/bypass-unsecure", exist_ok=True)   # For bypass-unsecure config files
    os.makedirs(f"{output_dir}/split-by-protocols", exist_ok=True)   # For protocol-split config files
    os.makedirs("../qr-codes", exist_ok=True)  # Also create qr-codes directory

    max_workers_download = min(DEFAULT_MAX_WORKERS, max(1, len(URLS)))

    # Download all regular URL files
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers_download) as download_pool:
        download_futures = [
            download_pool.submit(download_and_save, i, output_dir)
            for i in range(len(URLS))
        ]

        # Collect results
        file_pairs = []
        for future in concurrent.futures.as_completed(download_futures):
            result = future.result()
            if result:
                file_pairs.append(result)

    # Download all base64-encoded subscription files
    if URLS_BASE64:  # Only process if there are base64 URLs
        max_workers_base64 = min(DEFAULT_MAX_WORKERS, max(1, len(URLS_BASE64)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers_base64) as base64_pool:
            base64_futures = [
                base64_pool.submit(download_and_save_base64, i, output_dir)
                for i in range(len(URLS_BASE64))
            ]

            for future in concurrent.futures.as_completed(base64_futures):
                result = future.result()
                if result:
                    file_pairs.append(result)

    # Download all extra bypass URL files
    if EXTRA_URLS_FOR_BYPASS:  # Only process if there are extra URLs
        max_workers_extra = min(DEFAULT_MAX_WORKERS, max(1, len(EXTRA_URLS_FOR_BYPASS)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers_extra) as extra_pool:
            extra_futures = [
                extra_pool.submit(download_and_save_extra, i, output_dir)
                for i in range(len(EXTRA_URLS_FOR_BYPASS))
            ]

            for future in concurrent.futures.as_completed(extra_futures):
                result = future.result()
                if result:
                    file_pairs.append(result)

    # Create filtered configs (starting after original files and splits if needed)
    filtered_files = create_filtered_configs(output_dir)

    # Add filtered files to upload list
    for filtered_file in filtered_files:
        filename = os.path.basename(filtered_file)
        # Determine correct remote path based on file location
        if "bypass-unsecure" in filtered_file:
            # Handle bypass-unsecure files
            if filename == "bypass-unsecure-all.txt":
                remote_path = f"githubmirror/bypass-unsecure/bypass-unsecure-all.txt"
            else:
                remote_path = f"githubmirror/bypass-unsecure/{filename}"
        elif filename == "bypass-all.txt":  # Updated filename for the all.txt file
            remote_path = f"githubmirror/bypass/bypass-all.txt"
        elif "bypass-" in filename and "unsecure" not in filename:  # Bypass config files (not unsecure)
            remote_path = f"githubmirror/bypass/{filename}"
        else:  # This should not happen for filtered configs based on our changes, but just in case
            # This case shouldn't occur with our new code, but keeping as fallback
            pass  # Skip these files, they should be in default directory already
        file_pairs.append((filtered_file, remote_path))

    # Create the default all.txt file containing all unique configs from default folder
    default_all_file = create_default_all_file(output_dir)
    if default_all_file:
        file_pairs.append(default_all_file)

    # Create the default all-secure.txt file containing only secure configs from default folder
    default_all_secure_file = create_default_all_secure_file(output_dir)
    if default_all_secure_file:
        file_pairs.append(default_all_secure_file)

    # Create protocol-specific files in both secure and unsecure versions
    protocol_files = create_protocol_split_files(output_dir)
    file_pairs.extend(protocol_files)

    # Initialize GitHub handler and upload files
    if not dry_run and file_pairs:
        github_handler = GitHubHandler()
        upload_configs_to_github(file_pairs, github_handler, dry_run)

    # Print logs
    from utils.logger import print_logs
    print_logs()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Скачивание конфигов и загрузка в GitHub")
    parser.add_argument("--dry-run", action="store_true", help="Только скачивать и сохранять локально, не загружать в GitHub")
    args = parser.parse_args()

    main(dry_run=args.dry_run)
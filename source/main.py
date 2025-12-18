"""Main module for VPN config generator."""

import os
import sys
import concurrent.futures
import argparse
from typing import Tuple, Optional

# Add the source directory to the path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from config.settings import URLS, DEFAULT_MAX_WORKERS
from fetchers.fetcher import fetch_data, build_session
from utils.file_utils import save_to_local_file, load_from_local_file, split_config_file
from utils.logger import log
from utils.github_handler import GitHubHandler
from processors.config_processor import create_filtered_configs


def download_and_save(idx: int, output_dir: str = "../githubmirror") -> Optional[Tuple[str, str]]:
    """Downloads and saves a single config file."""
    url = URLS[idx]
    # Create default subdirectory if it doesn't exist
    default_dir = f"{output_dir}/default"
    import os
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


def main(dry_run: bool = False, output_dir: str = "../githubmirror"):
    """Main execution function."""
    # Create output directories at project root level (one level up from source)
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(f"{output_dir}/default", exist_ok=True)  # For original config files
    os.makedirs(f"{output_dir}/bypass", exist_ok=True)   # For bypass config files
    os.makedirs("../qr-codes", exist_ok=True)  # Also create qr-codes directory

    max_workers_download = min(DEFAULT_MAX_WORKERS, max(1, len(URLS)))

    # Download all files
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

    # Create filtered configs (starting after original files and splits if needed)
    filtered_files = create_filtered_configs(output_dir)

    # Add filtered files to upload list
    for filtered_file in filtered_files:
        filename = os.path.basename(filtered_file)
        # Determine correct remote path based on file location
        if filename == "bypass-all.txt":  # Updated filename for the all.txt file
            remote_path = f"githubmirror/bypass/bypass-all.txt"
        elif "bypass-" in filename:  # Bypass config files
            remote_path = f"githubmirror/bypass/{filename}"
        else:  # This should not happen for filtered configs based on our changes, but just in case
            # This case shouldn't occur with our new code, but keeping as fallback
            pass  # Skip these files, they should be in default directory already
        file_pairs.append((filtered_file, remote_path))

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
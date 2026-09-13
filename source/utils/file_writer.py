"""File writing utilities for VPN config output.

Extracted from config_processor.py. Pure file-writing functions with no
pipeline-specific logic. Used by bypass_builder.py, config_processor.py.
"""

import math
import os
from datetime import datetime, timedelta, timezone

from config.settings import GITHUBMIRROR_DIR
from utils.config_helpers import path_in_output
from utils.file_utils import is_valid_vpn_config_url
from utils.logger import log


def append_remark_suffix(config: str, suffix: str = "%20t.me%2Frjsxrd") -> str:
    """Append suffix to config remark. Configs are already URL-encoded."""
    if "#" in config:
        return f"{config}{suffix}"
    return f"{config}#{suffix}"


def get_subscription_header(
    filename: str,
    current_file: int | None = None,
    total_files: int | None = None,
    config_count: int = 0,
) -> str:
    """Generate subscription header for a file."""
    if current_file and total_files:
        title = f"{filename}-{current_file}/{total_files} t.me/rjsxrd"
    else:
        title = f"{filename} t.me/rjsxrd"

    lines = [
        f"#profile-title: {title}",
        "#profile-update-interval: 1",
        "#support-url: https://t.me/rjsxrd",
        "#profile-web-page-url: https://github.com/whoahaow/rjsxrd",
    ]
    if config_count > 0:
        msk = timezone(timedelta(hours=3))
        now = datetime.now(msk).strftime("%H:%M %d/%m/%Y")
        lines.append(f"#announce: t.me/rjsxrd · {config_count} configs · last update: {now}")
    else:
        lines.append("#announce: t.me/rjsxrd")
    lines.append("#subscription-userinfo: upload=0; download=0; total=0; expire=0")
    return "\n".join(lines) + "\n\n"


def write_configs_file(
    filepath: str, configs: list[str], header: str, add_suffix: bool = True
) -> None:
    """Write a single configs file with header, optional remark suffix."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    configs_with_suffix = [append_remark_suffix(cfg) for cfg in configs] if add_suffix else configs
    with open(filepath, "w", encoding="utf-8", buffering=65536) as f:
        f.write(header + "\n".join(configs_with_suffix))


def stream_write_configs_file(
    filepath: str,
    configs: list[str],
    header: str,
    add_suffix: bool = True,
    chunk_size: int = 1000,
    progress_every: int = 10000,
) -> None:
    """Stream-write a large configs list to a file in chunks (memory-bounded)."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8", buffering=65536) as f:
        f.write(header)
        for i in range(0, len(configs), chunk_size):
            chunk = configs[i : i + chunk_size]
            if add_suffix:
                chunk = [append_remark_suffix(cfg) for cfg in chunk]
            f.write("\n".join(chunk) + "\n")
            if progress_every and (i + chunk_size) % progress_every == 0:
                log(f"  Written {min(i + chunk_size, len(configs))}/{len(configs)}")


def _write_config_chunk(args) -> tuple[str, int, int, int, int, str | None]:
    """Worker function to write a single config chunk (must be at module level for pickling)."""
    chunk, filename, current_file, num_files, total_configs, filename_prefix, add_suffix = args
    try:
        header = get_subscription_header(
            filename_prefix, current_file, num_files, config_count=len(chunk)
        )
        write_configs_file(filename, chunk, header, add_suffix=add_suffix)
        return (filename, len(chunk), current_file, num_files, total_configs, None)
    except OSError as e:
        return (filename, 0, current_file, num_files, total_configs, str(e))


def split_configs_to_files(
    configs: list[str],
    output_dir: str,
    filename_prefix: str,
    max_configs_per_file: int = 300,
    add_suffix: bool = True,
) -> list[str]:
    """Split configs into multiple files with a given prefix using parallel processing."""
    num_configs = len(configs)
    if not num_configs:
        return []
    num_files = math.ceil(num_configs / max_configs_per_file)
    log(
        f"Number of configs: {num_configs}, Max configs per file: {max_configs_per_file}, "
        f"Calculated number of files: {num_files}"
    )

    from utils.executor_cache import ExecutorCache

    chunks_to_write = []
    for i in range(int(num_files)):
        start = i * max_configs_per_file
        end = start + max_configs_per_file
        chunk = configs[start:end]
        filename = path_in_output(output_dir, f"{filename_prefix}-{i + 1}.txt")
        chunks_to_write.append(
            (chunk, filename, i + 1, num_files, num_configs, filename_prefix, add_suffix)
        )

    executor = ExecutorCache.get("split_writer", max_workers=8)
    results = list(executor.map(_write_config_chunk, chunks_to_write))

    created_files = []
    for filename, *_, error in results:
        if error:
            log(f"Error writing {filename}: {error}")
        else:
            created_files.append(filename)
    return created_files


def _write_numbered_file(args) -> str | None:
    """Worker: write one numbered default file. Module-level for pickling."""
    configs, source_label, output_dir, idx = args
    valid = [cfg for cfg in configs if is_valid_vpn_config_url(cfg)]
    if not valid:
        return None
    filepath = path_in_output(output_dir, "default", f"{idx}.txt")
    header = get_subscription_header(f"{idx}/{source_label[:30]}", config_count=len(valid))
    write_configs_file(filepath, valid, header)
    return filepath


def create_numbered_default_files(
    numbered_configs_with_urls: list[tuple], output_dir: str = GITHUBMIRROR_DIR
) -> list[str]:
    """Create numbered default files (1.txt, 2.txt, ...) from sources."""
    from config.settings import MAX_NUMBERED_DEFAULT_FILES
    from utils.executor_cache import ExecutorCache

    if not numbered_configs_with_urls:
        return []

    executor = ExecutorCache.get("numbered_writer", max_workers=8)
    chunks = [
        (cfgs, src, output_dir, idx + 1)
        for idx, (cfgs, src) in enumerate(numbered_configs_with_urls[:MAX_NUMBERED_DEFAULT_FILES])
    ]
    results = list(executor.map(_write_numbered_file, chunks))
    return [p for p in results if p]


def _write_protocol_file(args) -> str | None:
    """Worker: write one protocol split file. Module-level for pickling."""
    protocol, configs, output_dir, max_size_mb, is_secure = args
    valid = [cfg for cfg in configs if is_valid_vpn_config_url(cfg)]
    suffix = "-secure" if is_secure else ""
    filepath = path_in_output(output_dir, "split-by-protocols", f"{protocol}{suffix}.txt")
    header = get_subscription_header(f"{protocol}{suffix}", config_count=len(valid))
    write_configs_file(filepath, valid, header)
    return filepath

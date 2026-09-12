#!/usr/bin/env python3
"""Remove 404/dead URLs from URLS.txt by fetching each one.

Preserves section structure (# default, # extra for bypass, etc.).

Usage:
    cd source
    python scripts/purge_dead_urls.py              # dry run (default)
    python scripts/purge_dead_urls.py --apply       # actually remove
    python scripts/purge_dead_urls.py --timeout 10 --apply
"""

import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, PROJECT_ROOT)

from fetchers.fetcher import fetch_data  # noqa: E402 - must follow the sys.path insert


def check_url(url: str, timeout: int) -> tuple[str, bool]:
    """Fetch a URL and return (url, is_alive)."""
    result = fetch_data(url, timeout=timeout, max_attempts=1)
    return url, result.success


def classify_lines(lines: list[str]) -> tuple[list[str], list[str]]:
    """Split lines into section headers and URL lines with their section."""
    alive: list[str] = []
    dead: list[str] = []
    return alive, dead


def run(dry_run: bool, timeout: int, max_workers: int) -> None:
    urls_file = os.path.join(PROJECT_ROOT, "config", "URLS.txt")
    if not os.path.exists(urls_file):
        print(f"ERROR: {urls_file} not found")
        sys.exit(1)

    with open(urls_file, encoding="utf-8") as f:
        all_lines = f.readlines()

    url_indices: list[tuple[int, str]] = []
    for i, line in enumerate(all_lines):
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            url_indices.append((i, stripped))

    print(f"checking {len(url_indices)} URLs with {max_workers} workers, {timeout}s timeout...")
    print(f"mode: {'DRY RUN (no changes)' if dry_run else 'APPLY (will remove dead URLs)'}")
    print()

    results: list[tuple[int, str, bool]] = []  # (line_index, url, is_alive)
    done = 0

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        fut_map = {pool.submit(check_url, url, timeout): (idx, url) for idx, url in url_indices}
        for future in as_completed(fut_map):
            idx, url = fut_map[future]
            _, alive = future.result()
            results.append((idx, url, alive))
            done += 1
            if done % 100 == 0 or done == len(url_indices):
                alive_count = sum(1 for _, _, a in results if a)
                dead_count = sum(1 for _, _, a in results if not a)
                print(
                    f"  progress: {done}/{len(url_indices)} (alive={alive_count}, dead={dead_count})"
                )

    # Sort results back to line order
    results.sort(key=lambda x: x[0])

    alive_urls = [(idx, url) for idx, url, alive in results if alive]
    dead_urls = [(idx, url) for idx, url, alive in results if not alive]

    print()
    print(f"results: {len(alive_urls)} alive, {len(dead_urls)} dead")

    if dead_urls:
        print()
        print(f"dead URLs ({len(dead_urls)}):")
        for _, url in dead_urls:
            print(f"  {url[:90]}")

    if dry_run:
        print()
        print("dry run — no changes made.")
        print(f"run with --apply to remove {len(dead_urls)} dead URLs.")
        print()
        return

    # Remove dead lines, preserving section headers and everything else
    dead_set = {url for _, url in dead_urls}
    new_lines: list[str] = []
    removed: list[str] = []
    for line in all_lines:
        stripped = line.strip()
        if stripped in dead_set:
            removed.append(stripped)
            continue
        new_lines.append(line)

    # Backup
    backup_path = urls_file + ".dead.backup"
    with open(backup_path, "w", encoding="utf-8") as f:
        f.writelines(all_lines)

    # Write
    with open(urls_file, "w", encoding="utf-8") as f:
        f.writelines(new_lines)

    print()
    print(f"removed {len(removed)} dead URLs from URLS.txt")
    print(f"backup saved to: {backup_path}")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Remove dead URLs from URLS.txt")
    parser.add_argument("--apply", action="store_true", help="actually remove (default: dry run)")
    parser.add_argument(
        "--timeout", type=int, default=7, help="fetch timeout per URL in seconds (default: 7)"
    )
    parser.add_argument("--workers", type=int, default=32, help="concurrent fetchers (default: 32)")
    args = parser.parse_args()
    run(dry_run=not args.apply, timeout=args.timeout, max_workers=args.workers)

#!/usr/bin/env python3
"""Benchmark VPN configs with Xray-core or TCP ping.

Usage:
    cd source
    python scripts/benchmark_configs.py --mode xray --count 500
    python scripts/benchmark_configs.py --mode tcp --local
    python scripts/benchmark_configs.py --mode tcp --count 200 --local
"""

import argparse
import os
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
REPO_ROOT = os.path.join(PROJECT_ROOT, "..")  # rjsxrd root
sys.path.insert(0, PROJECT_ROOT)

from utils.logger import log  # noqa: E402 - must follow the sys.path insert


def load_configs(path: str, count: int | None = None) -> list[str]:
    with open(path, encoding="utf-8") as f:
        configs = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    if count and count < len(configs):
        configs = configs[:count]
    return configs


def run_xray(path: str, count: int | None) -> None:
    from utils.bypass_builder import verify_config_file
    from utils.download_xray import ensure_xray_installed

    xray_path = ensure_xray_installed()
    if not xray_path:
        log("xray binary not found and couldn't be downloaded")
        sys.exit(1)
    log(f"using xray: {xray_path}")

    configs = load_configs(path, count)
    log(f"testing {len(configs)} configs with xray...")

    start = time.time()
    working = verify_config_file(path)  # reads from file
    elapsed = time.time() - start

    log(f"\n{'=' * 60}")
    log("xray benchmark results")
    log(f"{'=' * 60}")
    log(f"tested:   {len(configs)}")
    log(f"working:  {len(working)}")
    log(f"failed:   {len(configs) - len(working)}")
    log(f"rate:     {len(working) / len(configs) * 100:.1f}%")
    log(f"time:     {elapsed:.2f}s")
    if configs:
        log(f"per/sec:  {len(configs) / elapsed:.1f}")
    log(f"{'=' * 60}")


def run_tcp(path: str, count: int | None) -> None:
    from utils.simple_tester import SimpleTester

    configs = load_configs(path, count)
    log(f"tcp-ping testing {len(configs)} configs...")

    tester = SimpleTester(timeout=3.0)
    start = time.time()
    results = tester.test_batch(configs)
    elapsed = time.time() - start

    working = [(url, rtt) for url, ok, rtt in results if ok]
    failed = sum(1 for _, ok, _ in results if not ok)
    fastest = sorted(working, key=lambda x: x[1])[:5]

    log(f"\n{'=' * 60}")
    log("tcp ping benchmark results")
    log(f"{'=' * 60}")
    log(f"tested:          {len(configs)}")
    log(f"reachable (tcp): {len(working)}")
    log(f"unreachable:     {failed}")
    log(f"rate:            {len(working) / len(configs) * 100:.1f}%")
    log(f"time:            {elapsed:.2f}s")
    if configs:
        log(f"per/sec:         {len(configs) / elapsed:.1f}")
    log("")
    log("--- 5 fastest ---")
    for url, rtt in fastest:
        log(f"  {rtt:>6.1f}ms  {url[:80]}")
    log(f"{'=' * 60}")


def resolve_path(local: bool) -> str:
    if local:
        path = os.path.join(REPO_ROOT, "githubmirror", "bypass", "bypass-all.txt")
        if os.path.exists(path):
            return path
        log(f"local file not found: {path}")

    github_url = (
        "https://raw.githubusercontent.com/whoahaow/rjsxrd/main/githubmirror/bypass/bypass-all.txt"
    )
    import urllib.request
    import tempfile

    log(f"fetching: {github_url}")
    try:
        with urllib.request.urlopen(github_url, timeout=30) as resp:
            content = resp.read().decode("utf-8")
    except Exception as e:
        log(f"failed to fetch: {e}")
        sys.exit(1)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(content)
    count = len(
        [line for line in content.splitlines() if line.strip() and not line.strip().startswith("#")]
    )
    log(f"fetched {count} configs from bypass-all.txt")
    return tmp.name


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Benchmark VPN configs")
    parser.add_argument("--mode", choices=["xray", "tcp"], default="tcp", help="test mode")
    parser.add_argument("--count", type=int, default=None, help="limit to first N configs")
    parser.add_argument(
        "--local", action="store_true", help="use local file instead of fetching from github"
    )
    args = parser.parse_args()

    path = resolve_path(args.local)

    if args.mode == "xray":
        run_xray(path, args.count)
    else:
        run_tcp(path, args.count)

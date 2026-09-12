#!/usr/bin/env python3
"""End-to-end Telegram proxy verification — fetch, merge, test, save.

Usage:
    cd source
    python scripts/test_telegram_proxies.py
    python scripts/test_telegram_proxies.py --output-dir ../githubmirror
"""

import argparse
import os
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
REPO_ROOT = os.path.join(PROJECT_ROOT, "..")
sys.path.insert(0, PROJECT_ROOT)

# Project imports must follow the sys.path insert above.
from utils.logger import log  # noqa: E402
from utils.telegram_proxy_verifier import TelegramProxyVerifier  # noqa: E402
from processors.telegram_proxy_processor import TelegramProxyProcessor  # noqa: E402
from processors.config_processor import download_all_configs  # noqa: E402
from config.settings import TELEGRAM_PROXY_URLS  # noqa: E402


def run(output_dir: str | None = None) -> None:
    if output_dir is None:
        output_dir = os.path.join(REPO_ROOT, "githubmirror")

    log("=" * 60)
    log("telegram proxy verification")
    log("=" * 60)
    start = time.time()

    # Step 1: download and extract proxies
    log("")
    log("step 1/3: fetching configs and extracting telegram proxies...")
    all_configs, extra_bypass, numbered, mtproto, socks5, _ = download_all_configs(
        output_dir, scan_for_telegram_proxies=True
    )

    # Merge manual proxies from tg_proxies.txt
    processor = TelegramProxyProcessor()
    manual_mt, manual_socks = processor.load_manual_proxies()
    if manual_mt:
        mtproto = list(set(mtproto + manual_mt))
        log(f"  merged {len(manual_mt)} manual mtproto proxies")
    if manual_socks:
        socks5 = list(set(socks5 + manual_socks))
        log(f"  merged {len(manual_socks)} manual socks5 proxies")

    # Scan dedicated telegram proxy URLs
    if TELEGRAM_PROXY_URLS:
        tg_mt, tg_socks = processor.scan_urls_for_proxies(TELEGRAM_PROXY_URLS)
        if tg_mt:
            mtproto = list(set(mtproto + tg_mt))
        if tg_socks:
            socks5 = list(set(socks5 + tg_socks))
        log(f"  scanned {len(TELEGRAM_PROXY_URLS)} dedicated telegram proxy urls")

    log(f"  vpn configs fetched: {len(all_configs)}")
    log(f"  mtproto proxies:     {len(mtproto)}")
    log(f"  socks5 proxies:      {len(socks5)}")

    if not mtproto and not socks5:
        log("no telegram proxies found")
        return

    # Step 2: verify
    log("")
    log("step 2/3: verifying proxies...")
    verifier = TelegramProxyVerifier()
    timeout = 5
    max_conc = 200

    if mtproto:
        log(f"verifying {len(mtproto)} mtproto proxies...")
        mt_results = verifier.verify_proxy_list(mtproto, timeout=timeout, max_concurrent=max_conc)
        mt_working = [url for url, ok, _ in mt_results if ok]
        mt_pct = len(mt_working) / len(mtproto) * 100 if mtproto else 0
        log(f"  mtproto: {len(mt_working)}/{len(mtproto)} working ({mt_pct:.1f}%)")
    else:
        mt_working = []
        log("no mtproto proxies to verify")

    if socks5:
        log(f"verifying {len(socks5)} socks5 proxies...")
        s5_results = verifier.verify_proxy_list(socks5, timeout=timeout, max_concurrent=max_conc)
        s5_working = [url for url, ok, _ in s5_results if ok]
        s5_pct = len(s5_working) / len(socks5) * 100 if socks5 else 0
        log(f"  socks5:  {len(s5_working)}/{len(socks5)} working ({s5_pct:.1f}%)")
    else:
        s5_working = []
        log("no socks5 proxies to verify")

    # Step 3: save
    log("")
    log("step 3/3: saving results...")
    tg_dir = os.path.join(output_dir, "tg-proxy")
    os.makedirs(tg_dir, exist_ok=True)

    if mt_working:
        p = os.path.join(tg_dir, "mtproto.txt")
        with open(p, "w", encoding="utf-8") as f:
            f.write("\n".join(mt_working))
        log(f"  saved {len(mt_working)} working mtproto to {p}")
    else:
        log("  no working mtproto to save")

    if s5_working:
        p = os.path.join(tg_dir, "socks5.txt")
        with open(p, "w", encoding="utf-8") as f:
            f.write("\n".join(s5_working))
        log(f"  saved {len(s5_working)} working socks5 to {p}")
    else:
        log("  no working socks5 to save")

    elapsed = time.time() - start
    total = len(mtproto) + len(socks5)
    total_ok = len(mt_working) + len(s5_working)

    log("")
    log("=" * 60)
    log("summary")
    log("=" * 60)
    log(f"  mtproto:    {len(mt_working)}/{len(mtproto)} working")
    log(f"  socks5:     {len(s5_working)}/{len(socks5)} working")
    log(
        f"  total:      {total_ok}/{total} ({total_ok / total * 100:.1f}%)"
        if total
        else "  total:      0"
    )
    log(f"  time:       {elapsed:.1f}s")
    if total and elapsed:
        log(f"  per/sec:    {total / elapsed:.1f}")
    log("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test Telegram proxies")
    parser.add_argument(
        "--output-dir", default=None, help="output directory (default: ../githubmirror)"
    )
    args = parser.parse_args()
    run(output_dir=args.output_dir)

#!/usr/bin/env python3
"""Analyze url_stats.json — top sources, dead URLs, section breakdown.

Usage:
    cd source
    python scripts/analyze_url_stats.py
    python scripts/analyze_url_stats.py --dead       # only show dead URLs
    python scripts/analyze_url_stats.py --top 10      # show top N sources
"""
import argparse
import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)


def run(top_n: int, dead_only: bool) -> None:
    stats_path = os.path.join(PROJECT_ROOT, "data", "url_stats.json")
    urls_txt_path = os.path.join(PROJECT_ROOT, "config", "URLS.txt")

    if not os.path.exists(stats_path):
        print(f"stats file not found: {stats_path}")
        print("run main.py first to generate url_stats.json")
        sys.exit(1)

    with open(stats_path) as f:
        stats = json.load(f)

    section_map = _build_section_map(urls_txt_path)

    print(f"total entries in stats: {len(stats)}")
    print()

    by_yield = []
    dead = []
    no_yield_failed = []
    no_yield_unknown = []

    for url, entry in stats.items():
        if url.startswith("MANUAL_") or url == "DAILY_REPO":
            continue

        fetch = entry.get("fetch", {})
        fails = fetch.get("consecutive_failures", 0)
        if fails >= 3:
            dead.append((url, fails))
            continue

        yd = entry.get("yield")
        if not yd:
            hist = fetch.get("history", [])
            all_failed = all(not h.get("success", False) for h in hist) if hist else False
            if all_failed:
                no_yield_failed.append(url)
            else:
                no_yield_unknown.append(url)
            continue

        by_yield.append((
            yd.get("raw", 0),
            yd.get("secure", 0),
            yd.get("verified", 0),
            section_map.get(url, "?"),
            url,
        ))

    if dead_only:
        _print_dead(dead)
        return

    _print_top("verified configs", sorted(by_yield, key=lambda x: -x[2]), top_n, "ver")
    _print_top("raw configs", sorted(by_yield, key=lambda x: -x[0]), top_n, "raw")
    _print_top("secure configs", sorted(by_yield, key=lambda x: -x[1]), top_n, "sec")
    _print_wasteful(by_yield)
    _print_totals(by_yield, dead, no_yield_failed, no_yield_unknown)
    _print_by_section(by_yield)
    _print_dead(dead)


def _build_section_map(urls_txt_path: str) -> dict:
    """Map each URL in URLS.txt to its section label."""
    section_map = {}
    if not os.path.exists(urls_txt_path):
        return section_map

    current = "default"
    with open(urls_txt_path, encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if s.startswith("# "):
                sn = s[2:].strip().lower()
                if "yaml" in sn:
                    current = "yaml"
                elif "telegram" in sn or "tg" in sn:
                    current = "telegram"
                elif "extra" in sn or "bypass" in sn:
                    current = "extra_bypass"
                else:
                    current = "default"
            elif s and not s.startswith("#"):
                section_map[s] = current
    return section_map


def _print_top(title: str, data: list, top_n: int, label: str) -> None:
    if not data:
        return
    print(f"=== top {min(top_n, len(data))} by {title} ===")
    for raw, sec, ver, section, url in data[:top_n]:
        ratio = f"{ver / sec * 100:.0f}%" if sec else "-"
        print(f"  {label}={ver:>5} sec={sec:>6} raw={raw:>6} [{ratio:>4}] [{section}]  {url[:80]}")
    print()


def _print_wasteful(by_yield: list) -> None:
    """Sources with high raw count but near-zero verified output."""
    waste = [(r, s, v, u) for r, s, v, _, u in by_yield if r > 5_000 and v < 5]
    if not waste:
        return
    waste.sort(key=lambda x: -x[0])
    print("=== wasteful sources (raw>5k, verified<5) ===")
    for raw, sec, ver, url in waste[:15]:
        print(f"  raw={raw:>6} sec={sec:>6} ver={ver:>5}  {url[:80]}")
    print()


def _print_totals(by_yield: list, dead: list, no_yield_failed: list, no_yield_unknown: list) -> None:
    all_raw = sum(r for r, _, _, _, _ in by_yield)
    all_sec = sum(s for _, s, _, _, _ in by_yield)
    all_ver = sum(v for _, _, v, _, _ in by_yield)
    print("=== totals ===")
    print(f"  raw:      {all_raw:>8,}")
    print(f"  secure:   {all_sec:>8,}")
    print(f"  verified: {all_ver:>8,}")
    print(f"  sources with yield:     {len(by_yield)}")
    print(f"  dead (3+ fails):        {len(dead)}")
    print(f"  no yield (all failed):  {len(no_yield_failed)}")
    print(f"  no yield (other):       {len(no_yield_unknown)}")
    print()


def _print_by_section(by_yield: list) -> None:
    sections = {}
    for raw, sec, ver, section, _ in by_yield:
        s = sections.setdefault(section, {"urls": 0, "raw": 0, "sec": 0, "ver": 0})
        s["urls"] += 1
        s["raw"] += raw
        s["sec"] += sec
        s["ver"] += ver
    if not sections:
        return
    print("=== by section ===")
    for sn, s in sorted(sections.items(), key=lambda x: -x[1]["ver"]):
        print(f"  [{sn:>12}] urls={s['urls']:>4} raw={s['raw']:>8,} sec={s['sec']:>8,} ver={s['ver']:>5,}")
    print()


def _print_dead(dead: list) -> None:
    if not dead:
        print("no dead URLs")
        print()
        return
    dead.sort(key=lambda x: -x[1])
    print("=== dead URLs (3+ consecutive failures) ===")
    for url, fails in dead:
        print(f"  [{fails}x] {url[:90]}")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze URL statistics")
    parser.add_argument("--top", type=int, default=20, help="show top N sources (default: 20)")
    parser.add_argument("--dead", action="store_true", help="only show dead URLs")
    args = parser.parse_args()
    run(args.top, args.dead)

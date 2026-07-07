#!/usr/bin/env python3
"""Remove stale GitHub URLs from URLS.txt by checking last commit date.

Only checks URLs pointing to raw.githubusercontent.com or github.com.
Uses GitHub API (authenticated recommended — 5000 req/hr vs 60 req/hr).
Paces requests dynamically based on auth status.

Usage:
    cd source
    python scripts/purge_stale_urls.py                    # dry run (default)
    python scripts/purge_stale_urls.py --apply             # actually remove
    python scripts/purge_stale_urls.py --days 60 --apply   # custom threshold
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple, List, Any
from urllib.parse import urlparse

import requests

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

URLS_FILE = os.path.join(PROJECT_ROOT, "config", "URLS.txt")
CACHE_PATH = os.path.join(PROJECT_ROOT, "data", "stale_urls_cache.json")

# Load .env from project root (parent of source/)
from dotenv import load_dotenv
_env_path = os.path.join(os.path.dirname(PROJECT_ROOT), ".env")
if os.path.exists(_env_path):
    load_dotenv(_env_path)

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("MY_TOKEN")

# Rate limiting: GitHub allows 5000 req/hr authenticated, 60 req/hr unauthenticated.
# Delay between requests is paced dynamically in run() based on auth status.
_REQUEST_DELAY = 1.2 if GITHUB_TOKEN else 65.0  # 1.2s/auth (~3000/hr) vs 65s/unauth (~55/hr)
_MAX_RETRIES = 3


def parse_github_url(url: str) -> Optional[Tuple[str, str, str, str]]:
    """Parse a GitHub URL into (owner, repo, branch, path) or None.

    Handles raw.githubusercontent.com and github.com URLs. For
    raw.githubusercontent.com correctly splits refs/heads/branch paths.
    """
    url = url.split("#")[0].split("?")[0]
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    try:
        if host == "raw.githubusercontent.com":
            segments = parsed.path.strip("/").split("/")
            if len(segments) < 4:
                return None
            owner, repo = segments[0], segments[1]

            if segments[2] == "refs" and len(segments) >= 5:
                branch = segments[4]
                file_path = "/".join(segments[5:])
            else:
                branch = segments[2]
                file_path = "/".join(segments[3:])

            return owner, repo, branch, file_path

        elif host == "github.com":
            parts = parsed.path.strip("/").split("/", 5)
            if len(parts) >= 5 and parts[2] in ("blob", "raw"):
                return parts[0], parts[1], parts[3], "/".join(parts[4:])
    except (ValueError, IndexError):
        pass
    return None


def make_cache_key(parsed: Tuple[str, str, str, str]) -> str:
    """Cache key includes owner/repo/branch/path so same file on
    different branches doesn't share a cache entry."""
    return f"{parsed[0]}/{parsed[1]}/{parsed[2]}/{parsed[3]}"


def build_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({"Accept": "application/vnd.github.v3+json"})
    if GITHUB_TOKEN:
        session.headers.update({"Authorization": f"Bearer {GITHUB_TOKEN}"})
    return session


def check_rate_limit(session: requests.Session) -> Tuple[int, int]:
    """Check remaining API quota. Returns (remaining, limit)."""
    try:
        resp = session.get("https://api.github.com/rate_limit", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            core = data["resources"]["core"]
            return core["remaining"], core["limit"]
    except (requests.RequestException, KeyError, ValueError):
        pass
    return 0, 0


def wait_if_needed(headers: Any) -> bool:
    """Parse rate limit headers and sleep if we're close to the limit.

    Returns True if we waited, False if no wait needed.
    """
    remaining = headers.get("X-RateLimit-Remaining")
    reset_at = headers.get("X-RateLimit-Reset")
    retry_after = headers.get("Retry-After")

    if remaining is not None:
        remaining = int(remaining)

    # Secondary rate limit — backoff with Retry-After
    if retry_after is not None:
        wait = int(retry_after) + 2
        print(f"  secondary rate limit hit, sleeping {wait}s...", flush=True)
        time.sleep(wait)
        return True

    # Primary rate limit running low
    if remaining is not None and reset_at is not None and remaining < 10:
        reset_ts = int(reset_at)
        now = time.time()
        if reset_ts > now:
            wait = min(reset_ts - now + 2, 300)
            print(f"  rate limit nearly exhausted ({remaining} left), sleeping {wait:.0f}s until reset...", flush=True)
            time.sleep(wait)
            return True

    return False


def get_last_commit_date(
    session: requests.Session, owner: str, repo: str, path: str, branch: str
) -> Tuple[Optional[str], bool]:
    """Check the last commit date for a file via GitHub Commits API.

    Returns:
        (date_string or None, is_error)
        - (iso_date, False): file found, last commit date known
        - (None, False): file doesn't exist or branch not found (404/422) — remove
        - (None, True): API error (timeout, rate limit, server error) — keep URL
    """
    api_url = f"https://api.github.com/repos/{owner}/{repo}/commits"
    params = {"path": path, "per_page": 1, "sha": branch}

    for attempt in range(_MAX_RETRIES):
        try:
            resp = session.get(api_url, params=params, timeout=15)

            # Success
            if resp.status_code == 200:
                data = resp.json()
                if data:
                    date_str = data[0]["commit"]["committer"]["date"].replace("Z", "+00:00")
                    return date_str, False
                return None, False  # empty response — no commits for this file

            # File/branch definitively doesn't exist — safe to remove
            if resp.status_code in (404, 422):
                return None, False

            # Repository access issues — treat as not found, safe to remove
            if resp.status_code == 409:
                return None, False

            # Empty response, no content
            if resp.status_code == 204:
                return None, False

            # Rate limited
            if resp.status_code in (403, 429):
                waited = wait_if_needed(resp.headers)
                if waited:
                    continue  # retry after backoff
                # No Retry-After header — wait exponentially
                if attempt < _MAX_RETRIES - 1:
                    backoff = 2 ** (attempt + 1) * 5
                    print(f"  rate limited (status {resp.status_code}), retrying in {backoff}s...", flush=True)
                    time.sleep(backoff)
                    continue
                return None, True  # can't recover — uncertain

            # Server error — transient, retry
            if 500 <= resp.status_code < 600:
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(2 ** attempt * 2)
                    continue
                return None, True  # server error after retries — uncertain

            # Unexpected status
            print(f"  unexpected status {resp.status_code} for {owner}/{repo}/{path}, skipping", flush=True)
            return None, True

        except requests.Timeout:
            if attempt < _MAX_RETRIES - 1:
                print(f"  timeout, retrying ({attempt + 1}/{_MAX_RETRIES})...", flush=True)
                time.sleep(2 ** attempt * 2)
                continue
            return None, True

        except requests.RequestException as e:
            if attempt < _MAX_RETRIES - 1:
                print(f"  request error: {e}, retrying ({attempt + 1}/{_MAX_RETRIES})...", flush=True)
                time.sleep(2)
                continue
            return None, True

    return None, True


def collect_github_urls() -> List[Tuple[int, str, Tuple[str, str, str, str]]]:
    if not os.path.exists(URLS_FILE):
        print(f"ERROR: {URLS_FILE} not found")
        sys.exit(1)

    with open(URLS_FILE, encoding="utf-8") as f:
        lines = f.readlines()

    entries: List[Tuple[int, str, Tuple[str, str, str, str]]] = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parsed = parse_github_url(stripped)
        if parsed:
            entries.append((i, stripped, parsed))

    return entries


def load_cache() -> dict:
    if not os.path.exists(CACHE_PATH):
        return {}
    try:
        with open(CACHE_PATH) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def save_cache(cache: dict) -> None:
    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
    try:
        with open(CACHE_PATH, "w") as f:
            json.dump(cache, f, indent=2)
    except OSError as e:
        print(f"warning: could not save cache: {e}")


def run(dry_run: bool, stale_days: int) -> None:
    session = build_session()
    cache = load_cache()
    entries = collect_github_urls()
    threshold = timedelta(days=stale_days)
    now = datetime.now(timezone.utc)

    # Warm up: check rate limit before starting
    remaining, limit = check_rate_limit(session)
    auth_status = f"authenticated ({limit} req/hr)" if GITHUB_TOKEN else f"unauthenticated ({limit} req/hr)"

    print(f"checking {len(entries)} GitHub URLs (threshold: {stale_days}d)")
    print(f"auth: {auth_status}")
    print(f"rate limit: {remaining}/{limit} remaining")
    print(f"mode: {'DRY RUN (no changes)' if dry_run else 'APPLY (will remove stale URLs)'}")

    if GITHUB_TOKEN and remaining < len(entries):
        print(f"warning: only {remaining} requests available, need {len(entries)}.")
    elif not GITHUB_TOKEN:
        print(f"note: pacing at {_REQUEST_DELAY:.0f}s/request (~{int(3600/_REQUEST_DELAY)} req/hr) for unauthenticated access")
        if remaining < 5:
            print("  rate limit nearly exhausted. try again later or set GITHUB_TOKEN.")
            return

    print()

    results: List[Tuple[str, Optional[str], bool]] = []
    done = 0
    fresh_count = 0
    stale_count = 0
    error_count = 0
    skipped_count = 0

    for entry in entries:
        idx, url, parsed = entry
        cache_key = make_cache_key(parsed)

        # Check cache first
        cached = cache.get(cache_key)
        if cached and cached.get("date"):
            dt = datetime.fromisoformat(cached["date"])
            is_stale = (now - dt) > threshold
            results.append((url, cached["date"], is_stale))
            if is_stale:
                stale_count += 1
            else:
                fresh_count += 1
            done += 1
            if done % 100 == 0 or done == len(entries) or done == 1:
                print(f"  progress: {done}/{len(entries)} (cached, fresh={fresh_count}, stale={stale_count}, errors={error_count}, skipped={skipped_count})")
            continue

        # Cache hit with error marker — keep URL (uncertain last time, still uncertain)
        if cached and cached.get("error"):
            fresh_count += 1
            results.append((url, None, False))
            done += 1
            continue

        # Make API call
        date_str, is_error = get_last_commit_date(session, *parsed)
        time.sleep(_REQUEST_DELAY)  # pace ourselves

        if is_error:
            # API error — uncertain, keep URL
            results.append((url, None, False))
            skipped_count += 1
            cache[cache_key] = {"date": None, "error": True}
        elif date_str:
            dt = datetime.fromisoformat(date_str)
            is_stale = (now - dt) > threshold
            results.append((url, date_str, is_stale))
            if is_stale:
                stale_count += 1
            else:
                fresh_count += 1
            cache[cache_key] = {"date": date_str, "stale": is_stale}
        else:
            # File not found (404/422) — definitely stale
            results.append((url, None, True))
            stale_count += 1
            cache[cache_key] = {"date": None, "stale": True}

        done += 1
        if done % 100 == 0 or done == len(entries) or done == 1:
            print(f"  progress: {done}/{len(entries)} (fresh={fresh_count}, stale={stale_count}, errors={error_count}, skipped={skipped_count})")
            save_cache(cache)

    # Save final cache
    save_cache(cache)

    stale_urls = [(url, d) for url, d, s in results if s]
    fresh_urls = [(url, d) for url, d, s in results if not s and d]

    print()
    fresh_print = fresh_count
    stale_print = stale_count
    print(f"results: {fresh_print} fresh, {stale_print} stale, {error_count} errors, {skipped_count} skipped (API error, kept)")

    if stale_urls:
        aged = []
        for url, date_str in stale_urls:
            if date_str:
                age = (now - datetime.fromisoformat(date_str)).days
            else:
                age = -1
            aged.append((age, url, date_str))
        aged.sort(key=lambda x: -x[0])

        print()
        print(f"stale URLs ({len(aged)}):")
        for age, url, date_str in aged:
            label = f"[{age:>4}d]" if age >= 0 else "[  ???]"
            print(f"  {label} {url[:90]}")

        buckets = [(30, 60), (60, 90), (90, 180), (180, 365), (365, 9999)]
        print()
        print("breakdown by age:")
        for lo, hi in buckets:
            count = sum(1 for a, _, _ in aged if lo <= a < hi)
            if count:
                print(f"  {lo}-{hi}d: {count}")
        unknown = sum(1 for a, _, _ in aged if a < 0)
        if unknown:
            print(f"  unknown (no commit data): {unknown}")

    if dry_run:
        print()
        print("dry run — no changes made.")
        print(f"run with --apply to remove {len(stale_urls)} stale URLs.")
        print()
        return

    # Remove stale lines
    stale_set = {url for url, _ in stale_urls}
    with open(URLS_FILE, encoding="utf-8") as f:
        all_lines = f.readlines()

    new_lines = []
    removed = []
    for line in all_lines:
        stripped = line.strip()
        if stripped in stale_set:
            removed.append(stripped)
            continue
        new_lines.append(line)

    # Backup with timestamp to avoid overwriting previous backups
    ts = now.strftime("%Y%m%d_%H%M%S")
    backup = f"{URLS_FILE}.stale.{ts}.backup"
    with open(backup, "w", encoding="utf-8") as f:
        f.writelines(all_lines)
    with open(URLS_FILE, "w", encoding="utf-8") as f:
        f.writelines(new_lines)

    print()
    print(f"removed {len(removed)} stale URLs from URLS.txt")
    print(f"backup saved to: {backup}")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Remove stale GitHub URLs from URLS.txt")
    parser.add_argument("--apply", action="store_true", help="actually remove (default: dry run)")
    parser.add_argument("--days", type=int, default=30, help="stale threshold in days (default: 30)")
    args = parser.parse_args()
    run(dry_run=not args.apply, stale_days=args.days)

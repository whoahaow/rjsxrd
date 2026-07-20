#!/usr/bin/env python
"""Download Xray-core binary for config testing.

Supports: Windows (x86_64), Linux (x86_64, arm64), macOS (x86_64, arm64)
"""

import os
import sys
import platform
import json
import urllib.request
import urllib.error
import subprocess
import zipfile
import tarfile
import re
from pathlib import Path
from typing import Optional, Tuple
from utils.logger import log

# Xray-core version — override with env XRAY_VERSION to pin a specific version.
# When unset or empty, auto-update fetches the latest release from GitHub.
XRAY_VERSION = os.environ.get("XRAY_VERSION") or ""

# Base URL for Xray-core releases
GITHUB_RELEASES_URL = "https://github.com/XTLS/Xray-core/releases/download"
GITHUB_API_URL = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"


def _parse_version(version_str: str) -> Optional[Tuple[int, int, int]]:
    """Parse a version string like 'v26.2.6' or '26.2.6' into (26, 2, 6)."""
    clean = version_str.lstrip("vV")
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", clean)
    if match:
        return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    return None


def _compare_versions(a: str, b: str) -> int:
    """Compare two version strings. Returns -1 if a < b, 0 if equal, 1 if a > b."""
    va = _parse_version(a)
    vb = _parse_version(b)
    if va is None or vb is None:
        return 0  # can't parse, assume equal
    if va < vb:
        return -1
    if va > vb:
        return 1
    return 0


def get_current_xray_version(xray_path: Path) -> Optional[str]:
    """Get the installed xray version by running 'xray version'.

    Returns version string like 'v26.2.6' or None if can't determine.
    """
    try:
        result = subprocess.run(
            [str(xray_path), "version"],
            capture_output=True, text=True, timeout=10,
        )
        # Parse first line: "Xray 26.2.6 (Xray, Penetrates Everything.) ..."
        line = result.stdout.split("\n")[0] if result.stdout else ""
        match = re.search(r"Xray\s+v?(\d+\.\d+\.\d+)", line)
        if match:
            return f"v{match.group(1)}"
        return None
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


def fetch_latest_xray_version() -> Optional[str]:
    """Fetch the latest xray-core release version from GitHub.

    Tries two methods:
      1. GitHub API (api.github.com) — fast but may be rate-limited or blocked
      2. Releases page redirect — follows /releases/latest → /releases/tag/vX.Y.Z

    Returns version string like '26.4.1' or None if all methods fail.
    """
    # Method 1: GitHub API
    try:
        req = urllib.request.Request(
            GITHUB_API_URL,
            headers={"User-Agent": "rjsxrd/1.0", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            tag = data.get("tag_name", "")
            if tag:
                return tag
    except (urllib.error.URLError, json.JSONDecodeError, OSError, ValueError):
        pass

    # Method 2: Follow /releases/latest redirect to get version from URL
    try:
        req = urllib.request.Request(
            "https://github.com/XTLS/Xray-core/releases/latest",
            headers={"User-Agent": "rjsxrd/1.0"},
            method="HEAD",
        )
        # Don't follow redirect — we want the redirect URL to parse the version
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None  # stop at redirect, return it as response

        opener = urllib.request.build_opener(_NoRedirect)
        with opener.open(req, timeout=10) as resp:
            redirect_url = resp.headers.get("Location", "")
            # URL format: /XTLS/Xray-core/releases/tag/v26.4.1
            match = re.search(r"/tag/v?(\d+\.\d+\.\d+)", redirect_url)
            if match:
                return "v" + match.group(1)
    except (urllib.error.URLError, OSError, ValueError):
        pass

    return None


def get_platform_info() -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Detect current platform and return download info.
    
    Returns:
        tuple: (platform_string, filename, xray_binary_name) or (None, None, None) if unsupported
    """
    system = sys.platform
    machine = platform.machine().lower()
    
    # Map platform to Xray release filename
    platform_map = {
        # Windows
        ("win32", "amd64"): ("windows-64", "Xray-windows-64.zip", "xray.exe"),
        ("win32", "x86_64"): ("windows-64", "Xray-windows-64.zip", "xray.exe"),
        ("win32", "arm64"): ("windows-arm64-v8a", "Xray-windows-arm64-v8a.zip", "xray.exe"),
        
        # Linux
        ("linux", "amd64"): ("linux-64", "Xray-linux-64.zip", "xray"),
        ("linux", "x86_64"): ("linux-64", "Xray-linux-64.zip", "xray"),
        ("linux", "arm64"): ("linux-arm64-v8a", "Xray-linux-arm64-v8a.zip", "xray"),
        ("linux", "aarch64"): ("linux-arm64-v8a", "Xray-linux-arm64-v8a.zip", "xray"),
        
        # macOS
        ("darwin", "amd64"): ("macos-64", "Xray-macos-64.zip", "xray"),
        ("darwin", "x86_64"): ("macos-64", "Xray-macos-64.zip", "xray"),
        ("darwin", "arm64"): ("macos-arm64-v8a", "Xray-macos-arm64-v8a.zip", "xray"),
    }
    
    key = (system, machine)
    if key in platform_map:
        return platform_map[key]
    
    # Fallback for unknown architectures
    if system == "win32":
        return ("windows-64", "Xray-windows-64.zip", "xray.exe")
    elif system == "linux":
        return ("linux-64", "Xray-linux-64.zip", "xray")
    elif system == "darwin":
        return ("macos-64", "Xray-macos-64.zip", "xray")
    
    return None, None, None


def download_file(url, dest_path, show_progress=True) -> bool:
    """Download file with progress indicator.
    
    Returns:
        bool: True if successful, False otherwise
    """
    def reporthook(blocknum, blocksize, totalsize) -> None:
        if totalsize > 0 and show_progress:
            readsofar = blocknum * blocksize
            percent = readsofar * 100 / totalsize
            downloaded_mb = readsofar / 1024 / 1024
            total_mb = totalsize / 1024 / 1024
            # Use stderr for progress to avoid conflicts with tqdm
            print(f"\rProgress: {percent:5.1f}% ({downloaded_mb:.1f}MB / {total_mb:.1f}MB)", end='', file=sys.stderr, flush=True)
    
    try:
        urllib.request.urlretrieve(url, dest_path, reporthook)
        if show_progress:
            print(file=sys.stderr)  # Newline after progress
        return True
    except (urllib.error.URLError, OSError, ValueError) as e:
        if show_progress:
            print(file=sys.stderr)
        log(f"Download failed: {e}")
        return False


def extract_archive(archive_path, extract_dir) -> bool:
    """Extract zip or tar.gz archive.
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        if archive_path.suffix == ".zip":
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
        elif archive_path.suffix in [".gz", ".xz"]:
            with tarfile.open(archive_path, 'r:*') as tar_ref:
                tar_ref.extractall(extract_dir)
        else:
            log(f"Unsupported archive format: {archive_path.suffix}")
            return False
        return True
    except (zipfile.BadZipFile, tarfile.ReadError, OSError, ValueError) as e:
        log(f"Extraction failed: {e}")
        return False


def _clean_xray_dir(xray_dir: Path, xray_exe: str) -> None:
    """Remove xray binary and extracted assets from xray_dir."""
    for f in xray_dir.iterdir():
        try:
            if f.is_file():
                f.unlink()
            elif f.is_dir():
                import shutil
                shutil.rmtree(f)
        except OSError:
            pass


def ensure_xray_installed(version=None, xray_dir=None, force=False,
                          auto_update=True) -> Optional[Path]:
    """Ensure Xray-core is installed and up-to-date.

    By default fetches the latest version from GitHub. Override with
    env XRAY_VERSION to pin a specific version.

    Auto-update logic:
      1. If xray exists and auto_update is on → check version against latest
         release. If outdated, download latest. If current, skip.
      2. If xray exists and auto_update is off → use current binary as-is.
      3. If xray doesn't exist → fetch latest from GitHub API and download.

    Args:
        version: Xray-core version to pin (default: None = auto-detect latest).
        xray_dir: Custom installation directory (default: source/xray).
        force: Force re-download even if already installed and up-to-date.
        auto_update: Check GitHub API for latest version and update if newer.

    Returns:
        Path: Path to xray binary if successful, None otherwise.
    """
    # Determine xray directory - always install to source/xray (sibling to utils/)
    if xray_dir is None:
        xray_dir = Path(__file__).parent.parent / "xray"
    else:
        xray_dir = Path(xray_dir)

    # Get platform info
    platform_name, filename, xray_exe = get_platform_info()

    if not platform_name:
        log(f"Error: Unsupported platform: {sys.platform} ({platform.machine()})")
        return None

    xray_path = xray_dir / xray_exe
    target_version = version

    # ── Auto-update: check current vs latest ──────────────────────────
    if xray_path.exists() and not force:
        if auto_update:
            current_ver = get_current_xray_version(xray_path)
            latest_ver = fetch_latest_xray_version()
            if current_ver and latest_ver:
                cmp = _compare_versions(current_ver, latest_ver)
                if cmp < 0:
                    log(f"Xray update: {current_ver} -> {latest_ver}")
                    target_version = latest_ver
                    _clean_xray_dir(xray_dir, xray_exe)
                elif cmp == 0:
                    log(f"Xray {current_ver} is current")
                    return xray_path
                else:
                    log(f"Xray {current_ver} is newer than latest {latest_ver} - keeping")
                    return xray_path
            elif current_ver:
                log(f"Xray {current_ver} (could not check for updates)")
                return xray_path
            else:
                log("Xray found but version unknown - re-downloading")
                _clean_xray_dir(xray_dir, xray_exe)
        else:
            return xray_path
    elif xray_path.exists() and force:
        _clean_xray_dir(xray_dir, xray_exe)

    # ── Resolve target version ───────────────────────────────────────
    if not target_version:
        # No version specified — fetch latest from API
        target_version = fetch_latest_xray_version()
        if not target_version:
            log("Could not fetch latest xray version from GitHub - aborting")
            return None
        log(f"Latest xray version: {target_version}")

    # ── Download ─────────────────────────────────────────────────────
    xray_dir.mkdir(parents=True, exist_ok=True)

    url = f"{GITHUB_RELEASES_URL}/{target_version}/{filename}"
    log(f"Downloading Xray-core {target_version} for {platform_name}...")
    log(f"URL: {url}")

    download_path = Path(filename)
    if not download_file(url, download_path):
        return None

    log(f"Extracting {filename} to {xray_dir}/...")
    if not extract_archive(download_path, xray_dir):
        return None

    # Cleanup
    try:
        download_path.unlink()
    except OSError:
        pass

    # Make executable on Unix
    if sys.platform != "win32":
        try:
            os.chmod(xray_path, 0o755)
        except (OSError, PermissionError) as e:
            log(f"Warning: Could not set executable permission: {e}")

    log(f"✓ Xray-core {target_version} installed: {xray_path.absolute()}")
    return xray_path


def download_xray(version=XRAY_VERSION) -> Optional[Path]:
    """Legacy function - use ensure_xray_installed() instead."""
    return ensure_xray_installed(version)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Download Xray-core binary")
    parser.add_argument("--version", default=XRAY_VERSION, help=f"Xray version (default: {XRAY_VERSION})")
    parser.add_argument("--force", action="store_true", help="Force re-download")
    parser.add_argument("--output", help="Custom output directory")
    args = parser.parse_args()
    
    result = ensure_xray_installed(version=args.version, xray_dir=args.output, force=args.force)
    if result:
        log(f"\nSuccess: {result}")
        sys.exit(0)
    else:
        print("\nFailed to install Xray-core", file=sys.stderr)
        sys.exit(1)

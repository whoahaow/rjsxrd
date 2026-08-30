"""Fetcher module for downloading VPN configs using curl_cffi for speed."""

import os
import re
import time
import base64
import json
import warnings
from dataclasses import dataclass
from curl_cffi.requests import Session
import requests
from typing import Optional
from config.settings import CHROME_UA, GITHUB_API_FALLBACK

# Suppress SSL warnings when verify=False
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


@dataclass
class FetchResult:
    """Structured result from fetch_data with status info instead of exceptions."""
    text: str = ""
    status_code: int = 0
    error: str = ""
    success: bool = True


def _extract_status(exc: Exception) -> int:
    """Extract HTTP status code from various exception types."""
    if hasattr(exc, 'response') and hasattr(exc.response, 'status_code'):
        return exc.response.status_code
    if hasattr(exc, 'status_code'):
        return exc.status_code
    return 0


def _get_env_proxy() -> Optional[str]:
    """Get proxy from environment variables (set by main.py --proxy arg)."""
    return os.environ.get('HTTPS_PROXY') or os.environ.get('HTTP_PROXY') or os.environ.get('ALL_PROXY')


def _get_github_token() -> Optional[str]:
    """Get GitHub token from environment (set by .env via config/settings.py).

    Used as fallback when callers don't pass token explicitly.
    """
    return os.environ.get('GITHUB_TOKEN')


def _raw_to_api_url(url: str) -> Optional[str]:
    """Convert GitHub raw/blob URLs to API contents URL.

    Handles:
      raw.githubusercontent.com/owner/repo/refs/heads/branch/path
      raw.githubusercontent.com/owner/repo/branch/path
      github.com/owner/repo/raw/refs/heads/branch/path
      github.com/owner/repo/raw/branch/path
      github.com/owner/repo/blob/branch/path

    Output: api.github.com/repos/owner/repo/contents/path?ref=branch
    """
    # raw.githubusercontent.com with refs/heads/
    m = re.match(
        r'https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)/refs/heads/([^/]+)/(.+)',
        url
    )
    if m:
        owner, repo, branch, path = m.groups()
        return f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}"

    # raw.githubusercontent.com without refs/heads/
    m = re.match(
        r'https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)',
        url
    )
    if m:
        owner, repo, branch, path = m.groups()
        return f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}"

    # github.com/owner/repo/raw/refs/heads/branch/path
    m = re.match(
        r'https?://github\.com/([^/]+)/([^/]+)/raw/refs/heads/([^/]+)/(.+)',
        url
    )
    if m:
        owner, repo, branch, path = m.groups()
        return f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}"

    # github.com/owner/repo/raw/branch/path
    m = re.match(
        r'https?://github\.com/([^/]+)/([^/]+)/raw/([^/]+)/(.+)',
        url
    )
    if m:
        owner, repo, branch, path = m.groups()
        return f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}"

    # github.com/owner/repo/blob/branch/path
    m = re.match(
        r'https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)',
        url
    )
    if m:
        owner, repo, branch, path = m.groups()
        return f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}"

    return None


def _is_github_url(url: str) -> bool:
    """Check if URL is a GitHub raw/blob URL that can be converted to API format."""
    return _raw_to_api_url(url) is not None


def _fetch_via_api(
    url: str,
    token: Optional[str] = None,
    session: Optional[Session] = None,
    timeout: int = 5,
) -> Optional[str]:
    """Fetch file content via GitHub API (base64 decoded).

    Returns decoded text on success, None on failure.
    """
    api_url = _raw_to_api_url(url)
    if not api_url:
        return None

    try:
        sess = session or build_session()
        headers = {}
        if token:
            headers["Authorization"] = f"token {token}"

        resp = sess.get(api_url, timeout=timeout, headers=headers or None)
        resp.raise_for_status()
        data = resp.json()

        if "content" in data and data.get("encoding") == "base64":
            return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")

        return None
    except Exception:
        return None


def build_session(max_pool_size: int = 4, proxy_url: Optional[str] = None) -> Session:
    """Builds a curl_cffi session with proper proxy support.

    Args:
        max_pool_size: Connection pool size (used for compatibility, curl_cffi handles pooling internally)
        proxy_url: Optional proxy URL (e.g., 'socks5h://127.0.0.1:10808').
                    If not provided, checks environment variables.

    Note: Uses curl_cffi for better performance and TLS fingerprinting.
    """
    # Use provided proxy or fall back to environment variable
    effective_proxy = proxy_url or _get_env_proxy()

    # Create curl_cffi session with Chrome impersonation
    session = Session(impersonate="chrome124")

    # Configure proxy if present
    if effective_proxy:
        session.proxies = {
            'http': effective_proxy,
            'https': effective_proxy,
        }

    # Set user agent
    session.headers.update({"User-Agent": CHROME_UA})

    return session


def fetch_data(url: str, timeout: int = 5, max_attempts: int = 3, session=None, proxy_url: Optional[str] = None, token: Optional[str] = None) -> FetchResult:
    """Fetches data from URL with retry logic, fallbacks, and optional auth.

    Returns FetchResult instead of raising exceptions — always inspect .success first.

    Args:
        url: URL to fetch
        timeout: Request timeout in seconds (default: 5)
        max_attempts: Number of retry attempts (default: 3)
        session: Optional shared session. When provided, reuses it instead of
                 creating a new one. Reduces TLS handshake overhead across
                 multiple fetches. Token is sent per-request, not on the session.
        proxy_url: Optional proxy URL for routing request.
                  If not provided, uses environment variable (set by --proxy arg).
        token: Optional Bearer token. Only sent for GitHub URLs (github.com / raw.githubusercontent.com).

    Retry strategy:
        attempt 1: normal with verify=True
        attempt 2: verify=False (skip SSL cert check)
        attempt 3: downgrade HTTPS to HTTP (for DPI/workaround)
        attempt 4: GitHub API fallback (for raw.githubusercontent.com IP blocks)

    Note: Uses curl_cffi for better performance and TLS fingerprinting.
    """
    # Use provided proxy or fall back to environment
    effective_proxy = proxy_url or _get_env_proxy()

    # Auto-detect token: use provided, or fall back to env
    effective_token = token or _get_github_token()

    # Only pass token for GitHub URLs — avoids leaking auth to random hosts
    is_github_url = 'github.com' in url or 'raw.githubusercontent.com' in url
    request_token = effective_token if effective_token and is_github_url else None

    # Create or reuse session. When reusing, token is passed per-request
    # instead of being baked into the session, so a shared session is safe
    # for both authenticated and non-authenticated URLs.
    sess = session
    if sess is None:
        sess = build_session(max_pool_size=4, proxy_url=effective_proxy)

    # Per-request auth header (not on session, to avoid leaking to
    # non-GitHub hosts when using a shared session)
    extra_headers = {}
    if request_token:
        extra_headers["Authorization"] = f"token {request_token}"

    # If API fallback enabled and URL is GitHub — go straight to API, skip retries
    if GITHUB_API_FALLBACK and _is_github_url(url):
        api_token = request_token or _get_github_token()
        api_content = _fetch_via_api(url, token=api_token, session=sess, timeout=timeout)
        if api_content:
            return FetchResult(text=api_content, status_code=200)
        # API also failed — fall through to normal retry loop as last resort

    for attempt in range(1, max_attempts + 1):
        try:
            modified_url = url
            verify = True

            if attempt == 2:
                verify = False
            elif attempt == 3:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                if parsed.scheme == "https":
                    modified_url = parsed._replace(scheme="http").geturl()
                verify = False

            response = sess.get(
                modified_url,
                timeout=timeout,
                verify=verify,
                allow_redirects=True,
                headers=extra_headers or None,
            )
            response.raise_for_status()
            return FetchResult(text=response.text, status_code=response.status_code)

        except (requests.RequestException, OSError, ValueError, TypeError) as exc:
            if attempt < max_attempts:
                time.sleep(1)
                continue

            return FetchResult(text="", status_code=_extract_status(exc), error=str(exc), success=False)

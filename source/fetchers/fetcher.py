"""Fetcher module for downloading VPN configs using curl_cffi for speed."""

import os
import time
import warnings
from dataclasses import dataclass
from curl_cffi.requests import Session
import requests
from typing import Optional
from config.settings import CHROME_UA

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


def build_session(max_pool_size: int = 4, proxy_url: Optional[str] = None, token: Optional[str] = None) -> Session:
    """Builds a curl_cffi session with proper proxy support and optional auth.
    
    Args:
        max_pool_size: Connection pool size (used for compatibility, curl_cffi handles pooling internally)
        proxy_url: Optional proxy URL (e.g., 'socks5h://127.0.0.1:10808').
                    If not provided, checks environment variables.
        token: Optional Bearer token for authenticated requests (e.g., GitHub token).
    
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
    
    # Add auth token if provided
    if token:
        session.headers.update({"Authorization": f"Bearer {token}"})
    
    return session


def fetch_data(url: str, timeout: int = 5, max_attempts: int = 3, session=None, proxy_url: Optional[str] = None, token: Optional[str] = None) -> FetchResult:
    """Fetches data from URL with retry logic, fallbacks, and optional auth.

    Returns FetchResult instead of raising exceptions — always inspect .success first.

    Args:
        url: URL to fetch
        timeout: Request timeout in seconds (default: 5)
        max_attempts: Number of retry attempts (default: 3)
        session: Optional existing session
        proxy_url: Optional proxy URL for routing request.
                  If not provided, uses environment variable (set by --proxy arg).
        token: Optional Bearer token. Only sent for GitHub URLs (github.com / raw.githubusercontent.com).

    Retry strategy:
        attempt 1: normal with verify=True
        attempt 2: verify=False (skip SSL cert check)
        attempt 3: downgrade HTTPS to HTTP (for DPI/workaround)

    Note: Uses curl_cffi for better performance and TLS fingerprinting.
    """
    # Use provided proxy or fall back to environment
    effective_proxy = proxy_url or _get_env_proxy()
    
    # Only pass token for GitHub URLs — avoids leaking auth to random hosts
    effective_token = token if token and ('github.com' in url or 'raw.githubusercontent.com' in url) else None
    
    sess = session or build_session(max_pool_size=4, proxy_url=effective_proxy, token=effective_token)
    
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
            )
            response.raise_for_status()
            return FetchResult(text=response.text, status_code=response.status_code)
            
        except (requests.RequestException, OSError, ValueError, TypeError) as exc:
            if attempt < max_attempts:
                time.sleep(1)
                continue
            return FetchResult(text="", status_code=_extract_status(exc), error=str(exc), success=False)
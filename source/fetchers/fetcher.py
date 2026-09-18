"""Fetcher module for downloading VPN configs using curl_cffi for speed."""

import base64
import os
import re
import threading
import time
import warnings
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from urllib.parse import urlparse

import requests
from curl_cffi.requests import Session

from config.settings import CHROME_UA, GITHUB_API_FALLBACK, REFUSE_INSECURE_FETCH
from utils.logger import log, warning

# The retry ladder in fetch_data() trades TLS verification for reachability:
# attempt 2 skips certificate verification and attempt 3 re-sends the request
# in the clear. That is deliberate — this pipeline runs on a network that
# interferes with TLS — but it is also the point where an attacker on the path
# can influence what gets fetched, and therefore what gets published. It used
# to be invisible: a process-wide warning filter installed at import time hid
# the client's own signal, and nothing counted how often a fetch took the
# downgrade. Every downgrade is now logged with its host, counted, and printed
# by report_insecure_fetches() at the end of a run. SECURITY.md records the
# threat; REFUSE_INSECURE_FETCH refuses the downgrades outright.

# The modes the ladder can use on an attempt.
_MODE_VERIFIED = "verified"
_MODE_UNVERIFIED = "unverified"
_MODE_PLAINTEXT = "plaintext"
_INSECURE_MODES = frozenset({_MODE_UNVERIFIED, _MODE_PLAINTEXT})


@dataclass
class FetchResult:
    """Structured result from fetch_data with status info instead of exceptions."""

    text: str = ""
    status_code: int = 0
    error: str = ""
    success: bool = True


@dataclass(frozen=True)
class InsecureFetchStats:
    """A snapshot of one run's TLS downgrades, as the report states them."""

    unverified_attempts: int = 0
    plaintext_attempts: int = 0
    unverified_hosts: tuple[str, ...] = ()
    plaintext_hosts: tuple[str, ...] = ()

    @property
    def attempts(self) -> int:
        """Attempts that skipped verification or went out in the clear."""
        return self.unverified_attempts + self.plaintext_attempts

    @property
    def hosts_affected(self) -> int:
        """Distinct hosts behind those attempts.

        A single host that downgraded on every attempt counts once: the number
        an operator needs is how much of the source list was fetched insecurely,
        not how many requests it took.
        """
        return len(set(self.unverified_hosts) | set(self.plaintext_hosts))


class _InsecureFetchCounter:
    """Counts the ladder's downgrades for the current run, thread-safely.

    The fetch pool runs these calls in dozens of threads, and nothing else
    aggregates them — without this a run in which every source was fetched
    without certificate validation reports exactly like a clean one.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._unverified_attempts = 0
        self._plaintext_attempts = 0
        self._unverified_hosts: set[str] = set()
        self._plaintext_hosts: set[str] = set()

    def record(self, mode: str, host: str) -> None:
        """Count one downgraded attempt on `host`."""
        with self._lock:
            if mode == _MODE_PLAINTEXT:
                self._plaintext_attempts += 1
                self._plaintext_hosts.add(host)
            elif mode == _MODE_UNVERIFIED:
                self._unverified_attempts += 1
                self._unverified_hosts.add(host)

    def reset(self) -> None:
        """Drop the run's counts — for a test, or a process that runs twice."""
        with self._lock:
            self._unverified_attempts = 0
            self._plaintext_attempts = 0
            self._unverified_hosts.clear()
            self._plaintext_hosts.clear()

    def snapshot(self) -> InsecureFetchStats:
        """A consistent copy of the counts, safe to report from."""
        with self._lock:
            return InsecureFetchStats(
                unverified_attempts=self._unverified_attempts,
                plaintext_attempts=self._plaintext_attempts,
                unverified_hosts=tuple(sorted(self._unverified_hosts)),
                plaintext_hosts=tuple(sorted(self._plaintext_hosts)),
            )


# One counter per process, which is one per run: every entry point imports this
# module once and runs the fetch stage once. Tests reset it per case.
INSECURE_FETCHES = _InsecureFetchCounter()


def report_insecure_fetches() -> InsecureFetchStats:
    """Log the run's TLS downgrades and return the snapshot it logged.

    Called at the end of a run next to the URL health report, so a run that
    downgraded its fetches is distinguishable from a clean one by reading the
    last lines of its output rather than by recounting the log. Names the hosts
    it affected, not just the total: "42 attempts" says nothing about whether
    one source or all of them went plaintext.
    """
    stats = INSECURE_FETCHES.snapshot()
    if stats.attempts == 0:
        log("[fetch-security] no fetch skipped TLS verification and none went out in the clear")
        return stats

    warning(
        f"[fetch-security] {stats.attempts} attempts on {stats.hosts_affected} host(s) "
        f"skipped TLS verification: {stats.unverified_attempts} unverified, "
        f"{stats.plaintext_attempts} plaintext — see SECURITY.md"
    )
    for host in stats.plaintext_hosts:
        warning(f"[fetch-security]   plaintext HTTP: {host}")
    for host in stats.unverified_hosts:
        warning(f"[fetch-security]   unverified TLS: {host}")
    return stats


def _extract_status(exc: Exception) -> int:
    """Extract HTTP status code from various exception types.

    Both clients are untyped here, so the attribute is read and validated
    rather than assumed; `0` is this module's "unknown status" sentinel.
    """
    response = getattr(exc, "response", None)
    status = getattr(response, "status_code", None)
    if isinstance(status, int):
        return status
    status = getattr(exc, "status_code", None)
    if isinstance(status, int):
        return status
    return 0


def _get_env_proxy() -> str | None:
    """Get proxy from environment variables (set by main.py --proxy arg)."""
    return (
        os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY") or os.environ.get("ALL_PROXY")
    )


def _get_github_token() -> str | None:
    """Get GitHub token from environment (set by .env via config/settings.py).

    Used as fallback when callers don't pass token explicitly.
    """
    return os.environ.get("GITHUB_TOKEN")


def _host_of(url: str) -> str:
    """The host of a URL, lower-cased, or "" when it carries none."""
    return (urlparse(url).hostname or "").lower()


def _attempt_mode(attempt: int, url: str) -> str:
    """Which mode the ladder uses on a given attempt for this URL.

    attempt 1: TLS with certificate verification
    attempt 2: TLS with verification skipped
    attempt 3: the same request over plaintext HTTP, verification skipped
    attempt 4 and beyond: verified TLS again, as the loop's previous
    `verify = True` default did for every attempt it did not rewrite

    The third attempt is only a downgrade when the URL is https; for an
    http URL it repeats the second, and the log says which of the two happened
    rather than claiming a downgrade that did not. Callers must not reorder
    these or drop the third — the order is what keeps the fetch yield up on a
    network that interferes with TLS (SECURITY.md).
    """
    if attempt == 2:
        return _MODE_UNVERIFIED
    if attempt == 3:
        return _MODE_PLAINTEXT if urlparse(url).scheme == "https" else _MODE_UNVERIFIED
    return _MODE_VERIFIED


def _log_downgrade(mode: str, host: str, attempt: int) -> None:
    """State, in the run's log, what this attempt costs.

    A downgrade that nothing reports is the defect this replaces: someone
    reading a run's output has to be able to see "this host was fetched without
    TLS verification" without reading this module.
    """
    if mode == _MODE_PLAINTEXT:
        warning(f"[fetch-security] attempt {attempt}: {host} is fetched over plaintext HTTP")
    else:
        warning(
            f"[fetch-security] attempt {attempt}: {host} is fetched without TLS "
            "certificate verification"
        )


@contextmanager
def _silence_client_tls_warning(verify: bool) -> Iterator[None]:
    """Silence the client's unverified-request warning for one call only.

    The ignore used to be installed at import time and applied to the whole
    process: every warning of that shape, from any module, for the rest of the
    run. It is scoped here to the single call that sets `verify=False`, so
    unrelated code keeps reporting its warnings, and this module's own signal
    for a downgrade is `_log_downgrade` — which names the host, where the
    client's generic warning does not.

    Caveat, because it is inherited rather than fixable here: the filter list
    `warnings.catch_warnings()` swaps is process-global and has no thread-local
    form, so two unverified calls overlapping in different threads can leave
    the ignore installed after both return. That window is narrow and it
    silences the same warning this call deliberately silences; what it cannot
    do is hide anything for a thread that never fetched insecurely *and* never
    overlapped one that did. A scoped leak is the trade accepted against a
    filter that was installed for the whole process at import.
    """
    if verify:
        yield
        return
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")
        yield


def _raw_to_api_url(url: str) -> str | None:
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
        r"https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)/refs/heads/([^/]+)/(.+)", url
    )
    if m:
        owner, repo, branch, path = m.groups()
        return f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}"

    # raw.githubusercontent.com without refs/heads/
    m = re.match(r"https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)", url)
    if m:
        owner, repo, branch, path = m.groups()
        return f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}"

    # github.com/owner/repo/raw/refs/heads/branch/path
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)/raw/refs/heads/([^/]+)/(.+)", url)
    if m:
        owner, repo, branch, path = m.groups()
        return f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}"

    # github.com/owner/repo/raw/branch/path
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)/raw/([^/]+)/(.+)", url)
    if m:
        owner, repo, branch, path = m.groups()
        return f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}"

    # github.com/owner/repo/blob/branch/path
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)", url)
    if m:
        owner, repo, branch, path = m.groups()
        return f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}"

    return None


def _is_github_url(url: str) -> bool:
    """Check if URL is a GitHub raw/blob URL that can be converted to API format."""
    return _raw_to_api_url(url) is not None


def _fetch_via_api(
    url: str,
    token: str | None = None,
    session: Session | None = None,
    timeout: int = 5,
) -> str | None:
    """Fetch file content via GitHub API.

    <1MB: JSON with base64 content (default)
    1-100MB: raw content via application/vnd.github.raw+json media type
    >100MB: not supported by GitHub API

    Returns decoded text on success, None on failure.
    """
    api_url = _raw_to_api_url(url)
    if not api_url:
        return None

    try:
        sess = session or build_session()

        # First, get file metadata (size + sha) via JSON
        headers = {"Accept": "application/vnd.github.v3+json"}
        if token:
            headers["Authorization"] = f"token {token}"

        resp = sess.get(api_url, timeout=timeout, headers=headers)

        if resp.status_code == 403:
            import sys

            print(f"[github-api] rate limited: {api_url[:80]}", file=sys.stderr)
            return None

        if resp.status_code == 404:
            return None

        resp.raise_for_status()
        data = resp.json()

        # Small file: base64 encoded content
        if "content" in data and data.get("encoding") == "base64":
            return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")

        # Large file (1-100MB): use raw media type
        file_size = data.get("size", 0)
        if file_size > 1_000_000:
            if file_size > 100_000_000:
                import sys

                print(
                    f"[github-api] skipped ({file_size // 1024 // 1024}MB > 100MB limit): {url[:80]}",
                    file=sys.stderr,
                )
                return None

            # Re-fetch with raw media type
            raw_headers = {"Accept": "application/vnd.github.raw+json"}
            if token:
                raw_headers["Authorization"] = f"token {token}"

            raw_resp = sess.get(api_url, timeout=timeout * 3, headers=raw_headers)
            raw_resp.raise_for_status()
            body = raw_resp.text
            return body if isinstance(body, str) else None

        return None
    except Exception as e:
        import sys

        print(f"[github-api] error: {api_url[:80]}: {e}", file=sys.stderr)
        return None


def build_session(max_pool_size: int = 4, proxy_url: str | None = None) -> Session:
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
    session: Session = Session(impersonate="chrome124")

    # Configure proxy if present
    if effective_proxy:
        session.proxies = {
            "http": effective_proxy,
            "https": effective_proxy,
        }

    # Set user agent
    session.headers.update({"User-Agent": CHROME_UA})

    return session


def fetch_data(
    url: str,
    timeout: int = 5,
    max_attempts: int = 3,
    session=None,
    proxy_url: str | None = None,
    token: str | None = None,
) -> FetchResult:
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

    Retry strategy — the order and the count are load-bearing, not tunable
    here (SECURITY.md states what they cost):
        attempt 1: normal with verify=True
        attempt 2: verify=False (skip SSL cert check)
        attempt 3: downgrade HTTPS to HTTP (for DPI/workaround)
        attempt 4: GitHub API fallback (for raw.githubusercontent.com IP blocks)

    Every attempt that skips certificate verification, and every one that goes
    out in the clear, is logged with its host and counted; the run's total is
    printed by report_insecure_fetches(). With `REFUSE_INSECURE_FETCH` set,
    attempts 2 and 3 are skipped rather than performed.

    Note: Uses curl_cffi for better performance and TLS fingerprinting.
    """
    # Use provided proxy or fall back to environment
    effective_proxy = proxy_url or _get_env_proxy()

    # Auto-detect token: use provided, or fall back to env
    effective_token = token or _get_github_token()

    # Only pass token for GitHub URLs — avoids leaking auth to random hosts
    is_github_url = "github.com" in url or "raw.githubusercontent.com" in url
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

    host = _host_of(url)
    refused_attempts = 0
    last_error = ""

    for attempt in range(1, max_attempts + 1):
        mode = _attempt_mode(attempt, url)
        if mode in _INSECURE_MODES and REFUSE_INSECURE_FETCH:
            refused_attempts += 1
            warning(
                f"[fetch-security] attempt {attempt} for {host} skipped: "
                "REFUSE_INSECURE_FETCH refuses the TLS downgrades"
            )
            continue
        try:
            modified_url = url
            if mode == _MODE_PLAINTEXT:
                modified_url = urlparse(url)._replace(scheme="http").geturl()
            verify = mode == _MODE_VERIFIED
            if mode in _INSECURE_MODES:
                _log_downgrade(mode, host, attempt)
                INSECURE_FETCHES.record(mode, host)

            with _silence_client_tls_warning(verify):
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
            last_error = str(exc)
            if attempt < max_attempts:
                time.sleep(1)
                continue

            return FetchResult(
                text="", status_code=_extract_status(exc), error=last_error, success=False
            )

    # The loop can end here only when the insecure attempts it would have made
    # were refused. Report that as the reason when it is the reason, and keep
    # the transport's own error when there was one — the refusal explains why
    # nothing further was tried, not why the first attempt failed.
    if refused_attempts:
        refused_note = f"{refused_attempts} insecure attempt(s) skipped by REFUSE_INSECURE_FETCH"
        return FetchResult(
            text="",
            status_code=0,
            error=f"{last_error}; {refused_note}" if last_error else refused_note,
            success=False,
        )

    # max_attempts <= 0 never enters the loop. Report a failure rather than
    # returning None: the declared contract is a FetchResult that callers
    # inspect through `.success`, so None turns a bad argument into an
    # AttributeError at the call site.
    return FetchResult(
        text="", status_code=0, error="max_attempts must be at least 1", success=False
    )

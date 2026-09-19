"""Fetcher module for downloading VPN configs using curl_cffi for speed."""

import base64
import ipaddress
import os
import re
import socket
import threading
import time
import warnings
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from urllib.parse import urlparse

import requests
from curl_cffi.requests import Session

from config.settings import (
    CHROME_UA,
    FETCH_PRIVATE_ALLOWLIST,
    GITHUB_API_FALLBACK,
    REFUSE_INSECURE_FETCH,
)
from fetchers.destination_guard import (
    _is_blocked_address,
    refusal_reason,
    report_destination_refusals,
)
from utils.fetch_outcomes import report_run_conditions, run_condition
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


def report_fetch_security() -> None:
    """Print this run's fetch-security figures: refusals, curtailed fetches, downgrades.

    One call site, three reports, kept as separate sections on purpose: a refused
    destination is a network condition (the name resolved to an address this pipeline must
    not connect to), a curtailed fetch is the operator's own policy at work (the attempts
    that could have reached the source were skipped), and a downgraded fetch is a
    reachability trade (the request went out without certificate verification, or in the
    clear). None of the three is evidence that a source is dead — the URL health report is
    where that is said, and keeping the four apart is what lets an operator reading one run
    tell which one they are looking at.
    """
    report_destination_refusals()
    report_run_conditions()
    report_insecure_fetches()


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


# The hosts a GitHub token may be sent to. Compared against the parsed hostname of the
# request, never against the URL text: the text test this replaces handed the credential to
# any host a URL merely named — `https://evil.example/x?u=github.com` carried it — and a set
# is where a reader can see exactly who receives it.
#
# Established from where the credential is actually used, not from what the documentation
# said, because that gap is the trap here: the two hosts a request is ever made to are
# `github.com` and `raw.githubusercontent.com` (the only prefixes `_raw_to_api_url`
# recognizes, and the retry ladder requests the URL it was given), and the host the API
# fallback builds for itself is `api.github.com`. That last one is why this set is not the
# two hosts SECURITY.md used to name — leaving it out would stop authenticating the fallback
# silently, which is a worse outcome than the leak this closes.
GITHUB_TOKEN_HOSTS: frozenset[str] = frozenset(
    {"github.com", "raw.githubusercontent.com", "api.github.com"}
)


def _receives_github_token(url: str) -> bool:
    """Whether a request to `url` may carry the GitHub token.

    The policy, stated once: the credential goes to the hosts in `GITHUB_TOKEN_HOSTS` and
    nowhere else. Two decisions consult it — the one for the URL a caller asked for, and the
    one the API fallback makes for the host it is about to request (its metadata call and its
    raw re-fetch both go to that host).
    """
    return _host_of(url) in GITHUB_TOKEN_HOSTS


def _port_of(url: str) -> int | None:
    """The port the request will go to: the URL's own, or the scheme default.

    Defaulted rather than left unset, because the allowlist matches on it: an
    entry that names a port must not cover a URL that leaves the port implicit,
    or the list admits a destination the operator did not write down. None only
    when the URL carries no port and no scheme this module can default.
    """
    parsed = urlparse(url)
    try:
        explicit = parsed.port
    except ValueError:
        # A port that is not a number: the transport reports the malformed URL.
        return None
    if explicit is not None:
        return explicit
    if parsed.scheme == "https":
        return 443
    if parsed.scheme == "http":
        return 80
    return None


def _resolved_addresses(host: str, port: int | None) -> list[str]:
    """Every address `host` currently resolves to.

    This is the I/O seam the guard below reads through: the decision is about
    what to do with the answers, so the suite drives it with a stub instead of
    a resolver. `getaddrinfo` rather than `gethostbyname` so a v6 answer is
    seen too — a name that is public over v4 and loopback over v6 is still a
    destination that has to be refused.
    """
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


def _is_destination_allowlisted(
    host: str, port: int | None, address: str, allowlist: Sequence[str]
) -> bool:
    """Whether an operator entry covers an otherwise-blocked destination.

    Entries are as documented in `config/settings.py`: a CIDR or an IP literal,
    matched against the address the name resolved to; or `host` / `host:port`,
    matched against the URL's own host name. An entry that parses as none of
    those matches nothing — the list is an explicit operator decision, so it is
    read exactly as written rather than guessed at.
    """
    try:
        resolved = ipaddress.ip_address(address)
    except ValueError:
        resolved = None

    for entry in allowlist:
        entry = entry.strip()
        if not entry:
            continue
        if "/" in entry:
            try:
                network = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            if resolved is not None and resolved in network:
                return True
            continue
        try:
            literal = ipaddress.ip_address(entry)
        except ValueError:
            literal = None
        if literal is not None:
            if resolved is not None and literal == resolved:
                return True
            continue
        entry_host, _, entry_port = entry.rpartition(":")
        if entry_host and entry_port.isdigit():
            if entry_host.lower() == host.lower() and (port is None or int(entry_port) == port):
                return True
            continue
        if entry.lower() == host.lower():
            return True
    return False


def _destination_refusal(url: str, allowlist: Sequence[str]) -> str | None:
    """Why this URL's destination must not be fetched, or None when it may be.

    The check is on the *resolved* address, not on the URL text: a curated host
    name that resolves into a private range is exactly the case this exists
    for, and a URL that looks public is not evidence that it is. An IP literal
    is judged directly, so it costs no lookup.

    Every answer is checked and one blocked answer is enough to refuse — a name
    that answers with both a public and a private address is a name whose
    connection this module cannot predict, and the client picks among them.

    The message it returns names the host and the address, and the refusal is reported as
    an outcome of its own rather than as a failure: `destination_guard.refusal_reason()`
    counts it, the end-of-run report names it with its host and address, and
    `utils/url_stats.py` recognizes it through `utils.fetch_outcomes` and leaves the URL's
    age alone — a refusal is a statement about the network the run is on, never evidence
    that the source is gone. What it must not become is an empty successful fetch: that is
    indistinguishable from a dead source, so it would be invisible.
    """
    host = _host_of(url)
    if not host:
        return None

    port = _port_of(url)
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        addresses = [str(literal)]
    else:
        try:
            addresses = _resolved_addresses(host, port)
        except OSError as exc:
            # No address to judge. The request is left to fail on its own (a
            # resolver hiccup is not a blocked destination) but the reason is
            # stated, so it cannot be mistaken for a deliberate refusal.
            warning(f"[fetch-security] could not resolve {host}: {exc} — not verified as public")
            return None

    for address in addresses:
        if not _is_blocked_address(address):
            continue
        if _is_destination_allowlisted(host, port, address, allowlist):
            continue
        return refusal_reason(host, address)
    return None


def _redirect_refusal(requested_url: str, response, allowlist: Sequence[str]) -> str | None:
    """Why the body of a response must be dropped, or None when it may be used.

    The client follows redirects itself (`allow_redirects=True`), so a curated
    host that redirects into a private range is followed without this module
    seeing it happen. The address the request ended at is the one that decides,
    so the final URL goes through the same guard and the body is discarded when
    it is refused — the data never reaches the pipeline.
    """
    final_url = getattr(response, "url", None)
    if not isinstance(final_url, str) or not final_url:
        return None
    if _host_of(final_url) == _host_of(requested_url):
        return None
    return _destination_refusal(final_url, allowlist)


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
    """Whether the URL can be converted to a GitHub API URL.

    Not the token policy — that is `_receives_github_token`, and the two ask different
    questions on purpose: this one asks whether `_raw_to_api_url` recognizes the URL, and it
    implies the token policy only because the API host is in `GITHUB_TOKEN_HOSTS`.
    """
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
        # The credential is attached for the host this call is about to request, not for the
        # URL it was handed: the fallback builds an api.github.com URL from a GitHub one, and
        # that host is in GITHUB_TOKEN_HOSTS precisely so this call stays authenticated.
        if token and _receives_github_token(api_url):
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
            if token and _receives_github_token(api_url):
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
        token: Optional GitHub token. Sent only to the hosts in GITHUB_TOKEN_HOSTS
               (github.com, raw.githubusercontent.com, api.github.com) — never to a host
               that merely appears in the URL text.

    Retry strategy — the order and the count are load-bearing, not tunable
    here (SECURITY.md states what they cost):
        attempt 1: normal with verify=True
        attempt 2: verify=False (skip SSL cert check)
        attempt 3: downgrade HTTPS to HTTP (for DPI/workaround)
        attempt 4: GitHub API fallback (for raw.githubusercontent.com IP blocks)

    Every attempt that skips certificate verification, and every one that goes
    out in the clear, is logged with its host and counted; the run's total is
    printed by report_insecure_fetches(). With `REFUSE_INSECURE_FETCH` set,
    attempts 2 and 3 are skipped rather than performed — and a fetch whose insecure
    attempts were all skipped is then reported as a condition of the run rather
    than as a failure of its source: it is counted with its host, named in the
    end-of-run report, and it does not age the URL toward removal from `URLS.txt`.
    A safety setting the operator turned on must not delete a curated source.

    A destination that resolves into a private, loopback, link-local or
    metadata range is refused before any connection is made, and a response
    that arrived from a host the request did not ask for (a redirect) is
    discarded when that host is refused too — so neither can reach the
    pipeline. Both refusals are reported as failures, never as empty results.

    Note: Uses curl_cffi for better performance and TLS fingerprinting.
    """
    # Use provided proxy or fall back to environment
    effective_proxy = proxy_url or _get_env_proxy()

    # Auto-detect token: use provided, or fall back to env
    effective_token = token or _get_github_token()

    # The credential goes to the hosts in GITHUB_TOKEN_HOSTS and nowhere else. The
    # comparison is on the parsed hostname, so a URL that merely mentions a GitHub host in
    # its path or its query string carries no auth.
    request_token = effective_token if effective_token and _receives_github_token(url) else None

    # Refuse a destination that is not public before anything is sent. The
    # resolution happens once per call: every attempt below targets the same
    # host, and a second lookup would not make the answer the client's own
    # lookup any more predictable.
    refusal = _destination_refusal(url, FETCH_PRIVATE_ALLOWLIST)
    if refusal:
        warning(refusal)
        return FetchResult(text="", status_code=0, error=refusal, success=False)

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

    # If API fallback enabled and URL is GitHub — go straight to API, skip retries. The token
    # passed here is `request_token`: who may receive the credential was decided once, by the
    # host set, and re-deriving it at this call site is how a second, weaker policy appears.
    if GITHUB_API_FALLBACK and _is_github_url(url):
        api_content = _fetch_via_api(url, token=request_token, session=sess, timeout=timeout)
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

            redirected_into = _redirect_refusal(url, response, FETCH_PRIVATE_ALLOWLIST)
            if redirected_into:
                warning(redirected_into)
                return FetchResult(text="", status_code=0, error=redirected_into, success=False)
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
    # the transport's own error when there was one — the skip explains why
    # nothing further was tried, not why the first attempt failed. The skip note
    # comes first because it is the marker: what this outcome means for the URL
    # is decided from the beginning of the text (`utils/fetch_outcomes`), so a
    # message that led with the transport error would age the source on the
    # strength of the operator's own setting.
    if refused_attempts:
        skipped = f"{refused_attempts} insecure attempt(s) skipped by REFUSE_INSECURE_FETCH"
        reason = f"{skipped}; the verified attempt failed: {last_error}" if last_error else skipped
        return FetchResult(text="", status_code=0, error=run_condition(host, reason), success=False)

    # max_attempts <= 0 never enters the loop. Report a failure rather than
    # returning None: the declared contract is a FetchResult that callers
    # inspect through `.success`, so None turns a bad argument into an
    # AttributeError at the call site. It carries the run-condition marker too —
    # nothing was attempted, so this is a fact about the call rather than about
    # the source, and a URL must not be aged for a caller's mistake either.
    return FetchResult(
        text="",
        status_code=0,
        error=run_condition(host, "the fetch was called with max_attempts below 1"),
        success=False,
    )

"""File handling utilities.

Provides file I/O, config deduplication, SNI/CIDR filtering, and subscription headers.
Security validation extracted to utils/security_filter.py.
"""

import base64
import ipaddress
import json
import math
import os
import re
from functools import lru_cache
from urllib.parse import parse_qs, urlparse

from config.settings import SNI_DOMAINS
from utils.executor_cache import get_file_io_executor, get_regex_executor
from utils.logger import log

# ahocorasick-rs (Rust binding) for fast SNI domain matching. Per-haystack
# API: build the automaton once with all patterns, then check each
# haystack against the whole automaton via find_matches_as_strings().
# Per-pattern API (the c wrapper) is not used and not installed.
try:
    from ahocorasick_rs import AhoCorasick
except ImportError:
    AhoCorasick = None

# Shared protocol alternation. Single source of truth for which schemes
# count as "VPN protocols". Adding a new protocol = update this string.
# Single source of truth for supported protocols
SUPPORTED_PROTOCOLS = (
    "vless",
    "vmess",
    "trojan",
    "ss",
    "ssr",
    "tuic",
    "hysteria",
    "hysteria2",
    "hy2",
)

_VPN_PROTOCOLS = r"(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2|hy2)"
_VPN_PROTOCOL_PATTERN = re.compile(r"^" + _VPN_PROTOCOLS + r"://", re.IGNORECASE)
_GLUE_PATTERN = re.compile(_VPN_PROTOCOLS + r"://", re.IGNORECASE)


def _write_chunk(args: tuple[list[str], str]) -> str:
    chunk_lines, chunk_path = args
    with open(chunk_path, "w", encoding="utf-8", buffering=65536) as f:
        f.write("".join(chunk_lines))
    return chunk_path


def split_and_replace_file(filepath: str, max_size_mb: float = 49.0) -> list[str]:
    """Split file if it exceeds max_size_mb. **Original file is DELETED** after split.

    The "and_replace" suffix in the name is intentional — callers must be aware
    that `filepath` will not exist after this call returns. The return value is
    the list of split file paths (or [filepath] if no split was needed).

    WARNING: silent delete of the source is a footgun. If you intend to keep
    the original, copy it first. This was the source of a silent-no-output
    bug in the bypass pipeline — verify_config_file was reading `filepath`
    that had been deleted by a previous call to this function.

    If `filepath` doesn't exist, returns [] and logs.
    """
    if not os.path.exists(filepath):
        log(f"File not found: {filepath}")
        return []

    file_size_bytes = os.path.getsize(filepath)
    max_bytes = int(max_size_mb * 1024 * 1024)
    log(
        f"File size: {filepath} = {file_size_bytes / (1024 * 1024):.2f} MB (limit: {max_size_mb} MB)"
    )

    if file_size_bytes <= max_bytes:
        return [filepath]

    with open(filepath, encoding="utf-8", buffering=65536) as f:
        lines = [l.strip() + "\n" for l in f if l.strip()]

    if not lines:
        return [filepath]

    avg = sum(len(l) for l in lines) / len(lines)
    per_chunk = max(1, int(max_bytes * 0.9 / (avg + 1)))
    num_chunks = math.ceil(len(lines) / per_chunk)
    log(f"Splitting into {num_chunks} parts (~{per_chunk} lines each)")

    base, ext = os.path.splitext(filepath)
    chunks = [
        (lines[i : i + per_chunk], f"{base}-{n + 1}{ext}")
        for n, i in enumerate(range(0, len(lines), per_chunk))
    ]

    created = list(get_file_io_executor().map(_write_chunk, chunks))

    try:
        os.remove(filepath)
    except OSError as e:
        log(f"Warning: Could not remove original {filepath}: {e}")

    return created


def _decode_vmess_host_port(line: str) -> tuple[str, int] | None:
    """vmess:// — base64-decode the JSON payload and extract add/port."""
    if not line.lower().startswith("vmess://"):
        return None
    payload = line[8:]
    rem = len(payload) % 4
    if rem:
        payload += "=" * (4 - rem)
    try:
        decoded = base64.b64decode(payload).decode("utf-8", errors="ignore")
    except (ValueError, TypeError, UnicodeDecodeError):
        return None
    if not decoded.startswith("{"):
        return None
    try:
        j = json.loads(decoded)
    except (ValueError, json.JSONDecodeError):
        return None
    host = j.get("add", "")
    port = j.get("port", 0)
    if host and port:
        return (host, int(port))
    return None


def _decode_ssr_host_port(line: str) -> tuple[str, int] | None:
    """ssr:// — base64-decode the host:port:protocol:method:obfs:password format.

    SSR format: host:port:protocol:method:obfs:base64pass.
    Some clients emit a degenerate short form with just host:port.
    We accept it here for host:port extraction (used by SimpleTester
    for TCP ping). The actual xray parser (_parse_ssr_to_outbound)
    correctly rejects short-form SSR since it lacks method/password.
    This intentional leniency is the difference between "is this URL
    routable" and "can xray be configured from this URL."
    """
    if not line.lower().startswith("ssr://"):
        return None
    payload = line[6:]
    rem = len(payload) % 4
    if rem:
        payload += "=" * (4 - rem)
    decoded = None
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            decoded = decoder(payload).decode("utf-8", errors="ignore")
            if ":" in decoded:
                break
        except (ValueError, TypeError, UnicodeDecodeError):
            continue
    if not decoded or ":" not in decoded:
        return None
    # Strip query if present
    main = decoded.split("/?", 1)[0]
    parts = main.split(":")
    if len(parts) < 2:
        return None
    host, port_str = parts[0], parts[1]
    try:
        port = int(port_str)
        if host and port > 0:
            return (host, port)
    except ValueError:
        pass
    return None


def _decode_generic_host_port(line: str) -> tuple[str, int] | None:
    """Generic urlparse-based fallback for vless://, trojan://, ss://, etc."""
    parsed = urlparse(line)
    if parsed.hostname and parsed.port:
        return (parsed.hostname, parsed.port)
    # Last-resort: parse the user@host:port fragment
    if "@" in line:
        host_part = line.split("@", 1)[1].split("/")[0].split("?")[0].split("#")[0]
        if ":" in host_part:
            host, port_str = host_part.rsplit(":", 1)
            try:
                return (host, int(port_str))
            except ValueError:
                pass
    return None


# Dispatch table: scheme prefix → handler. Order matters — first match wins.
# NOTE: The original vmess branch used case-sensitive `startswith('vmess://')`,
# so uppercase VMESS:// URLs silently failed. The dispatch table uses
# `line.lower().startswith(prefix)` for ALL handlers, fixing that bug.
# Case-insensitive matching cannot break any valid config (real vmess URLs
# are always lowercase) and matches the long-standing ssr behaviour.
_HOST_PORT_HANDLERS = (
    ("vmess://", _decode_vmess_host_port),
    ("ssr://", _decode_ssr_host_port),
)


def extract_host_port(line: str) -> tuple[str, int] | None:
    """Extract (host, port) from any supported protocol URL.

    Dispatch table: tries each scheme-specific handler first, then the
    generic urlparse-based fallback. Each handler is independently testable
    — the test file can call `_decode_vmess_host_port("vmess://...")` directly.
    """
    if not line:
        return None
    for prefix, handler in _HOST_PORT_HANDLERS:
        if line.lower().startswith(prefix):
            result = handler(line)
            if result is not None:
                return result
    try:
        return _decode_generic_host_port(line)
    except (ValueError, TypeError):
        return None


def load_cidr_whitelist(
    cidr_file_path: str = "../source/config/cidrwhitelist.txt", max_cidr_size: int = 65536
) -> set:
    """Load CIDR ranges from a file and expand them to a set of individual IPs.

    CIDR ranges with more than `max_cidr_size` addresses are SKIPPED with a
    warning, not expanded. Without this guard, an accidental /16 or /8 entry
    in the whitelist would expand to millions of IPs in a Python set, blowing
    up memory. The threshold (65536 = /16 worth of IPv4) is generous — real
    whitelist entries are individual hosts, small subnets, or ASN-sized
    blocks. Anything bigger is almost certainly a mistake.

    Args:
        cidr_file_path: Path to a CIDR whitelist file (one CIDR per line).
        max_cidr_size: Maximum number of addresses per CIDR range. Default
            65536 = /16 worth of IPv4 addresses. /17+ entries are skipped.
    """
    ip_set = set()
    try:
        with open(cidr_file_path, encoding="utf-8", buffering=65536) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    network = ipaddress.ip_network(line, strict=False)
                    if network.num_addresses > max_cidr_size:
                        log(
                            f"Warning: CIDR {line} has {network.num_addresses} addresses, "
                            f"exceeds max_cidr_size={max_cidr_size}, skipping to prevent OOM"
                        )
                        continue
                    for ip in network:
                        ip_set.add(str(ip))
                except ValueError:
                    log(f"Warning: Invalid CIDR skipped: {line}")
    except FileNotFoundError:
        log(f"CIDR whitelist not found: {cidr_file_path}")
    return ip_set


def extract_ip_from_config(config: str) -> str | None:
    host_port = extract_host_port(config)
    if not host_port:
        return None
    host, _ = host_port
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        return None


def is_ip_in_cidr_whitelist(ip_str: str, cidr_whitelist: set) -> bool:
    return ip_str in cidr_whitelist


def prepare_config_content(content: str) -> list[str]:
    """Normalize config content by separating glued configs on newlines."""
    content = _GLUE_PATTERN.sub(r"\n\1://", content)
    return [
        line.strip()
        for line in content.splitlines()
        if line.strip()
        and not line.strip().startswith("#")
        and is_valid_vpn_config_url(line.strip())
    ]


def deduplicate_configs(configs: list[str]) -> list[str]:
    seen = set()
    result = []
    for c in configs:
        if not c or not c.strip():  # skip empty / whitespace-only
            continue
        key = _get_dedup_key(c)
        if key and key not in seen:
            seen.add(key)
            result.append(c)
    return result


@lru_cache(maxsize=131072)
def _get_dedup_key(config: str) -> tuple | None:
    try:
        # VMess: host/port live in the base64-encoded JSON payload,
        # not in the URL itself (urlparse sees the b64 string as netloc).
        # Key on (add, port, id) — ignore ps (the remark/name).
        if config.lower().startswith("vmess://"):
            payload = config[8:]
            rem = len(payload) % 4
            if rem:
                payload += "=" * (4 - rem)
            try:
                decoded = base64.b64decode(payload).decode("utf-8", errors="ignore")
                if decoded.startswith("{"):
                    j = json.loads(decoded)
                    return (
                        "vmess",
                        j.get("add", ""),
                        int(j.get("port", 0) or 0),
                        j.get("id", ""),
                    )
            except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
                pass  # fall through to generic key (handles malformed vmess)

        protocol = config.split("://")[0].lower()  # lowercase for case-insensitive dedup
        parsed = urlparse(config)
        host = parsed.hostname or ""
        port = parsed.port or 0
        params = parse_qs(parsed.query)
        for k in list(params):
            if k.lower() in ("remark", "#"):
                del params[k]
        # Normalize param keys and values to lowercase so that
        # ?security=TLS&type=WS and ?security=tls&type=ws produce the
        # same dedup key. This catches duplicates from sources that
        # randomly capitalize parameter names/values.
        frozen = frozenset(
            (k.lower(), tuple(v.lower() for v in vs)) for k, vs in sorted(params.items())
        )
        return (protocol, host, port, frozen)
    except (ValueError, TypeError):
        return None


def is_valid_vpn_config_url(line: str) -> bool:
    return bool(_VPN_PROTOCOL_PATTERN.match(line))


def apply_sni_cidr_filter(configs: list[str], filter_secure: bool = True) -> list[str]:
    if AhoCorasick is None:
        log("ahocorasick-rs not installed, running without SNI filter")
        return configs

    # Lazy import to break the circular: utils._sni_worker imports from
    # this module at its top level, so we can't import it at module load
    # time. Importing at call time is safe because by then both modules
    # are fully loaded.
    from utils._sni_worker import _filter_sni_cidr_chunk

    cidr_whitelist = load_cidr_whitelist()

    # Build the SNI-domain automaton once. Lowercased patterns so the
    # haystack can also be lowercased per-check.
    automaton = AhoCorasick([domain.lower() for domain in SNI_DOMAINS])

    # logarithmic chunking: n scales with input size, capped at 32
    # to keep individual chunks small (~2000) and maximise parallelism
    target_chunk_size = 2000
    n = max(1, min(32, len(configs) // target_chunk_size))
    chunk_size = max(target_chunk_size, math.ceil(len(configs) / n))
    chunks = [configs[i : i + chunk_size] for i in range(0, len(configs), chunk_size)]

    results = get_regex_executor().map(
        _filter_sni_cidr_chunk,
        [(chunk, automaton, cidr_whitelist, filter_secure) for chunk in chunks],
    )

    filtered = []
    for r in results:
        filtered.extend(r)
    return filtered

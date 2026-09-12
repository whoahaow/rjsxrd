"""Utility functions extracted from xray_tester.py for Xray testing helpers.

Pure functions for error tracking, URL validation, TCP ping, and response
validation. These have no dependency on XrayTester instance state.
"""

import re
import socket
import threading
import time

from utils.logger import log

# Constants for Xray error compression
_XRAY_PORT_TIMEOUT = 0.05
_XRAY_PORT_CHECK_SLEEP = 0.05


def quick_validate_url(url: str) -> bool:
    """Quick pre-validation: check URL has protocol prefix."""
    if not url or not url.strip():
        return False
    return "://" in url


def validate_response(response: str, test_url: str = "") -> bool:
    """Basic validation that response looks like real HTTP content."""
    if not response:
        return False
    return len(response) >= 20


def tcp_ping(host: str, port: int, timeout: float = 3.0) -> tuple[bool, float]:
    """Simple TCP connect test to check if a port is reachable."""
    start_time = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.close()
        latency = (time.time() - start_time) * 1000
        return True, latency
    except (TimeoutError, OSError):
        return False, 0.0


def wait_for_port(host: str, port: int, timeout: float = 3.0) -> bool:
    """Wait for a TCP port to become reachable."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(min(0.5, timeout / 4))
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                return True
        except OSError:
            pass
        time.sleep(0.1)
    return False


def wait_for_ports(ports: list[int], timeout: float = None) -> bool:
    """Wait for multiple ports to be listening with dynamic timeout.

    Dynamic timeout: 50ms per port, min 3s, max 30s.
    For 100 ports: 5s, for 200 ports: 10s.
    """
    if timeout is None:
        timeout = min(30.0, max(3.0, _XRAY_PORT_TIMEOUT * len(ports)))

    start = time.time()
    pending_ports = set(ports)

    while time.time() - start < timeout and pending_ports:
        for port in list(pending_ports):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(_XRAY_PORT_CHECK_SLEEP)
                result = sock.connect_ex(("127.0.0.1", port))
                sock.close()
                if result == 0:
                    pending_ports.discard(port)
            except OSError:
                pass
        if pending_ports:
            time.sleep(_XRAY_PORT_CHECK_SLEEP)

    if pending_ports:
        log(f"WARNING: {len(pending_ports)}/{len(ports)} ports never opened after {timeout:.1f}s")
    return len(pending_ports) == 0


# Error tracking state (module-level, not tied to XrayTester)
_error_stats: dict[str, int] = {}
_error_samples: dict[str, list[str]] = {}
_error_stats_lock = threading.Lock()


def track_error(error_type: str) -> None:
    """Track error occurrence for stats."""
    with _error_stats_lock:
        _error_stats[error_type] = _error_stats.get(error_type, 0) + 1


def normalize_error(error_str: str) -> str:
    """Normalize the error string: extract the first meaningful line
    and remove precise numbers that change between runs.
    """
    lines = error_str.strip().split("\n")
    meaningful = [
        line
        for line in lines
        if line.strip() and "info" not in line.lower()[:20] and "warning" not in line.lower()[:20]
    ]
    text = meaningful[0] if meaningful else lines[0] if lines else error_str
    text = re.sub(r"\d+\.\d+", "X.X", text)
    text = re.sub(r"port\s+\d+", "port X", text, flags=re.IGNORECASE)
    return text[:120]


def print_error_summary() -> None:
    """Log the final error statistics."""
    with _error_stats_lock:
        if not _error_stats:
            return
        top = sorted(_error_stats.items(), key=lambda x: -x[1])[:5]
        total = sum(_error_stats.values())
        log(f"Error summary ({total} total, top {len(top)}):")
        for error_type, count in top:
            pct = count / total * 100
            log(f"  {error_type}: {count} ({pct:.1f}%)")
            if error_type in _error_samples:
                for sample in _error_samples[error_type][:2]:
                    log(f"    e.g.: {sample[:120]}")

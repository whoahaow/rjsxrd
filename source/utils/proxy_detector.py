"""Proxy detection utility - scans common ports for active SOCKS/HTTP proxies."""

import socket

COMMON_PROXY_PORTS = [
    10808,  # v2rayN, Hiddify default
    2080,  # NekoRay default
    7890,  # Clash default
    7891,  # Clash alternative
    1080,  # Standard SOCKS
    8080,  # Common HTTP proxy
]


def check_port_open(host: str = "127.0.0.1", port: int = 10808, timeout: float = 0.5) -> bool:
    """Check if proxy port is listening."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except (TimeoutError, OSError):
        return False


def find_active_proxy_port(host: str = "127.0.0.1", ports: list[int] = None) -> int | None:
    """Scan common proxy ports to find active one.

    Returns:
        Port number if found, None otherwise
    """
    ports_to_scan = ports or COMMON_PROXY_PORTS

    for port in ports_to_scan:
        if check_port_open(host, port):
            return port
    return None

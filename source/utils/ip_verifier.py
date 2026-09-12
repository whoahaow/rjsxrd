"""Proxy setup utilities — configures single proxy and proxy chains via Xray.

Consolidated from ip_checker.py (IP check helpers, verify_protection) and
ip_verifier.py (proxy setup, chaining). Single module for all proxy operations.
"""

import os
import socket
import subprocess
import time
from urllib.parse import urlparse

import requests

from utils.logger import log
from utils.process_registry import default_registry

# ── IP Checking ───────────────────────────────────────────────────────

IP_CHECK_URLS = [
    "https://ipwho.is/",
    "https://api.ipify.org?format=json",
    "https://ifconfig.me/ip",
]


def _make_request(url: str, proxies: dict = None, timeout: float = 5.0):
    """HTTP request with curl_cffi (fallback to requests)."""
    try:
        from curl_cffi.requests import Session

        with Session(impersonate="chrome124") as session:
            return session.get(url, proxies=proxies, timeout=timeout)
    except ImportError:
        return requests.get(url, proxies=proxies, timeout=timeout)


def get_real_ip(timeout: float = 5.0) -> str | None:
    """Get external IP without proxy."""
    for url in IP_CHECK_URLS:
        try:
            response = _make_request(url, timeout=timeout)
            if "ipwho.is" in url or "ipify" in url:
                return response.json().get("ip")
            return response.text.strip()
        except (OSError, requests.Timeout, requests.ConnectionError, ValueError):
            continue
    return None


def get_proxy_ip(proxy_url: str, timeout: float = 5.0) -> str | None:
    """Get external IP through proxy."""
    proxies = {"http": proxy_url, "https": proxy_url}
    for url in IP_CHECK_URLS:
        try:
            response = _make_request(url, proxies=proxies, timeout=timeout)
            if "ipwho.is" in url or "ipify" in url:
                return response.json().get("ip")
            return response.text.strip()
        except (OSError, requests.Timeout, requests.ConnectionError, ValueError):
            continue
    return None


def verify_protection(
    proxy_host: str = "127.0.0.1", proxy_port: int = 10808, timeout: float = 5.0
) -> dict:
    """Verify proxy actually hides real IP.

    Returns dict with: active, real_ip, proxy_ip, different, country, error.
    """
    result = {
        "active": False,
        "real_ip": None,
        "proxy_ip": None,
        "different": False,
        "country": None,
        "error": None,
    }
    try:
        result["real_ip"] = get_real_ip(timeout=timeout)
        proxy_url = f"socks5h://{proxy_host}:{proxy_port}"
        result["proxy_ip"] = get_proxy_ip(proxy_url, timeout=timeout)

        try:
            proxies = {"http": proxy_url, "https": proxy_url}
            response = _make_request("https://ipwho.is/", proxies=proxies, timeout=timeout)
            result["country"] = response.json().get("country")
        except (OSError, requests.Timeout, requests.ConnectionError, ValueError, KeyError):
            pass

        if result["real_ip"] and result["proxy_ip"]:
            result["different"] = result["real_ip"] != result["proxy_ip"]
            result["active"] = result["different"]
        return result
    except (
        OSError,
        requests.Timeout,
        requests.ConnectionError,
        ValueError,
        TypeError,
        RuntimeError,
    ) as e:
        result["error"] = str(e)
        return result


# ── Proxy Env Management ──────────────────────────────────────────────

_PROXY_ENV_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")
_original_env_vars = {}


def _wait_for_tcp_port(host: str, port: int, timeout: float = 3.0) -> bool:
    """Wait for TCP port to be listening."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                return True
        except OSError:
            pass
        time.sleep(0.05)
    return False


def _mask_ip(ip: str) -> str:
    """Mask IP for display."""
    if not ip:
        return "***"
    if ":" in ip:
        return "IPv6:***"
    parts = ip.split(".")
    return f"{parts[0]}.***.***.***" if len(parts) == 4 else "***"


def _clear_proxy_env_vars() -> None:
    """Clear proxy-related env vars. Registered as cleanup callback."""
    for var in _PROXY_ENV_VARS:
        if var in os.environ:
            del os.environ[var]


default_registry.register_callback(_clear_proxy_env_vars)


def setup_global_proxy(proxy_url: str, timeout: float = 8.0) -> dict:
    """Setup global proxy using a proxy URL.

    For vless://, vmess://, trojan://, ss:// — starts persistent Xray instance.
    For socks5:// — tests and sets environment variables only.

    Returns dict with: active, real_ip, proxy_ip, different, country, socks_port, error.
    """
    result = {
        "active": False,
        "real_ip": None,
        "proxy_ip": None,
        "different": False,
        "country": None,
        "error": None,
        "socks_port": None,
    }

    try:
        if not proxy_url or not isinstance(proxy_url, str) or "://" not in proxy_url:
            result["error"] = "Invalid proxy URL (must include protocol)"
            return result

        global _original_env_vars
        if not _original_env_vars:
            for var in _PROXY_ENV_VARS:
                _original_env_vars[var] = os.environ.get(var)

        result["real_ip"] = get_real_ip(timeout=timeout)
        protocol = urlparse(proxy_url).scheme.lower()

        if protocol in ["socks5", "socks5h", "socks4", "http", "https"]:
            result["proxy_ip"] = get_proxy_ip(proxy_url, timeout=timeout)
            try:
                proxies = {"http": proxy_url, "https": proxy_url}
                response = _make_request("https://ipwho.is/", proxies=proxies, timeout=timeout)
                result["country"] = response.json().get("country")
            except (OSError, requests.Timeout, requests.ConnectionError, ValueError, KeyError):
                pass
            for var in _PROXY_ENV_VARS:
                os.environ[var] = proxy_url

        elif protocol in ["vless", "vmess", "trojan", "ss", "hysteria2", "hy2"]:
            from utils.download_xray import ensure_xray_installed
            from utils.xray_tester import XrayTester

            xray_path = ensure_xray_installed()
            if not xray_path:
                result["error"] = "Xray-core not installed"
                return result

            tester = XrayTester(xray_path=xray_path)
            socks_port = 24000
            config = tester.create_single_outbound_config(proxy_url, socks_port)
            if not config:
                result["error"] = "Failed to parse proxy config"
                return result

            success, process, error = tester.start_xray_instance(config, socks_port, verbose=True)
            if not success:
                result["error"] = f"Failed to start Xray: {error}"
                return result

            result["socks_port"] = socks_port

            if not _wait_for_tcp_port("127.0.0.1", socks_port, timeout=5.0):
                result["error"] = "Xray SOCKS port not listening"
                tester.stop_xray_process(process)
                return result

            socks_url = f"socks5h://127.0.0.1:{socks_port}"
            result["proxy_ip"] = get_proxy_ip(socks_url, timeout=timeout)
            try:
                proxies = {"http": socks_url, "https": socks_url}
                response = _make_request("https://ipwho.is/", proxies=proxies, timeout=timeout)
                result["country"] = response.json().get("country")
            except (OSError, requests.Timeout, requests.ConnectionError, ValueError, KeyError):
                pass

            for var in _PROXY_ENV_VARS:
                os.environ[var] = socks_url
        else:
            result["error"] = f"Unsupported protocol: {protocol}"
            return result

        if result["real_ip"] and result["proxy_ip"]:
            result["different"] = result["real_ip"] != result["proxy_ip"]
            result["active"] = result["different"]
        return result

    except (
        OSError,
        subprocess.TimeoutExpired,
        subprocess.CalledProcessError,
        ValueError,
        TypeError,
        requests.RequestException,
    ) as e:
        result["error"] = f"{type(e).__name__}: {str(e)}"
        return result


def setup_proxy_chain(proxy_urls: list, timeout: float = 8.0) -> dict:
    """Setup 2-hop proxy chain using single Xray instance with dialerProxy.

    Args:
        proxy_urls: List of exactly 2 proxy URLs
        timeout: Connection timeout

    Returns:
        Dict with proxy status, IP, country, socks_port
    """
    result = {
        "active": False,
        "proxy_ip": None,
        "country": None,
        "error": None,
        "socks_port": None,
        "chain_length": len(proxy_urls),
    }

    if len(proxy_urls) != 2:
        result["error"] = "Proxy chain requires exactly 2 proxies"
        return result

    try:
        VALID_PROTOCOLS = [
            "vless",
            "vmess",
            "trojan",
            "ss",
            "hysteria2",
            "hy2",
            "socks5",
            "socks5h",
        ]
        for i, url in enumerate(proxy_urls):
            if not url or "://" not in url:
                result["error"] = f"Invalid proxy URL at position {i + 1}"
                return result
            protocol = url.split("://")[0].lower()
            if protocol not in VALID_PROTOCOLS:
                result["error"] = f"Unsupported protocol '{protocol}' at position {i + 1}"
                return result

            from utils.security_filter import has_insecure_setting

            if has_insecure_setting(url):
                result["error"] = f"Insecure proxy at position {i + 1}"
                log(f"  WARNING: Proxy {i + 1} has insecure settings")
                return result

        result["real_ip"] = get_real_ip(timeout=timeout)
        if not result["real_ip"]:
            result["error"] = "Failed to get real IP"
            return result
        log("Real IP detected: {0}".format(_mask_ip(result["real_ip"])))

        from utils.download_xray import ensure_xray_installed
        from utils.xray_tester import XrayTester

        xray_path = ensure_xray_installed()
        if not xray_path:
            result["error"] = "Xray-core not installed"
            return result

        ENTRY_SOCKS_PORT = 22000
        log("Setting up proxy chain (EXPERIMENTAL)...")
        tester = XrayTester(xray_path=xray_path)
        config = tester.create_chain_config(proxy_urls=proxy_urls, socks_port=ENTRY_SOCKS_PORT)

        if not config:
            result["error"] = "Failed to create chain config (Reality not supported)"
            return result

        log("Starting Xray instance...")
        success, process, error = tester.start_xray_instance(config, ENTRY_SOCKS_PORT, verbose=True)
        if not success:
            result["error"] = f"Xray failed: {error}"
            return result

        if not _wait_for_tcp_port("127.0.0.1", ENTRY_SOCKS_PORT, timeout=3.0):
            result["error"] = "Xray port not listening"
            tester.stop_xray_process(process)
            return result

        log(f"  * Xray ready on port {ENTRY_SOCKS_PORT}")
        socks_url = f"socks5h://127.0.0.1:{ENTRY_SOCKS_PORT}"

        # Test hop 1 alone
        log("  Testing hop 1...")
        tester_temp = XrayTester(xray_path=xray_path)
        temp_port = 22999
        config_temp = tester_temp.create_single_outbound_config(proxy_urls[0], temp_port)
        hop1_ip = None
        if config_temp:
            success_temp, process_temp, _ = tester_temp.start_xray_instance(
                config_temp, temp_port, verbose=False
            )
            if success_temp:
                if _wait_for_tcp_port("127.0.0.1", temp_port, timeout=2.0):
                    hop1_ip = get_proxy_ip(f"socks5h://127.0.0.1:{temp_port}", timeout=timeout)
                    if hop1_ip:
                        log(f"  * Hop 1 IP: {_mask_ip(hop1_ip)}")
                else:
                    log(f"  * Hop 1 port {temp_port} not ready")
                tester_temp.stop_xray_process(process_temp)
            else:
                log("  * Hop 1 xray failed to start")

        # Test full chain
        log("  Testing full chain...")
        chain_success = False
        for url in IP_CHECK_URLS:
            try:
                proxies = {"http": socks_url, "https": socks_url}
                response = _make_request(url, proxies=proxies, timeout=timeout)
                if "ipwho.is" in url:
                    data = response.json()
                    result["proxy_ip"] = data.get("ip")
                    result["country"] = data.get("country")
                    result["asn"] = data.get("asn", {}).get("org", "")
                    log("  * Chain IP: {0}".format(_mask_ip(result["proxy_ip"])))
                    log("     Country: {0}, ASN: {1}".format(result["country"], result["asn"]))
                    chain_success = True
                    break
                if "ipify" in url:
                    result["proxy_ip"] = response.json().get("ip")
                    chain_success = True
                    break
                result["proxy_ip"] = response.text.strip()
                chain_success = True
                break
            except (OSError, requests.RequestException, ValueError, TypeError) as e:
                log(f"  * Error: {type(e).__name__}: {str(e)[:100]}")

        if not chain_success:
            result["error"] = "Failed to get IP through proxy chain"
            tester.stop_xray_process(process)
            return result

        # Get hop1 details for comparison
        if hop1_ip:
            try:
                tester_temp2 = XrayTester(xray_path=xray_path)
                config_temp2 = tester_temp2.create_single_outbound_config(proxy_urls[0], temp_port)
                if config_temp2:
                    success_temp2, process_temp2, _ = tester_temp2.start_xray_instance(
                        config_temp2, temp_port, verbose=False
                    )
                    if success_temp2:
                        if _wait_for_tcp_port("127.0.0.1", temp_port, timeout=2.0):
                            proxies = {
                                "http": f"socks5h://127.0.0.1:{temp_port}",
                                "https": f"socks5h://127.0.0.1:{temp_port}",
                            }
                            resp = requests.get(
                                "https://ipwho.is/", proxies=proxies, timeout=timeout
                            )
                            hop1_details = resp.json()
                            log(
                                "  Hop 1 details: {0}, ASN: {1}".format(
                                    hop1_details.get("country"),
                                    hop1_details.get("asn", {}).get("org", ""),
                                )
                            )
                        tester_temp2.stop_xray_process(process_temp2)
            except (requests.RequestException, ValueError, KeyError) as e:
                log(f"  (skipping hop1 details: {type(e).__name__}: {str(e)[:80]})")

        # Verify chain
        if result.get("proxy_ip") and result.get("real_ip"):
            if result["proxy_ip"] == result["real_ip"]:
                result["error"] = "Proxy chain not hiding real IP"
                tester.stop_xray_process(process)
                return result

        if hop1_ip and result["proxy_ip"] and hop1_ip == result["proxy_ip"]:
            log("  * CRITICAL: Chain exits via hop1 only - hop2 bypassed")
            result["error"] = "Chain broken - hop2 bypassed. Use WebSocket, not Reality."
            tester.stop_xray_process(process)
            return result

        log("  * Chain working ({0})".format(result.get("country", "Unknown")))
        for var in _PROXY_ENV_VARS:
            os.environ[var] = socks_url

        result["active"] = True
        result["socks_port"] = ENTRY_SOCKS_PORT
        return result

    except (
        OSError,
        subprocess.TimeoutExpired,
        subprocess.CalledProcessError,
        ValueError,
        TypeError,
        requests.RequestException,
    ) as e:
        result["error"] = f"{type(e).__name__}: {str(e)}"
        return result

"""Xray-core VPN config tester with concurrent testing support.

Tests VPN configs (VLESS, VMess, Trojan, Shadowsocks, Hysteria, TUIC, SSR) using Xray-core.

Supported protocols:
- VLESS: Full support (TLS, Reality, WS, gRPC, HTTPUpgrade)
- VMess: Full support (TLS, WS, gRPC, h2)
- Trojan: Full support (TLS, Reality, WS, gRPC, HTTPUpgrade)
- Shadowsocks: Full support (AEAD methods, plugins via streamSettings)
- ShadowsocksR: Basic support (converted to Shadowsocks, SSR features limited in Xray-core)
- Hysteria v2: Full support (QUIC, TLS)
- Hysteria v1: Limited support (may not work with all servers)
- TUIC: Parser included but NOT supported by Xray-core (use sing-box for TUIC)

Note: TUIC is not natively supported by Xray-core. TUIC configs will fail testing.
"""

# Import shared cipher sets from file_utils (single source of truth)
from utils.security_filter import SS_WEAK_CIPHERS
from utils import protocol_parsers

import os
import sys
import json
import subprocess
import tempfile
import time
import socket
import threading
import atexit
import signal
import re
import asyncio
import requests
from requests.adapters import HTTPAdapter
from typing import List, Tuple, Optional, Dict, Set
from utils.executor_cache import ExecutorCache
from urllib.parse import urlparse, parse_qs, unquote
import base64
import multiprocessing
from utils.logger import log
from utils.smart_eta import SmartETA
from config.settings import (
    XRAY_BASE_PORT, XRAY_BATCH_PORT_END, XRAY_CHAIN_PORT_START, XRAY_CHAIN_PORT_END,
    XRAY_PERSISTENT_PORT_START, XRAY_PORT_MAX_ATTEMPTS, XRAY_STARTUP_TIMEOUT,
    XRAY_PROCESS_KILL_TIMEOUT, XRAY_PROCESS_FORCE_KILL_TIMEOUT,
    LOG_ERROR_SAMPLE_LENGTH, LOG_XRAY_ERROR_LENGTH, MIN_CHAIN_HOPS,
    CHAIN_TRANSPORT_WHITELIST, CHAIN_SECURITY_REQUIRED,
    TEST_PING_URLS,
    ENABLE_FRAGMENT, FRAGMENT_PACKETS, FRAGMENT_LENGTH, FRAGMENT_INTERVAL,
)

# tqdm progress bar. Single source of truth is utils/progress.py.
from utils.progress import is_available, get_async_pbar, get_sync_pbar as _tqdm_sync
from utils.psutil_available import psutil, HAS_PSUTIL as PSUTIL_AVAILABLE

from utils.curl_import import CurlSession, AsyncSession, CURL_CFFI_AVAILABLE

# Global registry for cleanup on exit. The shared ProcessRegistry (in
# utils.process_registry) is the single source of truth for spawned xray
# processes across the codebase — see utils/process_registry.py docstring
# for why this consolidation was needed.
from utils.process_registry import default_registry
from utils.managed_process import ManagedProcess
from utils.vpn_config import parse_url as vpn_parse_url
from utils.system_specs import get_specs
from utils.xray_batch import BatchRunner
from utils.xray_helpers import wait_for_port


def _cleanup_all() -> None:
    """Cleanup all active Xray processes on exit.

    Backwards-compatible wrapper around the shared registry's force-cleanup.
    Callers should use install_signal_handler() from utils.process_registry
    instead, or let main.py handle cleanup via its own signal handler.
    """
    default_registry.cleanup(force=True)


class XrayTester:
    """Test VPN configs using Xray-core.
    
    Supports:
    - Single config testing (one Xray process per config)
    - Batch testing (multiple configs tested concurrently)
    - Proxy chain verification
    - Speed-based sorting (fastest configs first)
    """
    
    TEST_URLS = TEST_PING_URLS
    DEFAULT_TIMEOUT = 5.0
    BASE_PORT = XRAY_BASE_PORT
    BATCH_PORT_END = XRAY_BATCH_PORT_END
    CHAIN_PORT_START = XRAY_CHAIN_PORT_START
    CHAIN_PORT_END = XRAY_CHAIN_PORT_END
    PERSISTENT_PORT_START = XRAY_PERSISTENT_PORT_START
    BATCH_SIZE = 100
    MAX_BATCH_SIZE = 150
    MIN_BATCH_SIZE = 50
    
    def __init__(self, xray_path: Optional[str] = None) -> None:
        """Initialize Xray tester."""
        self.xray_path: Optional[str] = xray_path or self._find_xray()
        self._running_processes: List[subprocess.Popen] = []
        self._config_files: dict = {}  # Track config files for cleanup
        self._process_lock = threading.Lock()
        self._port_counter = [self.BASE_PORT]
        self._port_lock = threading.Lock()
        self._batch_runner = BatchRunner(self)

        # Error tracking for debugging
        self._error_stats = {}
        self._error_samples = {}
        self._error_stats_lock = threading.Lock()

        # No global tester registry needed: spawned processes are tracked
        # via the shared ProcessRegistry when start_xray_instance succeeds.
        # This avoids the previous double-registration problem (tester in
        # _active_testers AND (tester, process) in _xray_process_registry).
    
    def _find_xray(self) -> Optional[str]:
        """Find Xray binary with cross-platform support.
        
        Returns:
            Absolute path to xray binary if found, None otherwise.
            Callers must check for None — the old fallback of returning
            the literal string "xray" caused silent-accept-all behavior
            downstream (isfile("xray") was False so configs were marked
            as working with latency 0).
        """
        xray_exe = "xray.exe" if sys.platform == "win32" else "xray"
        possible_paths = [
            os.path.join(os.path.dirname(__file__), "..", "xray", xray_exe),
            os.path.join(os.path.dirname(__file__), "..", xray_exe),
            xray_exe,
        ]
        for path in possible_paths:
            if os.path.isfile(path):
                return os.path.abspath(path)
        return None
    
    def _get_next_port(self) -> int:
        """Get next available port with range skipping.
        
        Port ranges:
        - 20000-21999: Batch tester
        - 22000-23999: Proxy chains
        - 24000-24999: Persistent proxies
        """
        reserved_ports: Set[int] = set()
        
        for _ in range(XRAY_PORT_MAX_ATTEMPTS):
            with self._port_lock:
                port = self._port_counter[0]
                # Skip reserved ranges
                if self.CHAIN_PORT_START <= port <= self.CHAIN_PORT_END:
                    port = self.CHAIN_PORT_END + 1
                    self._port_counter[0] = port
                elif port >= self.PERSISTENT_PORT_START:
                    port = self.BASE_PORT
                    self._port_counter[0] = port
                
                # Check if already reserved by another thread
                if port in reserved_ports:
                    self._port_counter[0] += 1
                    continue
                
                # Atomically check and reserve port
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.bind(('127.0.0.1', port))
                    sock.close()
                    reserved_ports.add(port)
                    self._port_counter[0] = port + 1
                    return port
                except OSError:
                    self._port_counter[0] += 1
                    continue
        
        raise RuntimeError(f"Could not find available port after {XRAY_PORT_MAX_ATTEMPTS} attempts")
    
    def _wait_for_port(self, port: int, timeout: float = 1.5) -> bool:
        """Wait for SOCKS port to be listening."""
        return wait_for_port('127.0.0.1', port, timeout)
    
    def _url_to_outbound(self, url: str, tag: str = "proxy") -> Optional[Dict]:
        """Convert URL to outbound based on protocol.

        Uses the typed VPNConfig parsers (utils/vpn_config.py) as the primary
        path, falling back to the legacy inline parsers if the typed parser
        returns None (e.g., for unrecognized formats or edge cases).
        This lets us gradually migrate to the typed hierarchy.

        Protocol support levels:
        - VLESS: Full support (TLS, Reality, WS, gRPC, HTTPUpgrade)
        - VMess: Full support (TLS, WS, gRPC, h2)
        - Trojan: Full support (TLS, Reality, WS, gRPC, HTTPUpgrade)
        - Shadowsocks: Full support (AEAD ciphers only, weak ciphers rejected)
        - SSR: Limited (converted to Shadowsocks, protocol/obfs features lost)
        - Hysteria v2: Full support (QUIC, TLS)
        - Hysteria v1: Limited (may not work with all servers)
        - TUIC: Not supported (returns None, use sing-box)
        """
        return protocol_parsers.parse_url_to_outbound(url, tag)
    
    def create_single_outbound_config(self, url: str, socks_port: int) -> Optional[Dict]:
        """Create Xray config with single inbound + single outbound."""
        outbound = self._url_to_outbound(url, "proxy")
        if not outbound:
            return None
        self._apply_fragment(outbound)

        return {
            "log": {"loglevel": "error", "access": "", "error": ""},
            "inbounds": [{
                "tag": "socks",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "mixed",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {
                    "enabled": True,
                    "routeOnly": True,
                    "destOverride": ["http", "tls", "quic"]
                }
            }],
            "outbounds": [
                outbound,
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"}
            ],
            "routing": {
                "domainStrategy": "AsIs",
                "rules": [{
                    "type": "field",
                    "inboundTag": ["socks"],
                    "outboundTag": "proxy"
                }]
            }
        }
    
    def create_chain_config(self, proxy_urls: list, socks_port: int) -> Optional[Dict]:
        """Create Xray config with multiple chained VLESS outbounds (v2rayN-style).
        
        Uses dialerProxy to chain multiple VLESS proxies in a SINGLE Xray instance.
        This is the SAME approach used by v2rayN for proxy chaining.
        
        Architecture:
          App → Xray (:socks_port) → VLESS hop1 → dialerProxy → VLESS hop2 → Internet
        
        ⚠️  TRANSPORT REQUIREMENTS:
        All hops MUST use WebSocket (ws) or HTTPUpgrade transport with TLS.
        Reality protocol does NOT work with dialerProxy chaining.
        
        Supported: VLESS+WS+TLS, VLESS+HTTPUpgrade+TLS, VMess+WS+TLS
        NOT Supported: VLESS+Reality, VLESS+TCP
        
        Args:
            proxy_urls: List of VLESS/VMess URLs to chain ['vless://hop1', 'vless://hop2']
            socks_port: Local SOCKS port for user apps
        
        Returns:
            Xray config dict or None
        
        Example:
            config = tester.create_chain_config(
                proxy_urls=["vless://uuid1@hop1.example.com:443?...", "vless://uuid2@hop2.example.com:443?..."],
                socks_port=22000
            )
        """
        if len(proxy_urls) < MIN_CHAIN_HOPS:
            log(f"Chain requires at least {MIN_CHAIN_HOPS} proxies, got {len(proxy_urls)}")
            return None
        
        # VALIDATE ALL HOPS FIRST before building config
        for i, url in enumerate(proxy_urls):
            valid, error = self._validate_chain_transport(url, i + 1)
            if not valid:
                return None
        
        # REVERSE order to match v2rayN's approach
        # dialerProxy points to the NEXT outbound in the array
        # So we need: [LAST_HOP, ..., FIRST_HOP]
        # Then routing sends to FIRST_HOP which dials through the chain
        reversed_urls = list(reversed(proxy_urls))
        
        # Build outbound for each hop (in reversed order)
        outbounds = []
        chain_tags = []
        
        for i, url in enumerate(reversed_urls):
            outbound = self._url_to_outbound(url, f"chain-{i}")
            if not outbound:
                log(f"Failed to parse proxy URL at position {len(proxy_urls)-i} (reversed index {i+1})")
                return None
            self._apply_fragment(outbound)

            if i < len(reversed_urls) - 1:
                # All hops except the last one need dialerProxy
                if "streamSettings" not in outbound:
                    outbound["streamSettings"] = {}
                outbound["streamSettings"]["sockopt"] = {
                    "dialerProxy": f"chain-{i+1}"
                }
            
            outbound["tag"] = f"chain-{i}"
            chain_tags.append(f"chain-{i}")
            outbounds.append(outbound)
        
        # The FIRST hop in user's order is at the END of our reversed array
        first_hop_tag = f"chain-{len(reversed_urls)-1}"
        
        log(f"Created chain config with {len(proxy_urls)} hops")
        
        # Build complete config
        return {
            "log": {"loglevel": "error", "access": "", "error": ""},
            "inbounds": [{
                "tag": "socks",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "mixed",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {
                    "enabled": True,
                    "routeOnly": True,
                    "destOverride": ["http", "tls", "quic"]
                }
            }],
            "outbounds": outbounds + [
                {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}},
                {"tag": "block", "protocol": "blackhole"}
            ],
            "routing": {
                "domainStrategy": "AsIs",
                "rules": [{
                    "type": "field",
                    "inboundTag": ["socks"],
                    "outboundTag": first_hop_tag
                }]
            }
        }
    
    def _validate_chain_transport(self, url: str, hop_number: int) -> Tuple[bool, str]:
        """Validate proxy URL has compatible transport for chaining.
        
        Args:
            url: Proxy URL to validate
            hop_number: Human-readable hop position (1-based)
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        outbound = self._url_to_outbound(url, "temp")
        if not outbound:
            log(f"ERROR: Hop {hop_number} failed to parse URL")
            return False, "Failed to parse URL"
        
        stream_settings = outbound.get("streamSettings", {})
        security = stream_settings.get("security", "")
        network = stream_settings.get("network", "tcp")
        
        # Check for Reality protocol (not compatible with dialerProxy)
        if security == "reality":
            log(f"ERROR: Hop {hop_number} uses Reality protocol which is NOT compatible with dialerProxy chaining")
            log("Please use WebSocket (ws) or HTTPUpgrade transport with TLS instead")
            return False, "Reality protocol not compatible"
        
        # Check transport type
        if network not in CHAIN_TRANSPORT_WHITELIST:
            log(f"ERROR: Hop {hop_number} uses '{network}' transport which is NOT compatible with dialerProxy")
            log(f"Supported transports: {', '.join(CHAIN_TRANSPORT_WHITELIST)}")
            return False, f"Unsupported transport: {network}"
        
        # Check TLS requirement
        if security != CHAIN_SECURITY_REQUIRED:
            log(f"ERROR: Hop {hop_number} has security='{security}' but dialerProxy requires '{CHAIN_SECURITY_REQUIRED}'")
            return False, f"Security must be '{CHAIN_SECURITY_REQUIRED}', got '{security}'"
        
        return True, ""
    
    def create_multi_config(self, urls: List[str], base_port: int) -> Tuple[Optional[Dict], Dict[int, str]]:
        """Create SINGLE Xray config with multiple inbounds/outbounds (SMART batching).
        
        OPTIMAL BATCH SIZE: 100 configs per Xray instance.
        This creates ONE Xray process with 100 inbounds instead of 100 processes.
        
        Returns: (config_dict, port_to_url_mapping) or (None, {}) if failed
        """
        # SMART: Validate batch size
        if len(urls) > self.MAX_BATCH_SIZE:
            log(f"WARNING: Batch size {len(urls)} exceeds maximum {self.MAX_BATCH_SIZE}. Split into smaller batches.")
        
        config = {
            "log": {"loglevel": "error", "access": "", "error": ""},
            "inbounds": [],
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"}  # FIX: Required for proper routing
            ],
            "routing": {"domainStrategy": "AsIs", "rules": []}
        }
        port_map = {}
        used_ports = set()
        skipped_urls = []
        
        for idx, url in enumerate(urls):
            port = base_port + idx
            if port in used_ports:
                # Skip to next available port
                while port in used_ports:
                    port += 1
            
            # PRE-VALIDATE: Skip obviously broken configs BEFORE parsing
            # Skip configs that commonly cause Xray to crash entire batch
            if not url or not url.strip():
                skipped_urls.append((url, "Empty config"))
                continue
            
            # Skip malformed URLs
            if '://' not in url:
                skipped_urls.append((url, "Missing protocol prefix"))
                continue
            
            outbound = self._url_to_outbound(url, f"proxy{port}")
            if not outbound:
                skipped_urls.append((url, "Failed to parse outbound"))
                continue
            self._apply_fragment(outbound)

            # VALIDATE: Check for common config errors BEFORE adding to batch
            try:
                protocol = outbound.get("protocol", "")
                settings = outbound.get("settings", {})
                
                # Check VLESS/REALITY configs
                if protocol == "vless":
                    vnext = settings.get("vnext", [])
                    if vnext and len(vnext) > 0:
                        users = vnext[0].get("users", [])
                        if users and len(users) > 0:
                            user = users[0]
                            # Empty UUID/password
                            if not user.get("id"):
                                skipped_urls.append((url, "VLESS/REALITY with empty UUID"))
                                continue
                
                # Check Shadowsocks configs
                if protocol == "shadowsocks":
                    servers = settings.get("servers", [])
                    if servers and len(servers) > 0:
                        password = servers[0].get("password", "")

                        # Empty password
                        if not password:
                            skipped_urls.append((url, "Shadowsocks with empty password"))
                            continue
                
                # Check Trojan configs
                if protocol == "trojan":
                    servers = settings.get("servers", [])
                    if servers and len(servers) > 0:
                        password = servers[0].get("password", "")
                        if not password:
                            skipped_urls.append((url, "Trojan with empty password"))
                            continue
                
            except (KeyError, ValueError, IndexError, TypeError, json.JSONDecodeError) as e:
                skipped_urls.append((url, f"Validation error: {str(e)[:60]}"))
                continue
            
            inbound = {
                "tag": f"mixed{port}",
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "mixed",
                "settings": {"auth": "noauth", "udp": True}
            }
            config["inbounds"].append(inbound)
            config["outbounds"].append(outbound)
            
            rule = {
                "type": "field",
                "inboundTag": [f"mixed{port}"],
                "outboundTag": f"proxy{port}"
            }
            config["routing"]["rules"].append(rule)
            
            port_map[port] = url
            used_ports.add(port)
        
        if skipped_urls:
            # Log first few skipped configs for debugging
            sample = skipped_urls[:5]
            reasons = {}
            for _, reason in sample:
                reasons[reason] = reasons.get(reason, 0) + 1
            log(f"Skipped {len(skipped_urls)} invalid configs: {', '.join([f'{k}({v})' for k,v in list(reasons.items())[:3]])}...")
        
        if not port_map:
            return None, {}
        
        log(f"Created multi-config with {len(port_map)} valid inbounds (ports {min(port_map.keys())}-{max(port_map.keys())})")
        return config, port_map

    @staticmethod
    def _is_xray_spam(error_detail: str) -> bool:
        """Check if an Xray error message is spam (version banner, runtime info, etc.)."""
        spam_patterns = [
            "Xray 26.2.6",
            "Penetrates Everything",
            "A unified platform",
            "[Warning]", "[Info]",
            "infra/conf", "deprecated",
            "goroutine", "runtime.",
            "fp=0x", "sp=0x", "pc=0x",
            "runtime stack:", "fatal error:",
            "errno=", "ulimit",
            "Reading config:",
        ]
        return any(p in error_detail for p in spam_patterns)

    @staticmethod
    def _cleanup_config_file(config_file: Optional[str]) -> None:
        """Remove a config temp file if it exists. Safe to call with None."""
        if config_file and os.path.exists(config_file):
            try:
                os.unlink(config_file)
            except OSError:
                pass

    def _write_xray_config_file(self, config_json: str) -> Optional[str]:
        """Write Xray config JSON to a secure temp file.

        Returns the config file path on success, or None on failure.
        Cleans up the temp file on write failure.
        """
        try:
            fd, config_file = tempfile.mkstemp(suffix='.json', prefix='xray_')
            try:
                os.chmod(config_file, 0o600)
                with os.fdopen(fd, 'w') as f:
                    f.write(config_json)
            except OSError:
                os.close(fd)
                if config_file and os.path.exists(config_file):
                    os.unlink(config_file)
                raise
            return config_file
        except OSError:
            return None

    def _launch_xray_process(self, config_path: str) -> subprocess.Popen:
        """Launch Xray subprocess with config file."""
        cmd = [self.xray_path, "run", "-config", config_path]
        if sys.platform == "win32":
            return subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW,
                bufsize=1024 * 1024,
            )
        return subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            bufsize=1024 * 1024,
        )

    def start_xray_instance(self, config: Dict, socks_port: int, verbose: bool = False) -> Tuple[bool, Optional[subprocess.Popen], str]:
        """Start Xray with single config and wait for port readiness."""
        # Validate and serialize config
        try:
            config_json = json.dumps(config, separators=(',', ':'))
            json.loads(config_json)
        except json.JSONDecodeError as e:
            err = f"Invalid JSON config: {e}"
            if verbose:
                log(err)
            return False, None, err

        if not config.get('inbounds') or not config.get('outbounds'):
            err = "Invalid config structure: missing inbounds or outbounds"
            if verbose:
                log(f"{err}: {config_json[:500]}")
            return False, None, err

        config_file = self._write_xray_config_file(config_json)
        if config_file is None:
            return False, None, "Failed to write config file"

        try:
            process = self._launch_xray_process(config_file)
            # Short pause to let xray either bind the port or crash
            time.sleep(0.5)

            if process.poll() is not None:
                stdout, stderr = process.communicate(timeout=2)
                stderr_text = stderr.decode('utf-8', errors='ignore').strip() if stderr else ""
                stdout_text = stdout.decode('utf-8', errors='ignore').strip() if stdout else ""
                error_detail = stderr_text[:LOG_XRAY_ERROR_LENGTH] if stderr_text else (
                    stdout_text[:LOG_XRAY_ERROR_LENGTH] if stdout_text else "Xray exited immediately"
                )

                if self._is_xray_spam(error_detail):
                    self._track_error("XRAY_RESOURCE")
                    error_detail = "Xray resource error (filtered)"
                else:
                    log(f"Xray error: {error_detail[:LOG_ERROR_SAMPLE_LENGTH]}")

                # Cleanup config file on early exit
                self._cleanup_config_file(config_file)
                return False, None, error_detail

            if not self._wait_for_port(socks_port, timeout=XRAY_STARTUP_TIMEOUT):
                process.terminate()
                try:
                    stdout, stderr = process.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout, stderr = b"", b""
                stderr_text = stderr.decode('utf-8', errors='ignore').strip() if stderr else ""
                stdout_text = stdout.decode('utf-8', errors='ignore').strip() if stdout else ""
                error_detail = stderr_text[:2000] if stderr_text else (stdout_text[:2000] if stdout_text else "")
                if error_detail:
                    log(f"Xray port error: {error_detail[:1000]}")

                self._cleanup_config_file(config_file)
                return False, None, error_detail or "Port not listening"

            with self._process_lock:
                self._running_processes.append(process)
                self._config_files[process.pid] = config_file
            default_registry.register(self, process)

            return True, process, ""

        except (OSError, ValueError, subprocess.TimeoutExpired) as e:
            self._cleanup_config_file(config_file)
            error_str = str(e)
            is_config_error = any([
                'empty "password"' in error_str,
                'unsupported "encryption"' in error_str,
                "failed to build outbound" in error_str.lower(),
            ])
            if verbose and not is_config_error:
                log(f"Failed to start Xray: {e}")
            return False, None, str(e)
    
    def stop_xray_process(self, process: subprocess.Popen) -> None:
        """Stop Xray process with guaranteed cleanup using ManagedProcess."""
        # Pull config_file for this process before stopping (need pid lookup)
        config_file = self._config_files.pop(process.pid, None)
        mp = ManagedProcess(process, config_file=config_file)
        try:
            mp.stop(force=False, kill_timeout=XRAY_PROCESS_KILL_TIMEOUT,
                    force_kill_timeout=XRAY_PROCESS_FORCE_KILL_TIMEOUT)
        except (OSError, subprocess.TimeoutExpired, RuntimeError) as e:
            log(f"ERROR: Failed to stop process {process.pid}: {e}")
            if PSUTIL_AVAILABLE:
                try:
                    psutil.Process(process.pid).kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    pass
        
        with self._process_lock:
            if process in self._running_processes:
                self._running_processes.remove(process)
        # Also unregister from the shared ProcessRegistry.
        default_registry.unregister(self, process)
    
    def _get_session(self) -> requests.Session:
        """Get thread-local session (no lock contention)."""
        if not hasattr(self, '_thread_local') or self._thread_local is None:
            self._thread_local = threading.local()
        
        if not hasattr(self._thread_local, 'session'):
            session = requests.Session()
            adapter = HTTPAdapter(max_retries=0, pool_connections=1, pool_maxsize=1)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            self._thread_local.session = session
        
        return self._thread_local.session
    
    def _quick_validate_url(self, url: str) -> Tuple[bool, str]:
        """Minimal validation - let Xray decide if config is valid."""
        if not url or not isinstance(url, str):
            return False, "Empty URL"
        if '://' not in url:
            return False, "No protocol"
        # Let Xray validate the rest
        return True, ""
    
    
    def _track_error(self, error_msg: str, category: str = None) -> None:
        """Track error for summary statistics with deduplication."""
        # Auto-categorize if not provided
        if not category:
            error_lower = error_msg.lower() if error_msg else "unknown"
            
            if "timeout" in error_lower or "timed out" in error_lower:
                category = "timeout"
            elif "connection refused" in error_lower:
                category = "connection_refused"
            elif "connection reset" in error_lower or "connection aborted" in error_lower:
                category = "connection_reset"
            elif "proxy" in error_lower or "socks" in error_lower:
                category = "proxy_error"
            elif "xray" in error_lower or "process" in error_lower:
                category = "xray_error"
            elif "parse" in error_lower or "invalid" in error_lower or "malformed" in error_lower:
                category = "parse_error"
            elif "certificate" in error_lower or "ssl" in error_lower or "tls" in error_lower:
                category = "ssl_error"
            elif "http" in error_lower and ("failed" in error_lower or "error" in error_lower):
                category = "http_error"
            else:
                category = "other"
        
        # Normalize error message for deduplication (remove specific values)
        normalized = self._normalize_error(error_msg)
        
        with self._error_stats_lock:
            self._error_stats[category] = self._error_stats.get(category, 0) + 1
            
            # Store up to 3 sample errors per category
            if category not in self._error_samples:
                self._error_samples[category] = []
            if len(self._error_samples[category]) < 3 and normalized not in self._error_samples[category]:
                self._error_samples[category].append(error_msg[:200])
    
    def _normalize_error(self, error_msg: str) -> str:
        """Normalize error message by removing variable parts for deduplication."""
        if not error_msg:
            return "unknown"
        
        # Remove ports, IPs, UUIDs, timestamps
        normalized = error_msg
        # Remove port numbers
        normalized = re.sub(r':\d+', ':PORT', normalized)
        # Remove UUIDs
        normalized = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'UUID', normalized, flags=re.I)
        # Remove IP addresses
        normalized = re.sub(r'\d+\.\d+\.\d+\.\d+', 'IP', normalized)
        # Remove file paths
        normalized = re.sub(r'C:\\[^\\s]+|/[^\\s]+\\.json', 'FILE', normalized)
        
        return normalized[:150]  # Truncate for comparison
    
    def _print_error_summary(self) -> None:
        """Print detailed summary of errors with samples (called once at end of batch)."""
        with self._error_stats_lock:
            if not self._error_stats:
                return
            
            log(f"\n{'='*70}")
            log("DETAILED ERROR SUMMARY:")
            total = sum(self._error_stats.values())
            
            for category, count in sorted(self._error_stats.items(), key=lambda x: -x[1]):
                pct = count / total * 100 if total > 0 else 0
                log(f"\n  {category.upper()}: {count} ({pct:.1f}%)")
                
                # Show sample errors for this category
                if category in self._error_samples:
                    for i, sample in enumerate(self._error_samples[category], 1):
                        log(f"    [{i}] {sample}")
            
            log(f"\n  {'='*60}")
            log(f"  TOTAL ERRORS: {total}")
            log(f"{'='*70}\n")
            
            # Reset for next batch
            self._error_stats.clear()
            self._error_samples.clear()
    
    def _validate_response(self, test_url: str, body: str) -> bool:
        """Validate response body is genuine, not a block/cache/error page."""
        if 'cdn-cgi/trace' in test_url:
            return 'ip=' in body
        if 'generate_204' in test_url:
            return len(body.strip()) == 0
        return bool(body.strip())

    @staticmethod
    def _apply_fragment(outbound: Dict) -> None:
        """Add TLS fragment to outbound streamSettings if enabled in settings."""
        if not ENABLE_FRAGMENT:
            return
        stream = outbound.setdefault("streamSettings", {})
        stream["fragment"] = {
            "packets": FRAGMENT_PACKETS,
            "length": FRAGMENT_LENGTH,
            "interval": FRAGMENT_INTERVAL,
        }

    async def _tcp_ping(self, host: str, port: int, timeout: float = 1.5) -> bool:
        """Quick async TCP connect. Returns True if port is reachable."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False

    
    
    
    
    
    
    
    
    
    
    
    def cleanup(self) -> None:
        """Stop all running Xray instances with guaranteed cleanup."""
        # Stop all processes with psutil fallback
        with self._process_lock:
            for process in self._running_processes[:]:
                try:
                    mp = ManagedProcess(process)
                    if process.poll() is None:
                        mp.stop(force=False, kill_timeout=3, force_kill_timeout=2)
                except (OSError, psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    log(f"ERROR: Failed to stop process {process.pid}: {e}")
                    if PSUTIL_AVAILABLE:
                        try:
                            psutil.Process(process.pid).kill()
                        except (psutil.NoSuchProcess, OSError):
                            pass
            self._running_processes.clear()
        
        # Delete all config files (security: remove credentials from disk)
        for config_file in list(self._config_files.values()):
            try:
                if os.path.exists(config_file):
                    os.unlink(config_file)
            except (OSError, PermissionError) as e:
                log(f"ERROR: Failed to delete config file: {e}")
        self._config_files.clear()
        
        # Clear thread-local sessions to prevent memory leak
        if hasattr(self, '_thread_local') and self._thread_local is not None:
            if hasattr(self._thread_local, 'session'):
                try:
                    self._thread_local.session.close()
                except (OSError, RuntimeError):
                    pass
                delattr(self._thread_local, 'session')

        # No global tester registry to remove from. The shared ProcessRegistry
        # tracks (tester, process) pairs; processes are unregistered when
        # stop_xray_process is called explicitly. If a tester is GC'd without
        # calling stop on its processes, they remain in the registry and are
        # caught by the next default_registry.cleanup() call.


    def test_batch(self, urls, concurrency=None, timeout=None, verbose=False,
                    progress_callback=None):
        """Test configs through Xray with batch runner."""
        return self._batch_runner.test_batch(urls, concurrency, timeout, verbose, progress_callback=progress_callback)

    def test_single_config(self, url, timeout, verbose=False, max_retries=1, skip_tcp_ping=False):
        """Test config through Xray HTTP test via batch runner."""
        return self._batch_runner.test_single_config(url, timeout, verbose, max_retries, skip_tcp_ping)

    def test_through_socks(self, socks_port, timeout, verbose=False):
        """Test connection through SOCKS proxy via batch runner."""
        return self._batch_runner.test_through_socks(socks_port, timeout, verbose)

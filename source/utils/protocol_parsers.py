"""
Standalone protocol parsers for Xray outbound configs.

Extracted from utils/xray_tester.py to reduce the size of that god module.

Each function takes a URL and a tag string, returning an Optional[Dict]
representing an Xray outbound config, or None if the URL could not be parsed.

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

import base64
import json
import re
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote

from utils.logger import log
from utils.security_filter import SS_WEAK_CIPHERS
from utils.vpn_config import parse_url as vpn_parse_url


# ── Shared helpers ─────────────────────────────────────────────────────

def _clean_url_part(url: str) -> str:
    """Strip protocol:// prefix case-insensitively."""
    return url[url.index('://') + 3:]


def _split_fragment_query(url_part: str) -> Tuple[str, str, str]:
    """Split url_part into (base_part, query_part, fragment).

    Handles both #fragment and ?query separators in any order.
    """
    fragment = ''
    if '#' in url_part:
        url_part, fragment = url_part.split('#', 1)
    query_part = ''
    if '?' in url_part:
        base_part, query_part = url_part.split('?', 1)
    else:
        base_part = url_part
    return base_part, query_part, fragment


def _parse_user_host_port(base_part: str) -> Optional[Tuple[str, str, int]]:
    """Parse 'user@host:port' from a URL base part.

    Returns (user, hostname, port) or None on failure.
    """
    if '@' not in base_part:
        return None
    user, host_port = base_part.rsplit('@', 1)
    if ':' not in host_port:
        return None
    hostname, port_str = host_port.rsplit(':', 1)
    port_str = port_str.strip().rstrip('/')
    try:
        port = int(port_str)
    except (ValueError, TypeError):
        return None
    if not hostname or not port or not user:
        return None
    return user, hostname, port


def _make_tls_settings(sni: str, fp: str = None) -> dict:
    """Build tlsSettings dict."""
    from config.settings import TLS_FINGERPRINT
    return {"serverName": sni, "fingerprint": fp or TLS_FINGERPRINT}


def _make_reality_settings(sni: str, pbk: str, fp: str = None, sid: str = '') -> Optional[dict]:
    """Build realitySettings dict. Returns None if sni or pbk is missing."""
    from config.settings import TLS_FINGERPRINT
    sni = sni.strip()
    pbk = pbk.strip()
    if not sni or not pbk:
        return None
    return {"serverName": sni, "fingerprint": fp, "publicKey": pbk, "shortId": sid}


def _make_ws_settings(path: str, host: str) -> dict:
    """Build wsSettings dict."""
    return {"path": unquote(path), "headers": {"Host": unquote(host)}}


def _make_grpc_settings(service_name: str) -> dict:
    """Build grpcSettings dict."""
    return {"serviceName": unquote(service_name)}


def _make_httpupgrade_settings(path: str, host: str) -> dict:
    """Build httpupgradeSettings dict."""
    return {"path": unquote(path), "headers": {"Host": unquote(host)}}


def _make_stream_settings(
    network: str, security: str, params: dict, default_host: str
) -> Optional[dict]:
    """Build streamSettings dict for common transports (ws, grpc, httpupgrade).

    Returns None if Reality params are invalid.
    """
    stream = {"network": network, "security": security}

    if security == 'tls':
        sni = params.get('sni', [default_host])[0]
        if not sni:
            sni = default_host
        fp_from_url = params.get('fp', [None])[0] or None
        stream["tlsSettings"] = _make_tls_settings(sni, fp_from_url)
    elif security == 'reality':
        fp_from_url = params.get('fp', [None])[0] or None
        reality = _make_reality_settings(
            params.get('sni', [''])[0],
            params.get('pbk', [''])[0],
            fp_from_url,
            params.get('sid', [''])[0],
        )
        if reality is None:
            return None
        stream["realitySettings"] = reality

    if network == 'ws':
        stream["wsSettings"] = _make_ws_settings(
            params.get('path', ['/'])[0],
            params.get('host', [default_host])[0],
        )
    elif network == 'grpc':
        stream["grpcSettings"] = _make_grpc_settings(params.get('serviceName', [''])[0])
    elif network == 'httpupgrade':
        stream["httpupgradeSettings"] = _make_httpupgrade_settings(
            params.get('path', ['/'])[0],
            params.get('host', [default_host])[0],
        )

    return stream


# ── Protocol parsers ──────────────────────────────────────────────────

def parse_vless_to_outbound(url: str, tag: str = "proxy") -> Optional[Dict]:
    """Parse VLESS URL to Xray outbound with tag."""
    try:
        url_part = _clean_url_part(url)
        base_part, query_part, _ = _split_fragment_query(url_part)
        parsed = _parse_user_host_port(base_part)
        if parsed is None:
            return None
        uuid, hostname, port = parsed
        params = parse_qs(query_part)

        stream = _make_stream_settings(
            params.get('type', ['tcp'])[0],
            params.get('security', ['none'])[0],
            params, hostname,
        )
        if stream is None:
            return None

        return {
            "tag": tag,
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": hostname,
                    "port": port,
                    "users": [{
                        "id": uuid,
                        "encryption": params.get('encryption', ['none'])[0],
                        "flow": params.get('flow', [''])[0]
                    }]
                }]
            },
            "streamSettings": stream
        }
    except (ValueError, IndexError, KeyError, TypeError, json.JSONDecodeError, base64.binascii.Error):
        return None


def parse_vmess_to_outbound(url: str, tag: str = "proxy") -> Optional[Dict]:
    """Parse VMess URL to Xray outbound."""
    try:
        encoded = url[url.index('://') + 3:].strip()

        # Add padding if needed
        padding = 4 - len(encoded) % 4
        if padding != 4:
            encoded += '=' * padding

        # Decode base64
        try:
            decoded_bytes = base64.b64decode(encoded)
        except (ValueError, IndexError, KeyError, TypeError, json.JSONDecodeError, base64.binascii.Error):
            return None

        # Decode UTF-8
        try:
            decoded = decoded_bytes.decode('utf-8', errors='ignore')
        except (ValueError, IndexError, KeyError, TypeError, json.JSONDecodeError, base64.binascii.Error):
            return None

        # Parse JSON
        try:
            data = json.loads(decoded)
        except json.JSONDecodeError:
            return None

        # Validate required fields
        if not data.get('add') or not data.get('port') or not data.get('id'):
            return None

        # Build stream settings
        network = data.get('net', 'tcp')
        security = data.get('tls', '')

        stream_settings = {
            "network": network,
            "security": security if security else 'none'
        }

        # Add tlsSettings when security is TLS
        if security == 'tls':
            server_name = data.get('host') or data.get('add')
            if not server_name or not server_name.strip():
                return None
            stream_settings["tlsSettings"] = {
                "serverName": server_name.strip(),
                "fingerprint": data.get('fp', 'chrome')
            }

        # Add transport-specific settings
        if network == 'ws':
            stream_settings["wsSettings"] = {
                "path": data.get('path', '/'),
                "headers": {
                    "Host": data.get('host', data.get('add', ''))
                }
            }
        elif network == 'grpc':
            stream_settings["grpcSettings"] = {
                "serviceName": data.get('path', '')
            }
        elif network == 'h2':
            host_value = data.get('host')
            if isinstance(host_value, list):
                hosts = host_value if host_value else [data.get('add', '')]
            else:
                hosts = [host_value] if host_value else [data.get('add', '')]

            stream_settings["httpSettings"] = {
                "path": data.get('path', '/'),
                "host": hosts
            }

        return {
            "tag": tag,
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": str(data.get('add', '')),
                    "port": int(data.get('port', 443)),
                    "users": [{
                        "id": str(data.get('id', '')),
                        "alterId": int(data.get('aid', 0)),
                        "security": data.get('scy', 'auto')
                    }]
                }]
            },
            "streamSettings": stream_settings
        }
    except (ValueError, IndexError, KeyError, TypeError, json.JSONDecodeError, base64.binascii.Error):
        return None


def parse_trojan_to_outbound(url: str, tag: str = "proxy") -> Optional[Dict]:
    """Parse Trojan URL to Xray outbound."""
    try:
        url_part = _clean_url_part(url)
        base_part, query_part, _ = _split_fragment_query(url_part)
        parsed = _parse_user_host_port(base_part)
        if parsed is None:
            return None
        password, hostname, port = parsed
        params = parse_qs(query_part)

        security = params.get('security', ['tls'])[0] if params.get('security') else 'tls'
        network = params.get('type', ['tcp'])[0] if params.get('type') else 'tcp'

        stream = _make_stream_settings(network, security, params, hostname)
        if stream is None:
            return None

        return {
            "tag": tag,
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": hostname,
                    "port": port,
                    "password": password
                }]
            },
            "streamSettings": stream
        }
    except (ValueError, IndexError, KeyError, TypeError, json.JSONDecodeError, base64.binascii.Error):
        return None


def _decode_ss_base64(url_part: str) -> Optional[tuple]:
    """Try base64 decode of url_part to extract method:password@host:port.

    Returns a tuple (method, password, hostname, port) or None on failure.
    """
    try:
        # Add padding if needed
        padding = 4 - len(url_part) % 4
        if padding != 4:
            url_part += '=' * padding

        decoded = base64.urlsafe_b64decode(url_part).decode('utf-8', errors='ignore')

        # Decoded format: method:password@host:port
        if '@' in decoded:
            userinfo, server = decoded.rsplit('@', 1)
            if ':' in userinfo:
                method, password = userinfo.split(':', 1)
            else:
                method = userinfo
                password = ''

            if ':' in server:
                hostname, port_str = server.rsplit(':', 1)
                port = int(port_str)
            else:
                hostname = server
                port = 443
            return method, password, hostname, port
    except (ValueError, IndexError, json.JSONDecodeError):
        pass
    return None


def _parse_ss_legacy_format(url: str) -> Optional[tuple]:
    """Try legacy method:password@host:port format (not base64).

    Parses the full URL from scratch, ignoring any previous base64 modifications.
    Returns a tuple (method, password, hostname, port) or None on failure.
    """
    try:
        url_part = url[url.index('://') + 3:]
        if '#' in url_part:
            url_part, _ = url_part.split('#', 1)
        if '?' in url_part:
            url_part, _ = url_part.split('?', 1)

        if '@' in url_part:
            userinfo, server = url_part.rsplit('@', 1)
            if ':' in userinfo:
                method, password = userinfo.split(':', 1)
            else:
                method = userinfo
                password = ''

            if ':' in server:
                hostname, port_str = server.rsplit(':', 1)
                port = int(port_str)
            else:
                hostname = server
                port = 443
            return method, password, hostname, port
    except (ValueError, IndexError):
        pass
    return None


def _parse_ss_last_resort(url: str) -> Optional[tuple]:
    """Last resort: try to extract host and port from url_part.

    Parses the full URL from scratch. Only extracts hostname and port;
    method and password are returned as defaults (chacha20-poly1305 / empty).
    Returns a tuple (method, password, hostname, port) or None on failure.
    """
    try:
        url_part = url[url.index('://') + 3:]
        if '#' in url_part:
            url_part, _ = url_part.split('#', 1)
        if '?' in url_part:
            url_part, _ = url_part.split('?', 1)

        if ':' in url_part:
            parts = url_part.split(':')
            if len(parts) >= 2:
                port_str = parts[-1].strip()
                hostname = ':'.join(parts[:-1]).split('@')[-1]
                try:
                    port = int(port_str)
                    return 'chacha20-poly1305', '', hostname, port
                except ValueError:
                    pass
    except (ValueError, IndexError):
        pass
    return None


def parse_shadowsocks_to_outbound(url: str, tag: str = "proxy") -> Optional[Dict]:
    """Parse Shadowsocks URL to Xray outbound.

    Filters weak ciphers (RC4, DES, CFB modes, Salsa20, Chacha20 non-IETF).
    Only AEAD ciphers are considered secure.
    """
    try:
        # Remove protocol prefix (case-insensitive)
        url_part = url[url.index('://') + 3:]

        # Split at # to separate fragment
        if '#' in url_part:
            url_part, _ = url_part.split('#', 1)

        # Split at ? to separate query params FIRST
        if '?' in url_part:
            url_part, query_part = url_part.split('?', 1)
        else:
            query_part = ''

        # Handle both formats: base64 and plain
        method = 'chacha20-poly1305'
        password = ''
        hostname = None
        port = None

        # Try base64 decode first (uses stripped url_part directly)
        result = _decode_ss_base64(url_part)
        if result:
            method, password, hostname, port = result
        else:
            # Try legacy format: method:password@host:port (not base64)
            result = _parse_ss_legacy_format(url)
            if result:
                method, password, hostname, port = result
            else:
                # Last resort: try to extract what we can
                result = _parse_ss_last_resort(url)
                if result:
                    method, password, hostname, port = result

        # Final validation
        if not hostname:
            return None

        if not port:
            port = 443

        # SECURITY: Reject empty passwords
        if not password or not password.strip():
            return None

        # SECURITY CHECK: Reject weak ciphers (using module-level constants)
        method_lower = method.lower()
        if method_lower in SS_WEAK_CIPHERS:
            return None

        # Parse query params for additional settings
        params = parse_qs(query_part) if query_part else {}

        # Reject plugin configs (not supported by Xray)
        plugin = params.get('plugin', [None])[0] if params.get('plugin') else None
        if plugin:
            return None

        # Add network transport settings if specified
        network = params.get('type', ['tcp'])[0] if params.get('type') else 'tcp'
        stream_settings = {
            "network": network,
            "security": "none"
        }

        if network == 'ws':
            stream_settings["wsSettings"] = {
                "path": unquote(params.get('path', ['/'])[0]),
                "headers": {"Host": unquote(params.get('host', [hostname])[0])}
            }

        outbound = {
            "tag": tag,
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": str(hostname),
                    "port": int(port),
                    "password": str(password),
                    "method": str(method)
                }]
            },
            "streamSettings": stream_settings
        }

        return outbound
    except (ValueError, IndexError, KeyError, TypeError, json.JSONDecodeError, base64.binascii.Error):
        return None


def parse_hysteria2_to_outbound(url: str, tag: str = "proxy") -> Optional[Dict]:
    """Parse Hysteria2/Hy2 URL to Xray outbound."""
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not parsed.hostname or not parsed.port:
            return None

        # Hysteria2 uses QUIC transport with TLS
        auth = unquote(parsed.username) if parsed.username else ""
        sni = params.get('sni', [parsed.hostname])[0] if params.get('sni') else parsed.hostname

        # Validate SNI for TLS
        if not sni or not sni.strip():
            sni = parsed.hostname

        # Hysteria2 uses different structure - direct settings, NOT servers[] array
        # Password goes in hysteriaSettings.auth, NOT in settings.password
        return {
            "tag": tag,
            "protocol": "hysteria2",
            "settings": {
                "version": 2,
                "address": parsed.hostname,
                "port": parsed.port
            },
            "streamSettings": {
                "network": "hysteria",
                "security": "tls",
                "hysteriaSettings": {
                    "version": 2,
                    "auth": auth
                },
                "tlsSettings": {
                    "serverName": sni,
                    "fingerprint": params.get('fp', ['chrome'])[0] if params.get('fp') else 'chrome'
                }
            }
        }
    except (ValueError, IndexError, KeyError, TypeError, json.JSONDecodeError, base64.binascii.Error):
        return None


def parse_hysteria_to_outbound(url: str, tag: str = "proxy") -> Optional[Dict]:
    """Parse Hysteria v1 URL to Xray outbound.

    Note: Hysteria v1 has limited support in Xray-core. This parser creates
    a basic config but may not work with all Hysteria v1 servers.
    """
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not parsed.hostname or not parsed.port:
            return None

        auth = unquote(parsed.username) if parsed.username else params.get('auth', [''])[0]
        protocol = params.get('protocol', ['udp'])[0]
        sni = params.get('sni', [parsed.hostname])[0] if params.get('sni') else parsed.hostname

        # Check for insecure TLS setting
        insecure = params.get('insecure', ['0'])[0] == '1'

        return {
            "tag": tag,
            "protocol": "hysteria",
            "settings": {
                "servers": [{
                    "address": parsed.hostname,
                    "port": parsed.port,
                    "password": auth
                }]
            },
            "streamSettings": {
                "network": "hysteria",
                "security": "tls",
                "hysteriaSettings": {
                    "version": 1,
                    "auth": auth,
                    "protocol": protocol,
                    "up_mbps": int(params.get('upmbps', ['100'])[0]) if params.get('upmbps') else 100,
                    "down_mbps": int(params.get('downmbps', ['100'])[0]) if params.get('downmbps') else 100
                },
                "tlsSettings": {
                    "serverName": sni,
                    "insecure": insecure
                }
            }
        }
    except (ValueError, IndexError, KeyError, TypeError, json.JSONDecodeError, base64.binascii.Error):
        return None


def parse_ssr_to_outbound(url: str, tag: str = "proxy") -> Optional[Dict]:
    """Parse ShadowsocksR (SSR) URL to Xray outbound.

    Note: Xray-core has limited SSR support. This converts to basic Shadowsocks
    without SSR-specific features (protocol, obfs). For full SSR support, use v2fly-core.
    """
    try:
        url_part = _clean_url_part(url)

        # Add padding if needed
        padding = 4 - len(url_part) % 4
        if padding != 4:
            url_part += '=' * padding

        # Decode base64
        try:
            decoded = base64.urlsafe_b64decode(url_part).decode('utf-8', errors='ignore')
        except (ValueError, IndexError, KeyError, TypeError, json.JSONDecodeError, base64.binascii.Error):
            return None

        # SSR format: host:port:protocol:method:obfs:base64pass/?obfsparam=base64&protoparam=base64&remarks=base64
        if '/?' in decoded:
            main_part, query_part = decoded.split('/?', 1)
        else:
            main_part = decoded
            query_part = ''

        parts = main_part.split(':')
        if len(parts) < 6:
            return None

        hostname = parts[0]
        try:
            port = int(parts[1])
            if port <= 0:
                return None
        except ValueError:
            return None

        protocol = parts[2]
        method = parts[3]
        obfs = parts[4]
        # protocol/obfs parsed for forward-compat; not used in current cipher check
        del protocol, obfs

        # Decode password from base64 with validation
        try:
            password_padding = 4 - len(parts[5]) % 4
            if password_padding != 4:
                password_base64 = parts[5] + '=' * password_padding
            password = base64.urlsafe_b64decode(password_base64).decode('utf-8', errors='ignore').strip()
            if not password:
                return None
        except (ValueError, IndexError, KeyError, TypeError, json.JSONDecodeError, base64.binascii.Error):
            return None

        # Parse query params (forward-compat: may be used by future checks)
        params = parse_qs(query_part)
        del params

        # SECURITY CHECK: Reject weak ciphers (using module-level constants)
        if method.lower() in SS_WEAK_CIPHERS:
            return None

        # Note: Xray-core has limited SSR support. This creates a basic Shadowsocks config
        # without SSR-specific features (protocol, obfs). For full SSR support, use v2fly-core.
        return {
            "tag": tag,
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": hostname,
                    "port": port,
                    "password": password,
                    "method": method
                }]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none"
            }
        }
    except (ValueError, IndexError, KeyError, TypeError, json.JSONDecodeError, base64.binascii.Error):
        return None


def parse_tuic_to_outbound(url: str, tag: str = "proxy") -> Optional[Dict]:
    """Parse TUIC URL to Xray outbound.

    Note: TUIC is not natively supported by Xray-core. This parser always
    returns None. For TUIC support, use sing-box instead.
    """
    return None


def parse_url_to_outbound(url: str, tag: str = "proxy") -> Optional[Dict]:
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
    # Primary path: typed VPNConfig dataclass
    try:
        cfg = vpn_parse_url(url)
        if cfg is not None:
            outbound = cfg.to_xray_outbound(tag)
            if outbound is not None:
                return outbound
    except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
        pass  # Fall through to legacy parsers

    # Fallback: legacy inline parsers
    url_lower = url.lower()
    dispatch = {
        'vless://': parse_vless_to_outbound,        # Full support
        'vmess://': parse_vmess_to_outbound,        # Full support
        'trojan://': parse_trojan_to_outbound,      # Full support
        'ss://': parse_shadowsocks_to_outbound,     # Full support (AEAD only)
        'ssr://': parse_ssr_to_outbound,            # Limited (converted to SS)
        'hysteria://': parse_hysteria_to_outbound,  # Limited (v1)
        'hysteria2://': parse_hysteria2_to_outbound, # Full support (v2)
        'hy2://': parse_hysteria2_to_outbound,      # Alias for hysteria2
    }

    for prefix, parser in dispatch.items():
        if url_lower.startswith(prefix):
            return parser(url, tag)

    return None

"""
Standalone protocol parsers for Xray outbound configs.

Extracted from utils/xray_tester.py to reduce the size of that god module.

Each function takes a URL and a tag string, returning an Optional[Dict]
representing an Xray outbound config, or None if the URL could not be parsed.

Supported protocols:
- VLESS: Full support (TLS, Reality, WS, gRPC, HTTPUpgrade)
- VMess: Full support (TLS, WS, gRPC, h2)
- Trojan: Full support (TLS, Reality, WS, gRPC, HTTPUpgrade)
- Shadowsocks: AEAD methods only; `plugin=` is rejected (xray takes no plugin)
- ShadowsocksR: Basic support (converted to Shadowsocks, SSR features limited in Xray-core)
- Hysteria2: Full support — outbound "hysteria" with version 2, TLS, salamander finalmask
- Hysteria v1: NOT supported by Xray-core (refused before verification, not parsed)
- TUIC: NOT supported by Xray-core (use sing-box for TUIC)

Hysteria v1 has no parser here on purpose: xray's hysteria outbound rejects
`version != 2` when it loads a config, and in batch mode one failed load drops
every other config sharing the process. `utils/xray_tester.py` refuses those URLs
with that reason instead.
"""

import base64
import binascii
import json
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from utils.security_filter import SS_WEAK_CIPHERS
from utils.vpn_config import parse_url as vpn_parse_url

# ── Shared helpers ─────────────────────────────────────────────────────


def _clean_url_part(url: str) -> str:
    """Strip protocol:// prefix case-insensitively."""
    return url[url.index("://") + 3 :]


def _split_fragment_query(url_part: str) -> tuple[str, str, str]:
    """Split url_part into (base_part, query_part, fragment).

    Handles both #fragment and ?query separators in any order.
    """
    fragment = ""
    if "#" in url_part:
        url_part, fragment = url_part.split("#", 1)
    query_part = ""
    if "?" in url_part:
        base_part, query_part = url_part.split("?", 1)
    else:
        base_part = url_part
    return base_part, query_part, fragment


def _parse_user_host_port(base_part: str) -> tuple[str, str, int] | None:
    """Parse 'user@host:port' from a URL base part.

    Returns (user, hostname, port) or None on failure.
    """
    if "@" not in base_part:
        return None
    user, host_port = base_part.rsplit("@", 1)
    if ":" not in host_port:
        return None
    hostname, port_str = host_port.rsplit(":", 1)
    port_str = port_str.strip().rstrip("/")
    try:
        port = int(port_str)
    except (ValueError, TypeError):
        return None
    if not hostname or not port or not user:
        return None
    return user, hostname, port


def apply_tls_fragment(stream: dict[str, Any]) -> None:
    """Attach TLS ClientHello fragmentation, in the shape xray reads.

    There is no `streamSettings.fragment` key in xray: an unrecognised field is
    skipped silently, so a config written that way verifies with an intact
    ClientHello and the operator never learns. Fragmentation is a TCP finalmask
    stage — `finalmask.tcp` with `{"type": "fragment", "settings": {...}}` — and
    the pacing field xray calls `delay`, not `interval`.

    Skipped for hysteria: that transport is QUIC, so a TCP-stage mask would be
    dead weight in a config the pipeline is about to hand to xray.
    """
    from config.settings import (
        ENABLE_FRAGMENT,
        FRAGMENT_INTERVAL,
        FRAGMENT_LENGTH,
        FRAGMENT_PACKETS,
    )

    if not ENABLE_FRAGMENT or stream.get("network") == "hysteria":
        return

    finalmask = stream.setdefault("finalmask", {})
    # `udp` may already carry a salamander stage from the hysteria2 parser;
    # replacing the dict instead of appending would silently drop it.
    finalmask.setdefault("tcp", []).append(
        {
            "type": "fragment",
            "settings": {
                "packets": FRAGMENT_PACKETS,
                "length": FRAGMENT_LENGTH,
                "delay": FRAGMENT_INTERVAL,
            },
        }
    )


def _make_tls_settings(sni: str, fp: str | None = None) -> dict:
    """Build tlsSettings dict."""
    from config.settings import TLS_FINGERPRINT

    return {"serverName": sni, "fingerprint": fp or TLS_FINGERPRINT}


def _make_reality_settings(sni: str, pbk: str, fp: str | None = None, sid: str = "") -> dict | None:
    """Build realitySettings dict. Returns None if sni or pbk is missing."""
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
) -> dict | None:
    """Build streamSettings dict for common transports (ws, grpc, httpupgrade).

    Returns None if Reality params are invalid.
    """
    stream: dict[str, Any] = {"network": network, "security": security}

    if security == "tls":
        sni = params.get("sni", [default_host])[0]
        if not sni:
            sni = default_host
        fp_from_url = params.get("fp", [None])[0] or None
        stream["tlsSettings"] = _make_tls_settings(sni, fp_from_url)
    elif security == "reality":
        fp_from_url = params.get("fp", [None])[0] or None
        reality = _make_reality_settings(
            params.get("sni", [""])[0],
            params.get("pbk", [""])[0],
            fp_from_url,
            params.get("sid", [""])[0],
        )
        if reality is None:
            return None
        stream["realitySettings"] = reality

    if network == "ws":
        stream["wsSettings"] = _make_ws_settings(
            params.get("path", ["/"])[0],
            params.get("host", [default_host])[0],
        )
    elif network == "grpc":
        stream["grpcSettings"] = _make_grpc_settings(params.get("serviceName", [""])[0])
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = _make_httpupgrade_settings(
            params.get("path", ["/"])[0],
            params.get("host", [default_host])[0],
        )

    return stream


# ── Protocol parsers ──────────────────────────────────────────────────


def parse_vless_to_outbound(url: str, tag: str = "proxy") -> dict | None:
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
            params.get("type", ["tcp"])[0],
            params.get("security", ["none"])[0],
            params,
            hostname,
        )
        if stream is None:
            return None

        return {
            "tag": tag,
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": hostname,
                        "port": port,
                        "users": [
                            {
                                "id": uuid,
                                "encryption": params.get("encryption", ["none"])[0],
                                "flow": params.get("flow", [""])[0],
                            }
                        ],
                    }
                ]
            },
            "streamSettings": stream,
        }
    except (
        ValueError,
        IndexError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
        binascii.Error,
    ):
        return None


def parse_vmess_to_outbound(url: str, tag: str = "proxy") -> dict | None:
    """Parse VMess URL to Xray outbound."""
    try:
        encoded = url[url.index("://") + 3 :].strip()

        # Add padding if needed
        padding = 4 - len(encoded) % 4
        if padding != 4:
            encoded += "=" * padding

        # Decode base64
        try:
            decoded_bytes = base64.b64decode(encoded)
        except (
            ValueError,
            IndexError,
            KeyError,
            TypeError,
            json.JSONDecodeError,
            binascii.Error,
        ):
            return None

        # Decode UTF-8
        try:
            decoded = decoded_bytes.decode("utf-8", errors="ignore")
        except (
            ValueError,
            IndexError,
            KeyError,
            TypeError,
            json.JSONDecodeError,
            binascii.Error,
        ):
            return None

        # Parse JSON
        try:
            data = json.loads(decoded)
        except json.JSONDecodeError:
            return None

        # Validate required fields
        if not data.get("add") or not data.get("port") or not data.get("id"):
            return None

        # Build stream settings
        network = data.get("net", "tcp")
        security = data.get("tls", "")

        stream_settings = {"network": network, "security": security if security else "none"}

        # Add tlsSettings when security is TLS
        if security == "tls":
            server_name = data.get("host") or data.get("add")
            if not server_name or not server_name.strip():
                return None
            stream_settings["tlsSettings"] = {
                "serverName": server_name.strip(),
                "fingerprint": data.get("fp", "chrome"),
            }

        # Add transport-specific settings
        if network == "ws":
            stream_settings["wsSettings"] = {
                "path": data.get("path", "/"),
                "headers": {"Host": data.get("host", data.get("add", ""))},
            }
        elif network == "grpc":
            stream_settings["grpcSettings"] = {"serviceName": data.get("path", "")}
        elif network == "h2":
            host_value = data.get("host")
            if isinstance(host_value, list):
                hosts = host_value if host_value else [data.get("add", "")]
            else:
                hosts = [host_value] if host_value else [data.get("add", "")]

            stream_settings["httpSettings"] = {"path": data.get("path", "/"), "host": hosts}

        return {
            "tag": tag,
            "protocol": "vmess",
            "settings": {
                "vnext": [
                    {
                        "address": str(data.get("add", "")),
                        "port": int(data.get("port", 443)),
                        "users": [
                            {
                                "id": str(data.get("id", "")),
                                "alterId": int(data.get("aid", 0)),
                                "security": data.get("scy", "auto"),
                            }
                        ],
                    }
                ]
            },
            "streamSettings": stream_settings,
        }
    except (
        ValueError,
        IndexError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
        binascii.Error,
    ):
        return None


def parse_trojan_to_outbound(url: str, tag: str = "proxy") -> dict | None:
    """Parse Trojan URL to Xray outbound."""
    try:
        url_part = _clean_url_part(url)
        base_part, query_part, _ = _split_fragment_query(url_part)
        parsed = _parse_user_host_port(base_part)
        if parsed is None:
            return None
        password, hostname, port = parsed
        params = parse_qs(query_part)

        security = params.get("security", ["tls"])[0] if params.get("security") else "tls"
        network = params.get("type", ["tcp"])[0] if params.get("type") else "tcp"

        stream = _make_stream_settings(network, security, params, hostname)
        if stream is None:
            return None

        return {
            "tag": tag,
            "protocol": "trojan",
            "settings": {"servers": [{"address": hostname, "port": port, "password": password}]},
            "streamSettings": stream,
        }
    except (
        ValueError,
        IndexError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
        binascii.Error,
    ):
        return None


def _decode_ss_base64(url_part: str) -> tuple | None:
    """Try base64 decode of url_part to extract method:password@host:port.

    Returns a tuple (method, password, hostname, port) or None on failure.
    """
    try:
        # Add padding if needed
        padding = 4 - len(url_part) % 4
        if padding != 4:
            url_part += "=" * padding

        decoded = base64.urlsafe_b64decode(url_part).decode("utf-8", errors="ignore")

        # Decoded format: method:password@host:port
        if "@" in decoded:
            userinfo, server = decoded.rsplit("@", 1)
            if ":" in userinfo:
                method, password = userinfo.split(":", 1)
            else:
                method = userinfo
                password = ""

            if ":" in server:
                hostname, port_str = server.rsplit(":", 1)
                port = int(port_str)
            else:
                hostname = server
                port = 443
            return method, password, hostname, port
    except (ValueError, IndexError, json.JSONDecodeError):
        pass
    return None


def _parse_ss_legacy_format(url: str) -> tuple | None:
    """Try legacy method:password@host:port format (not base64).

    Parses the full URL from scratch, ignoring any previous base64 modifications.
    Returns a tuple (method, password, hostname, port) or None on failure.
    """
    try:
        url_part = url[url.index("://") + 3 :]
        if "#" in url_part:
            url_part, _ = url_part.split("#", 1)
        if "?" in url_part:
            url_part, _ = url_part.split("?", 1)

        if "@" in url_part:
            userinfo, server = url_part.rsplit("@", 1)
            if ":" in userinfo:
                method, password = userinfo.split(":", 1)
            else:
                method = userinfo
                password = ""

            if ":" in server:
                hostname, port_str = server.rsplit(":", 1)
                port = int(port_str)
            else:
                hostname = server
                port = 443
            return method, password, hostname, port
    except (ValueError, IndexError):
        pass
    return None


def _parse_ss_last_resort(url: str) -> tuple | None:
    """Last resort: try to extract host and port from url_part.

    Parses the full URL from scratch. Only extracts hostname and port;
    method and password are returned as defaults (chacha20-poly1305 / empty).
    Returns a tuple (method, password, hostname, port) or None on failure.
    """
    try:
        url_part = url[url.index("://") + 3 :]
        if "#" in url_part:
            url_part, _ = url_part.split("#", 1)
        if "?" in url_part:
            url_part, _ = url_part.split("?", 1)

        if ":" in url_part:
            parts = url_part.split(":")
            if len(parts) >= 2:
                port_str = parts[-1].strip()
                hostname = ":".join(parts[:-1]).split("@")[-1]
                try:
                    port = int(port_str)
                    return "chacha20-poly1305", "", hostname, port
                except ValueError:
                    pass
    except (ValueError, IndexError):
        pass
    return None


def parse_shadowsocks_to_outbound(url: str, tag: str = "proxy") -> dict | None:
    """Parse Shadowsocks URL to Xray outbound.

    Filters weak ciphers (RC4, DES, CFB modes, Salsa20, Chacha20 non-IETF).
    Only AEAD ciphers are considered secure.
    """
    try:
        # Remove protocol prefix (case-insensitive)
        url_part = url[url.index("://") + 3 :]

        # Split at # to separate fragment
        if "#" in url_part:
            url_part, _ = url_part.split("#", 1)

        # Split at ? to separate query params FIRST
        if "?" in url_part:
            url_part, query_part = url_part.split("?", 1)
        else:
            query_part = ""

        # Handle both formats: base64 and plain
        method = "chacha20-poly1305"
        password = ""
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
        plugin = params.get("plugin", [None])[0] if params.get("plugin") else None
        if plugin:
            return None

        # Add network transport settings if specified
        network = params.get("type", ["tcp"])[0] if params.get("type") else "tcp"
        stream_settings: dict[str, Any] = {"network": network, "security": "none"}

        if network == "ws":
            stream_settings["wsSettings"] = {
                "path": unquote(params.get("path", ["/"])[0]),
                "headers": {"Host": unquote(params.get("host", [hostname])[0])},
            }

        return {
            "tag": tag,
            "protocol": "shadowsocks",
            "settings": {
                "servers": [
                    {
                        "address": str(hostname),
                        "port": int(port),
                        "password": str(password),
                        "method": str(method),
                    }
                ]
            },
            "streamSettings": stream_settings,
        }
    except (
        ValueError,
        IndexError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
        binascii.Error,
    ):
        return None


def parse_hysteria2_to_outbound(url: str, tag: str = "proxy") -> dict | None:
    """Parse a Hysteria2/Hy2 URL into the outbound Xray documents.

    xray has no "hysteria2" outbound: the protocol is "hysteria" and
    infra/conf/hysteria.go rejects `settings.version != 2`. The password belongs
    to `hysteriaSettings.auth`, QUIC camouflage is a `finalmask.udp` stage rather
    than a transport, and `insecure=1` is left unmapped because xray removed
    `allowInsecure` — a node that needs verification off has no xray shape, so
    the compatibility filter refuses it by name instead of letting it fail like a
    dead server. Query keys are matched case-insensitively: the hysteria2 URI
    spec writes `pinSHA256`, collectors lowercase it.
    """
    try:
        parsed = urlparse(url)
        params = {k.lower(): v for k, v in parse_qs(parsed.query).items()}

        if not parsed.hostname or not parsed.port:
            return None

        def param(name: str, default: str = "") -> str:
            return params.get(name, [default])[0]

        auth = unquote(parsed.username) if parsed.username else param("auth")
        sni = param("sni").strip() or parsed.hostname

        tls_settings = _make_tls_settings(sni, param("fp") or None)
        pinned = param("pinsha256").strip()
        if pinned:
            tls_settings["pinnedPeerCertSha256"] = pinned

        hysteria_settings: dict[str, Any] = {"version": 2}
        if auth:
            hysteria_settings["auth"] = auth

        stream_settings: dict[str, Any] = {
            "network": "hysteria",
            # xray errors "tls config is nil" without it: hysteria rides on TLS.
            "security": "tls",
            "hysteriaSettings": hysteria_settings,
            "tlsSettings": tls_settings,
        }
        if param("obfs").strip().lower() == "salamander" and param("obfs-password"):
            stream_settings["finalmask"] = {
                "udp": [
                    {
                        "type": "salamander",
                        "settings": {"password": unquote(param("obfs-password"))},
                    }
                ]
            }

        return {
            "tag": tag,
            "protocol": "hysteria",
            "settings": {"version": 2, "address": parsed.hostname, "port": parsed.port},
            "streamSettings": stream_settings,
        }
    except (
        ValueError,
        IndexError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
        binascii.Error,
    ):
        return None


def parse_ssr_to_outbound(url: str, tag: str = "proxy") -> dict | None:
    """Parse ShadowsocksR (SSR) URL to Xray outbound.

    Note: Xray-core has limited SSR support. This converts to basic Shadowsocks
    without SSR-specific features (protocol, obfs). For full SSR support, use v2fly-core.
    """
    try:
        url_part = _clean_url_part(url)

        # Add padding if needed
        padding = 4 - len(url_part) % 4
        if padding != 4:
            url_part += "=" * padding

        # Decode base64
        try:
            decoded = base64.urlsafe_b64decode(url_part).decode("utf-8", errors="ignore")
        except (
            ValueError,
            IndexError,
            KeyError,
            TypeError,
            json.JSONDecodeError,
            binascii.Error,
        ):
            return None

        # SSR format: host:port:protocol:method:obfs:base64pass/?obfsparam=base64&protoparam=base64&remarks=base64
        if "/?" in decoded:
            main_part, query_part = decoded.split("/?", 1)
        else:
            main_part = decoded
            query_part = ""

        parts = main_part.split(":")
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
                password_base64 = parts[5] + "=" * password_padding
            password = (
                base64.urlsafe_b64decode(password_base64).decode("utf-8", errors="ignore").strip()
            )
            if not password:
                return None
        except (
            ValueError,
            IndexError,
            KeyError,
            TypeError,
            json.JSONDecodeError,
            binascii.Error,
        ):
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
                "servers": [
                    {"address": hostname, "port": port, "password": password, "method": method}
                ]
            },
            "streamSettings": {"network": "tcp", "security": "none"},
        }
    except (
        ValueError,
        IndexError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
        binascii.Error,
    ):
        return None


def parse_url_to_outbound(url: str, tag: str = "proxy") -> dict | None:
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
    - Hysteria2: Full support (see this module's header for the shape)
    - Hysteria v1 and TUIC: not supported by Xray-core, so no parser is registered
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
        "vless://": parse_vless_to_outbound,  # Full support
        "vmess://": parse_vmess_to_outbound,  # Full support
        "trojan://": parse_trojan_to_outbound,  # Full support
        "ss://": parse_shadowsocks_to_outbound,  # Full support (AEAD only)
        "ssr://": parse_ssr_to_outbound,  # Limited (converted to SS)
        "hysteria2://": parse_hysteria2_to_outbound,  # Full support (v2)
        "hy2://": parse_hysteria2_to_outbound,  # Alias for hysteria2
    }

    for prefix, parser in dispatch.items():
        if url_lower.startswith(prefix):
            return parser(url, tag)

    return None

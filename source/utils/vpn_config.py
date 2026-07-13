"""Typed VPN config representations.

Defines a dataclass hierarchy for parsed VPN configs, replacing the
untyped `str → Optional[Dict]` pattern used by the xray_tester parsers.

Each protocol has its own dataclass. A `parse_url()` factory dispatches
to the right parser by URL scheme. Integrated into xray_tester._url_to_outbound()
as the primary path, falling back to legacy inline parsers for edge cases.

Usage:
    cfg = parse_url("vless://uuid@host:443?security=tls")
    if cfg:
        outbound = cfg.to_xray_outbound(tag="proxy")
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlparse, parse_qs
import json
import base64
from utils.security_filter import SS_WEAK_CIPHERS


# ── Base class ──────────────────────────────────────────────────────────

@dataclass(slots=True)
class VPNConfig:
    """Common fields for all VPN protocols.

    Subclasses add protocol-specific fields. The to_xray_outbound() method
    produces the Xray-core outbound dict (same shape the current str→Dict
    parsers return).
    """
    host: str
    port: int
    remark: str = ""
    # Common transport fields (shared by most protocols, used by _add_stream_settings)
    transport: str = "tcp"  # tcp, ws, grpc, httpupgrade
    tls: bool = False
    sni: str = ""
    ws_path: str = ""
    ws_host: str = ""
    grpc_service_name: str = ""

    def to_xray_outbound(self, tag: str = "proxy") -> Optional[Dict[str, Any]]:
        """Convert to Xray outbound dict. Override in subclasses."""
        raise NotImplementedError

    def dedup_key(self) -> Tuple[Any, ...]:
        """Return a hashable key for deduplication (host+port+protocol).
        Override in subclasses to add protocol-specific fields."""
        return (self.__class__.__name__, self.host, self.port)


# ── Protocol-specific configs ───────────────────────────────────────────

@dataclass(slots=True)
class VLESSConfig(VPNConfig):
    uuid: str = ""
    flow: str = ""
    encryption: str = "none"
    # Reality
    reality: bool = False
    public_key: str = ""
    short_id: str = ""
    # WS
    ws_path: str = ""
    ws_host: str = ""
    # gRPC
    grpc_service_name: str = ""

    def to_xray_outbound(self, tag: str = "proxy") -> Optional[Dict[str, Any]]:
        outbound = _make_base_outbound(tag, "vless")
        outbound["settings"] = {
            "vnext": [{
                "address": self.host,
                "port": self.port,
                "users": [{"id": self.uuid, "flow": self.flow or None,
                           "encryption": self.encryption}]
            }]
        }
        security = "reality" if self.reality else ("tls" if self.tls else None)
        _add_stream_settings(outbound, self, security_override=security)
        if self.reality and self.public_key:
            outbound["streamSettings"]["fingerprint"] = "chrome"
            outbound["streamSettings"]["realitySettings"] = {
                "serverName": self.sni or self.host,
                "fingerprint": "chrome",
                "publicKey": self.public_key,
                "shortId": self.short_id or "",
            }
        elif self.reality and not self.public_key:
            return None  # Reality requires publicKey
        return outbound

    def dedup_key(self) -> Tuple[Any, ...]:
        return (self.__class__.__name__, self.host, self.port, self.uuid)


@dataclass(slots=True)
class VMessConfig(VPNConfig):
    uuid: str = ""
    alter_id: int = 0
    security: str = "auto"
    # WS
    ws_path: str = ""
    ws_host: str = ""
    # gRPC
    grpc_service_name: str = ""
    # HTTP/2
    h2_hosts: tuple = ()

    def to_xray_outbound(self, tag: str = "proxy") -> Dict[str, Any]:
        outbound = _make_base_outbound(tag, "vmess")
        outbound["settings"] = {
            "vnext": [{
                "address": self.host,
                "port": self.port,
                "users": [{"id": self.uuid, "alterId": self.alter_id,
                           "security": self.security}]
            }]
        }
        _add_stream_settings(outbound, self)
        return outbound

    def dedup_key(self) -> Tuple[Any, ...]:
        return (self.__class__.__name__, self.host, self.port, self.uuid)


@dataclass(slots=True)
class TrojanConfig(VPNConfig):
    password: str = ""
    flow: str = ""
    # WS
    ws_path: str = ""
    ws_host: str = ""
    # Reality
    reality: bool = False
    public_key: str = ""
    short_id: str = ""

    def to_xray_outbound(self, tag: str = "proxy") -> Optional[Dict[str, Any]]:
        outbound = _make_base_outbound(tag, "trojan")
        outbound["settings"] = {
            "servers": [{
                "address": self.host,
                "port": self.port,
                "password": self.password,
                "flow": self.flow or None,
            }]
        }
        security = "reality" if self.reality else ("tls" if self.tls else None)
        _add_stream_settings(outbound, self, security_override=security)
        if self.reality and self.public_key:
            outbound["streamSettings"]["fingerprint"] = "chrome"
            outbound["streamSettings"]["realitySettings"] = {
                "serverName": self.sni or self.host,
                "fingerprint": "chrome",
                "publicKey": self.public_key,
                "shortId": self.short_id or "",
            }
        elif self.reality and not self.public_key:
            return None
        return outbound

    def dedup_key(self) -> Tuple[Any, ...]:
        return (self.__class__.__name__, self.host, self.port, self.password)


@dataclass(slots=True)
class ShadowsocksConfig(VPNConfig):
    method: str = "chacha20-ietf-poly1305"
    password: str = ""

    def to_xray_outbound(self, tag: str = "proxy") -> Dict[str, Any]:
        outbound = _make_base_outbound(tag, "shadowsocks")
        outbound["settings"] = {
            "servers": [{
                "address": self.host,
                "port": self.port,
                "method": self.method,
                "password": self.password,
            }]
        }
        return outbound

    def dedup_key(self) -> Tuple[Any, ...]:
        return (self.__class__.__name__, self.host, self.port, self.method)


@dataclass(slots=True)
class Hysteria2Config(VPNConfig):
    auth: str = ""
    obfs: str = ""

    def to_xray_outbound(self, tag: str = "proxy") -> Dict[str, Any]:
        outbound = _make_base_outbound(tag, "hysteria2", is_quic=True)
        outbound["settings"] = {
            "host": self.host,
            "port": self.port,
            "serverName": self.sni or self.host,
        }
        if self.auth:
            outbound["settings"]["auth"] = self.auth
        _add_stream_settings(outbound, self)
        return outbound

    def dedup_key(self) -> Tuple[Any, ...]:
        return (self.__class__.__name__, self.host, self.port)


# ── Factory ─────────────────────────────────────────────────────────────

def parse_url(url: str) -> Optional[VPNConfig]:
    """Parse a VPN URL string into the appropriate typed config.

    Dispatches by URL scheme. Returns None if the URL doesn't match any
    known protocol or is malformed.

    This is the entry point that replaces the ad-hoc str→Dict parsers.
    """
    if not url or "://" not in url:
        return None

    scheme = url.split("://")[0].lower()

    if scheme == "vless":
        return _parse_vless(url)
    elif scheme == "vmess":
        return _parse_vmess(url)
    elif scheme == "trojan":
        return _parse_trojan(url)
    elif scheme == "ss":
        return _parse_shadowsocks(url)
    elif scheme in ("hysteria2", "hy2"):
        return _parse_hysteria2(url)
    else:
        return None


# ── Protocol parsers ─────────────────────────────────────────────────────

def _parse_vless(url: str) -> Optional[VLESSConfig]:
    parsed = urlparse(url)
    if not parsed.hostname or not parsed.port:
        return None
    # VLESS requires uuid@host:port format — reject if no @
    if "@" not in parsed.netloc:
        return None
    params = parse_qs(parsed.query)
    uuid = parsed.netloc.split("@")[0]

    return VLESSConfig(
        host=parsed.hostname,
        port=parsed.port,
        remark=parsed.fragment or "",
        uuid=uuid,
        flow=params.get("flow", [""])[0],
        encryption=params.get("encryption", ["none"])[0],
        tls=params.get("security", [""])[0] in ("tls", "reality"),
        sni=params.get("sni", [""])[0],
        reality=params.get("security", [""])[0] == "reality",
        public_key=params.get("pbk", [""])[0],
        short_id=params.get("sid", [""])[0],
        transport=params.get("type", ["tcp"])[0],
        ws_path=params.get("path", [""])[0],
        ws_host=params.get("host", [""])[0],
        grpc_service_name=params.get("serviceName", [""])[0],
    )


def _parse_vmess(url: str) -> Optional[VMessConfig]:
    """Parse vmess:// from base64-encoded JSON."""
    payload = url[8:]  # strip 'vmess://'
    rem = len(payload) % 4
    if rem:
        payload += "=" * (4 - rem)
    try:
        decoded = base64.b64decode(payload).decode("utf-8", errors="ignore")
    except (ValueError, TypeError):
        return None
    if not decoded.startswith("{"):
        return None
    try:
        j = json.loads(decoded)
    except (json.JSONDecodeError, ValueError):
        return None

    return VMessConfig(
        host=j.get("add", ""),
        port=int(j.get("port", 0)),
        remark=j.get("ps", ""),
        uuid=j.get("id", ""),
        alter_id=int(j.get("aid", 0)),
        security=j.get("scy", "auto"),
        tls=bool(j.get("tls")),
        sni=j.get("sni", ""),
        transport=j.get("net", "tcp"),
        ws_path=j.get("path", ""),
        ws_host=j.get("host", ""),
        grpc_service_name=j.get("serviceName", ""),
    )


def _parse_trojan(url: str) -> Optional[TrojanConfig]:
    parsed = urlparse(url)
    if not parsed.hostname or not parsed.port:
        return None
    params = parse_qs(parsed.query)
    password = (parsed.username or parsed.password or "").split("@")[0] if parsed.username else ""
    if "@" in parsed.netloc:
        password = parsed.netloc.split("@")[0]

    return TrojanConfig(
        host=parsed.hostname,
        port=parsed.port,
        remark=parsed.fragment or "",
        password=password,
        tls=params.get("security", [""])[0] in ("tls", "reality"),
        sni=params.get("sni", [""])[0],
        flow=params.get("flow", [""])[0],
        reality=params.get("security", [""])[0] == "reality",
        public_key=params.get("pbk", [""])[0],
        transport=params.get("type", ["tcp"])[0],
        ws_path=params.get("path", [""])[0],
        ws_host=params.get("host", [""])[0],
    )


def _parse_shadowsocks(url: str) -> Optional[ShadowsocksConfig]:
    parsed = urlparse(url)
    if not parsed.hostname or not parsed.port:
        return None
    method, password = "chacha20-ietf-poly1305", ""
    # Reconstruct the userinfo: urlparse splits method:password into username/password
    user_part = parsed.username or ""
    if parsed.password:
        user_part = f"{user_part}:{parsed.password}"
    if ":" in user_part:
        method, password = user_part.split(":", 1)
    else:
        # Legacy base64 format: username is base64(method:password)
        try:
            rem = len(user_part) % 4
            padded = user_part + "=" * (4 - rem)
            decoded = base64.b64decode(padded).decode("utf-8")
            if ":" in decoded:
                method, password = decoded.split(":", 1)
        except (ValueError, IndexError, UnicodeDecodeError):
            pass

    # SECURITY: reject weak ciphers and empty passwords
    if method.lower() in SS_WEAK_CIPHERS:
        return None
    if not password:
        return None

    return ShadowsocksConfig(
        host=parsed.hostname,
        port=parsed.port,
        remark=parsed.fragment or "",
        method=method,
        password=password,
    )


def _parse_hysteria2(url: str) -> Optional[Hysteria2Config]:
    parsed = urlparse(url)
    if not parsed.hostname or not parsed.port:
        return None
    params = parse_qs(parsed.query)
    return Hysteria2Config(
        host=parsed.hostname,
        port=parsed.port,
        remark=parsed.fragment or "",
        auth=params.get("auth", [""])[0],
        sni=params.get("sni", [""])[0],
        obfs=params.get("obfs", [""])[0],
    )


# ── Shared helpers ──────────────────────────────────────────────────────

def _make_base_outbound(tag: str, protocol: str,
                        is_quic: bool = False) -> Dict[str, Any]:
    """Build the base Xray outbound dict shared by all protocols."""
    outbound: Dict[str, Any] = {
        "tag": tag,
        "protocol": protocol,
        "settings": {},
    }
    if is_quic:
        outbound["streamSettings"] = {
            "quicSettings": {},
        }
    return outbound


def _add_stream_settings(outbound: Dict[str, Any], cfg: VPNConfig,
                         security_override: Optional[str] = None) -> None:
    """Add transport-level streamSettings to an outbound dict.

    Args:
        outbound: Xray outbound dict to modify in-place
        cfg: VPNConfig instance with transport/tls fields
        security_override: If set, forces the security value (e.g. "reality").
                          Normally derived from cfg.tls.
    """
    ss: Dict[str, Any] = {}
    if security_override:
        ss["security"] = security_override
    elif cfg.tls:
        ss["security"] = "tls"
    else:
        ss["security"] = "none"

    if ss.get("security") == "tls" or (cfg.tls and not security_override):
        from config.settings import TLS_FINGERPRINT
        tls_settings: Dict[str, Any] = {
            "serverName": cfg.sni or cfg.host,
            "fingerprint": TLS_FINGERPRINT,
        }
        ss["tlsSettings"] = tls_settings

    if cfg.transport == "ws":
        ws: Dict[str, Any] = {"path": cfg.ws_path or "/"}
        if cfg.ws_host:
            ws["headers"] = {"Host": cfg.ws_host}
        ss["network"] = "ws"
        ss["wsSettings"] = ws
    elif cfg.transport == "grpc":
        ss["network"] = "grpc"
        ss["grpcSettings"] = {"serviceName": cfg.grpc_service_name or ""}
    elif cfg.transport == "httpupgrade":
        ss["network"] = "httpupgrade"
    elif cfg.transport == "tcp":
        ss["network"] = "tcp"

    outbound["streamSettings"] = ss

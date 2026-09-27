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

import base64
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urlparse

from utils.security_filter import is_xray_cipher
from utils.url_payload import base64_payload, query_parameters
from utils.xray_helpers import xray_fingerprint
from utils.xray_stream_settings import (
    _WS_NAMES,
    _XHTTP_NAMES,
    _make_grpc_settings,
    _make_httpupgrade_settings,
    _make_ws_settings,
    _make_xhttp_settings,
    vmess_security,
)

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
    transport: str = "tcp"  # tcp, ws, grpc, httpupgrade, xhttp, splithttp
    tls: bool = False
    sni: str = ""
    fingerprint: str = ""  # the URL's `fp=`, resolved by xray_fingerprint()
    mode: str = ""  # xhttp's `mode=`; xray defaults to "auto" when it is absent
    ws_path: str = ""
    ws_host: str = ""
    grpc_service_name: str = ""

    def to_xray_outbound(self, tag: str = "proxy") -> dict[str, Any] | None:
        """Convert to Xray outbound dict. Override in subclasses."""
        raise NotImplementedError

    def dedup_key(self) -> tuple[Any, ...]:
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

    def to_xray_outbound(self, tag: str = "proxy") -> dict[str, Any] | None:
        outbound = _make_base_outbound(tag, "vless")
        outbound["settings"] = {
            "vnext": [
                {
                    "address": self.host,
                    "port": self.port,
                    "users": [
                        {"id": self.uuid, "flow": self.flow or None, "encryption": self.encryption}
                    ],
                }
            ]
        }
        security = "reality" if self.reality else ("tls" if self.tls else None)
        _add_stream_settings(outbound, self, security_override=security)
        if self.reality and not _add_reality_settings(outbound, self):
            return None  # Reality requires a publicKey
        return outbound

    def dedup_key(self) -> tuple[Any, ...]:
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

    def to_xray_outbound(self, tag: str = "proxy") -> dict[str, Any]:
        outbound = _make_base_outbound(tag, "vmess")
        outbound["settings"] = {
            "vnext": [
                {
                    "address": self.host,
                    "port": self.port,
                    "users": [
                        {"id": self.uuid, "alterId": self.alter_id, "security": self.security}
                    ],
                }
            ]
        }
        _add_stream_settings(outbound, self)
        return outbound

    def dedup_key(self) -> tuple[Any, ...]:
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

    def to_xray_outbound(self, tag: str = "proxy") -> dict[str, Any] | None:
        outbound = _make_base_outbound(tag, "trojan")
        outbound["settings"] = {
            "servers": [
                {
                    "address": self.host,
                    "port": self.port,
                    "password": self.password,
                }
            ]
        }
        security = "reality" if self.reality else ("tls" if self.tls else None)
        _add_stream_settings(outbound, self, security_override=security)
        if self.reality and not _add_reality_settings(outbound, self):
            return None  # Reality requires a publicKey
        return outbound

    def dedup_key(self) -> tuple[Any, ...]:
        return (self.__class__.__name__, self.host, self.port, self.password)


@dataclass(slots=True)
class ShadowsocksConfig(VPNConfig):
    method: str = "chacha20-ietf-poly1305"
    password: str = ""

    def to_xray_outbound(self, tag: str = "proxy") -> dict[str, Any]:
        outbound = _make_base_outbound(tag, "shadowsocks")
        outbound["settings"] = {
            "servers": [
                {
                    "address": self.host,
                    "port": self.port,
                    "method": self.method,
                    "password": self.password,
                }
            ]
        }
        return outbound

    def dedup_key(self) -> tuple[Any, ...]:
        return (self.__class__.__name__, self.host, self.port, self.method)


@dataclass(slots=True)
class Hysteria2Config(VPNConfig):
    auth: str = ""
    obfs: str = ""
    obfs_password: str = ""
    pin_sha256: str = ""

    def to_xray_outbound(self, tag: str = "proxy") -> dict[str, Any]:
        """Build the Hysteria2 outbound, in the shape xray documents.

        Kept identical to `protocol_parsers.parse_hysteria2_to_outbound()`: this
        is the path `_url_to_outbound()` tries first, so the two producers
        disagreeing would mean the same URL is tested two different ways.
        """
        hysteria_settings: dict[str, Any] = {"version": 2}
        if self.auth:
            hysteria_settings["auth"] = self.auth

        from config.settings import TLS_FINGERPRINT

        tls_settings: dict[str, Any] = {
            "serverName": self.sni or self.host,
            "fingerprint": TLS_FINGERPRINT,
        }
        if self.pin_sha256:
            tls_settings["pinnedPeerCertSha256"] = self.pin_sha256

        stream: dict[str, Any] = {
            "network": "hysteria",
            # xray errors "tls config is nil" without it: hysteria rides on TLS.
            "security": "tls",
            "hysteriaSettings": hysteria_settings,
            "tlsSettings": tls_settings,
        }
        if self.obfs == "salamander" and self.obfs_password:
            stream["finalmask"] = {
                "udp": [
                    {"type": "salamander", "settings": {"password": self.obfs_password}},
                ]
            }

        return {
            "tag": tag,
            "protocol": "hysteria",
            "settings": {"version": 2, "address": self.host, "port": self.port},
            "streamSettings": stream,
        }

    def dedup_key(self) -> tuple[Any, ...]:
        return (self.__class__.__name__, self.host, self.port)


# ── Factory ─────────────────────────────────────────────────────────────


def parse_url(url: str) -> VPNConfig | None:
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
    if scheme == "vmess":
        return _parse_vmess(url)
    if scheme == "trojan":
        return _parse_trojan(url)
    if scheme == "ss":
        return _parse_shadowsocks(url)
    if scheme in ("hysteria2", "hy2"):
        return _parse_hysteria2(url)
    return None


# ── Protocol parsers ─────────────────────────────────────────────────────


def _parse_vless(url: str) -> VLESSConfig | None:
    parsed = urlparse(url)
    if not parsed.hostname or not parsed.port:
        return None
    # VLESS requires uuid@host:port format — reject if no @
    if "@" not in parsed.netloc:
        return None
    params = query_parameters(parsed.query)
    uuid = parsed.netloc.split("@")[0]

    # xray folds the spelling of both fields before matching it
    # (`StreamConfig.Build`: `switch strings.ToLower(c.Security)`,
    # `TransportProtocol.Build`: `switch strings.ToLower(string(p))`), so the
    # comparison here has to fold too -- `security=TLS` was otherwise read as no
    # encryption at all and the node was dialled in plaintext.
    security = params.get("security", [""])[0].lower()
    return VLESSConfig(
        host=parsed.hostname,
        port=parsed.port,
        remark=parsed.fragment or "",
        uuid=uuid,
        flow=params.get("flow", [""])[0],
        encryption=params.get("encryption", ["none"])[0],
        tls=security in ("tls", "reality"),
        sni=params.get("sni", [""])[0],
        reality=security == "reality",
        public_key=params.get("pbk", [""])[0],
        short_id=params.get("sid", [""])[0],
        fingerprint=params.get("fp", [""])[0],
        mode=params.get("mode", [""])[0],
        transport=params.get("type", ["tcp"])[0].lower(),
        ws_path=params.get("path", [""])[0],
        ws_host=params.get("host", [""])[0],
        grpc_service_name=params.get("servicename", [""])[0],
    )


def _parse_vmess(url: str) -> VMessConfig | None:
    """Parse vmess:// from base64-encoded JSON."""
    payload = base64_payload(url)
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

    # The `tls` field is a string, a boolean or absent depending on which client
    # wrote the JSON; xray matches `security` against a string, so this has to be
    # resolved before it reaches the outbound. Anything other than "none"/"tls"
    # (reality above all) is left to the URL parsers, because the reality key
    # names in this object are not agreed on between the clients that write it.
    net_security = vmess_security(j.get("tls"))
    if net_security not in ("none", "tls"):
        return None

    return VMessConfig(
        host=j.get("add", ""),
        port=int(j.get("port", 0)),
        remark=j.get("ps", ""),
        uuid=j.get("id", ""),
        alter_id=int(j.get("aid", 0)),
        security=j.get("scy", "auto"),
        tls=net_security == "tls",
        sni=j.get("sni", ""),
        fingerprint=j.get("fp", ""),
        mode=str(j.get("mode", "")),
        transport=j.get("net", "tcp"),
        ws_path=j.get("path", ""),
        ws_host=j.get("host", ""),
        grpc_service_name=j.get("serviceName", ""),
    )


def _parse_trojan(url: str) -> TrojanConfig | None:
    parsed = urlparse(url)
    if not parsed.hostname or not parsed.port:
        return None
    params = query_parameters(parsed.query)
    password = (parsed.username or parsed.password or "").split("@")[0] if parsed.username else ""
    if "@" in parsed.netloc:
        password = parsed.netloc.split("@")[0]

    security = params.get("security", [""])[0].lower()  # folded, as upstream folds it
    return TrojanConfig(
        host=parsed.hostname,
        port=parsed.port,
        remark=parsed.fragment or "",
        password=password,
        tls=security in ("tls", "reality"),
        sni=params.get("sni", [""])[0],
        flow=params.get("flow", [""])[0],
        reality=security == "reality",
        public_key=params.get("pbk", [""])[0],
        # shortId is how a reality server routes the handshake: dropping it makes
        # the node reject us, so the test reported a working node as dead.
        short_id=params.get("sid", [""])[0],
        fingerprint=params.get("fp", [""])[0],
        mode=params.get("mode", [""])[0],
        transport=params.get("type", ["tcp"])[0].lower(),
        ws_path=params.get("path", [""])[0],
        ws_host=params.get("host", [""])[0],
    )


def _parse_shadowsocks(url: str) -> ShadowsocksConfig | None:
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

    # SECURITY: reject ciphers xray's loader does not know, and empty passwords.
    # The method is normalized first: xray matches the 2022 names case-sensitively
    # against `shadowaead_2022.List`, so `to_xray_outbound()` has to emit the
    # spelling the loader actually has.
    method = method.strip().lower()
    if not is_xray_cipher(method):
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


def _parse_hysteria2(url: str) -> Hysteria2Config | None:
    """Parse `hysteria2://` / `hy2://`, in the shape the URI scheme defines.

    The auth token belongs in the userinfo (`hysteria2://<token>@host:port`);
    `auth=` in the query is what Clash-style converters emit, so both are read.
    Keys are matched case-insensitively: the spec writes `pinSHA256`, and
    collectors lowercase it.
    """
    parsed = urlparse(url)
    if not parsed.hostname or not parsed.port:
        return None
    params = query_parameters(parsed.query)

    def param(name: str, default: str = "") -> str:
        return params.get(name, [default])[0]

    return Hysteria2Config(
        host=parsed.hostname,
        port=parsed.port,
        remark=parsed.fragment or "",
        auth=unquote(parsed.username) if parsed.username else param("auth"),
        sni=param("sni"),
        obfs=param("obfs").strip().lower(),
        obfs_password=unquote(param("obfs-password")),
        pin_sha256=param("pinsha256").strip(),
    )


# ── Shared helpers ──────────────────────────────────────────────────────


def _make_base_outbound(tag: str, protocol: str) -> dict[str, Any]:
    """Build the base Xray outbound dict shared by all protocols."""
    return {
        "tag": tag,
        "protocol": protocol,
        "settings": {},
    }


def _add_stream_settings(
    outbound: dict[str, Any], cfg: VPNConfig, security_override: str | None = None
) -> None:
    """Add transport-level streamSettings to an outbound dict.

    Args:
        outbound: Xray outbound dict to modify in-place
        cfg: VPNConfig instance with transport/tls fields
        security_override: If set, forces the security value (e.g. "reality").
                          Normally derived from cfg.tls.
    """
    ss: dict[str, Any] = {}
    if security_override:
        ss["security"] = security_override
    elif cfg.tls:
        ss["security"] = "tls"
    else:
        ss["security"] = "none"

    if ss.get("security") == "tls" or (cfg.tls and not security_override):
        tls_settings: dict[str, Any] = {
            "serverName": cfg.sni or cfg.host,
            "fingerprint": xray_fingerprint(cfg.fingerprint),
        }
        ss["tlsSettings"] = tls_settings

    if cfg.transport in _WS_NAMES:
        ss["network"] = cfg.transport
        ss["wsSettings"] = _make_ws_settings(cfg.ws_path or "/", cfg.ws_host or cfg.host)
    elif cfg.transport == "grpc":
        ss["network"] = "grpc"
        ss["grpcSettings"] = _make_grpc_settings(cfg.grpc_service_name)
    elif cfg.transport == "httpupgrade":
        ss["network"] = "httpupgrade"
        ss["httpupgradeSettings"] = _make_httpupgrade_settings(
            cfg.ws_path or "/", cfg.ws_host or cfg.host
        )
    elif cfg.transport in _XHTTP_NAMES:
        ss["network"] = cfg.transport
        ss["xhttpSettings"] = _make_xhttp_settings(
            cfg.ws_path or "/", cfg.ws_host or cfg.host, cfg.mode
        )
    elif cfg.transport == "tcp":
        ss["network"] = "tcp"

    outbound["streamSettings"] = ss


def _add_reality_settings(outbound: dict[str, Any], cfg: Any) -> bool:
    """Attach realitySettings to a VLESS or Trojan outbound; False when unusable.

    The fingerprint belongs *inside* realitySettings: `streamSettings.fingerprint`
    is not a key xray's `StreamConfig` has, so writing it there did nothing, while
    a blank or unresolvable value *here* makes the client builder abort the load
    with `unknown "fingerprint"`. xray's Reality client also rejects `unsafe`.
    """
    if not cfg.public_key:
        return False
    outbound["streamSettings"]["realitySettings"] = {
        "serverName": cfg.sni or cfg.host,
        "fingerprint": xray_fingerprint(cfg.fingerprint),
        "publicKey": cfg.public_key,
        "shortId": cfg.short_id or "",
    }
    return True

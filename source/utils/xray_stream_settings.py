"""streamSettings section builders, in the keys xray reads.

Split out of `utils/protocol_parsers.py`, which had crossed the repository's
module-size ceiling. These are the functions both the parsers and the verifier
call to assemble `streamSettings`, and they are the half of that file that is
about xray's config schema rather than about URL syntax -- which matters,
because `utils/vpn_config.py` builds the same blocks on the typed path and the
two have to agree key for key.

Every key below is one of `StreamConfig`'s (checked against
`infra/conf/transport_internet.go` at v26.3.27): `network`, `security`,
`tlsSettings`, `realitySettings`, `wsSettings{path,host}`, `grpcSettings`,
`httpupgradeSettings{path,host}`, `xhttpSettings{path,host,mode}` and
`finalmask`. A key xray does not have is dropped in silence rather than
rejected, so inventing one looks exactly like a dead node.
"""

from typing import Any
from urllib.parse import unquote

from utils.xray_helpers import xray_fingerprint

# The transport name pairs `TransportProtocol.Build()` resolves to the same
# protocol: "ws"/"websocket" and "xhttp"/"splithttp" are aliases upstream, so both
# spellings have to reach the same settings block. Emitting the URL's own spelling
# is fine -- xray normalizes it -- but dispatching on it is what decides whether the
# path and host get sent at all.
_WS_NAMES = frozenset({"ws", "websocket"})
_XHTTP_NAMES = frozenset({"xhttp", "splithttp"})

# The modes `SplitHTTPConfig.Build()` accepts besides the empty default.
_XHTTP_MODES = frozenset({"auto", "stream-up", "stream-one", "packet-up"})

# The vmess JSON writes its transport security four ways in the wild: the strings
# "tls"/"none", a bare JSON boolean, and — since Xray added it — "reality".
# `StreamConfig` matches `security` against a *string*, so a `true` reaching the
# JSON comes back as `Unknown security "true"` and the config never loads.
_TLS_ON = frozenset({"tls", "1", "true", "yes", "on"})
_TLS_OFF = frozenset({"", "none", "off", "0", "false", "no"})


def vmess_security(raw: object) -> str:
    """The `security` spelling xray reads, from a vmess object's `tls` field."""
    value = str(raw if raw is not None else "").strip().lower()
    if value in _TLS_OFF:
        return "none"
    if value in _TLS_ON:
        return "tls"
    return value


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
    return {"serverName": sni, "fingerprint": xray_fingerprint(fp)}


def _make_reality_settings(sni: str, pbk: str, fp: str | None = None, sid: str = "") -> dict | None:
    """Build realitySettings dict. Returns None if sni or pbk is missing."""
    sni = sni.strip()
    pbk = pbk.strip()
    if not sni or not pbk:
        return None
    return {
        "serverName": sni,
        "fingerprint": xray_fingerprint(fp),
        "publicKey": pbk,
        "shortId": sid,
    }


def _make_ws_settings(path: str, host: str) -> dict:
    """Build wsSettings dict.

    `host` is the field xray's WebSocketConfig reads; a `host` inside `headers` is
    still honored but only as a fallback and it prints a deprecation warning, so
    the deprecated shape is not emitted.
    """
    return {"path": unquote(path), "host": unquote(host)}


def _make_grpc_settings(service_name: str) -> dict:
    """Build grpcSettings dict."""
    return {"serviceName": unquote(service_name)}


def _make_httpupgrade_settings(path: str, host: str) -> dict:
    """Build httpupgradeSettings dict — `host`, not a `headers` map."""
    return {"path": unquote(path), "host": unquote(host)}


def _make_xhttp_settings(path: str, host: str, mode: str) -> dict:
    """Build xhttpSettings dict. `network: splithttp` and `xhttp` share it.

    Only the modes `SplitHTTPConfig.Build()` accepts are emitted; an unknown one is
    `unsupported mode` there, and omitting the field makes xray default to `auto`.
    """
    settings: dict[str, Any] = {"path": unquote(path), "host": unquote(host)}
    if mode in _XHTTP_MODES:
        settings["mode"] = mode
    return settings


def _make_stream_settings(
    network: str, security: str, params: dict, default_host: str
) -> dict | None:
    """Build streamSettings dict for the transports xray names.

    Returns None if Reality params are invalid.

    `network` and `security` are folded because that is what upstream folds: the
    transport switch is `switch strings.ToLower(string(p))`
    (`transport_internet.go:999`, v26.3.27) and the security switch is
    `switch strings.ToLower(c.Security)` (`:1763`). Comparing the URL's spelling
    instead meant `?security=TLS` fell through to `none` -- the node then tested over
    plaintext while the security filter, which had folded the same string, filed it as
    encrypted. The emitted JSON carries the canonical lowercase name xray expects.

    `mode` is deliberately not folded: `SplitHTTPConfig.Build()` switches on the value
    as written (`:280`), so `Auto` is `unsupported mode` upstream and there is no
    case-insensitive spelling to normalize to.
    """
    network = str(network).lower()
    security = str(security).lower()
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

    if network in _WS_NAMES:
        stream["wsSettings"] = _make_ws_settings(
            params.get("path", ["/"])[0],
            params.get("host", [default_host])[0],
        )
    elif network in _XHTTP_NAMES:
        stream["xhttpSettings"] = _make_xhttp_settings(
            params.get("path", ["/"])[0],
            params.get("host", [default_host])[0],
            params.get("mode", [""])[0],
        )
    elif network == "grpc":
        stream["grpcSettings"] = _make_grpc_settings(params.get("servicename", [""])[0])
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = _make_httpupgrade_settings(
            params.get("path", ["/"])[0],
            params.get("host", [default_host])[0],
        )

    return stream

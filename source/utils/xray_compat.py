"""The configs xray cannot load, refused before verification.

Verification gates publication: whatever this module rejects never appears in a
verified file, however healthy the server behind it is. That makes a wrong rule
here worse than a slow pipeline — a false refusal silently shrinks what the
project publishes, which is exactly what happened to Hysteria2 for as long as the
filter claimed xray had removed it (it added the outbound in v26.1.13, and this
pipeline runs `releases/latest`).

Most rules exist because these configs parse into an outbound and then fail when
xray loads the resulting JSON. In batch mode one xray process carries up to
`XRAY_BATCH_SIZE` configs, so a single unbuildable config costs every other
config in that chunk, not just itself — which is why the check runs on raw URL
strings before anything is built, rather than after.

Two rules are not load-failure guards, and the difference is written where each
one lives so nobody reads it as one: the VLESS user-id check filters junk that
xray accepts and authentication then rejects, and the Hysteria2 `insecure=1` rule
refuses a node that verifies and can therefore never connect. Both would come
back as timeouts; refusing them says what they are instead.

Extracted from `utils/xray_tester.py`, which is over the repository's module-size
ceiling and can only hold debt; the filter is pure string inspection with two
callers, so it is the seam that closes.
"""

import re
from urllib.parse import unquote

from utils.logger import log
from utils.security_filter import extract_ss_credentials, is_xray_cipher
from utils.url_payload import is_truthy

# The xray-core release every rule here and every outbound shape in the parsers was
# read from. The binary is downloaded from `releases/latest` unless `XRAY_VERSION`
# pins it, so a new release can delete a transport or rename a field while these
# patterns keep refusing on a reading that no longer describes the program being
# run. `health_check.check_xray_version()` compares the two at startup and says in
# the log which one this run trusted.
RULES_VERIFIED_AGAINST = "v26.3.27"

# Regex for validating UUIDs (standard format: 8-4-4-4-12 hex)
_RE_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I,
)

# The 32-character dashless spelling. `common/uuid/uuid.go` parses it the same
# way, so this filter must not treat it as garbage.
_RE_UUID_DASHLESS = re.compile(r"^[0-9a-f]{32}$", re.I)

# The flows xray's VLESS account builder accepts. `infra/conf/vless.go` switches
# on "", `vless.XRV` and `vless.XRV + "-udp443"` and returns
# `"flow" doesn't support "..." in this version` for everything else, which is a
# config-load failure. An allowlist because the rejected set is open-ended: the
# denylist this replaces both banned `-udp443` (accepted) and let
# `xtls-rprx-splice-anything` through to xray.
_VLESS_FLOWS = frozenset({"", "xtls-rprx-vision", "xtls-rprx-vision-udp443"})

# Transport names `TransportProtocol.Build()` resolves at v26.3.27. `splithttp`
# is an accepted alias of `xhttp`, and `kcp`/`mkcp` still build (they get no
# removal error, unlike h2/h3/http/quic), so refusing either was a false refusal.
_XRAY_TRANSPORTS = frozenset(
    {
        "raw",
        "tcp",
        "xhttp",
        "splithttp",
        "kcp",
        "mkcp",
        "grpc",
        "ws",
        "websocket",
        "httpupgrade",
        "hysteria",
    }
)

# Transports xray has deleted. `transport_internet.go` returns
# `PrintRemovedFeatureError` for these names, and any name outside
# `_XRAY_TRANSPORTS` falls to `default:` and returns
# `Config: unknown transport protocol:` — both are config-load failures, so in
# batch mode one such URL costs every other config in the chunk.
_REMOVED_TRANSPORTS = frozenset({"h2", "h3", "http", "quic"})

# The transports Reality loads over. `StreamConfig.Build()` compares the name
# `TransportProtocol.Build()` resolved to `tcp`, `splithttp` or `grpc` and answers
# `REALITY only supports RAW, XHTTP and gRPC for now.` for everything else
# (`transport_internet.go:1777-1780`, v26.3.27) -- a config-load failure, so ws,
# httpupgrade, kcp/mkcp and hysteria are refused here rather than handed to the shared
# process. `splithttp` is in the set because that is what xhttp resolves to, and a rule
# written against the spelling in the URL would refuse configs xray accepts.
_REALITY_TRANSPORTS = frozenset({"raw", "tcp", "xhttp", "splithttp", "grpc"})

# Reality's client decodes `shortId` with `hex.Decode` into an 8-byte buffer
# after rejecting `len > 16`, so: at most 16 hex characters, an even count, and
# empty is legal (it is the common case — most panels ship no shortId).
_RE_SHORTID = re.compile(r"^(?:[0-9a-f]{2}){0,8}$", re.I)

# `publicKey` goes through `base64.RawURLEncoding.DecodeString` with the result
# required to be exactly 32 bytes. Raw URL alphabet, unpadded: 43 characters of
# `A-Za-z0-9_-`. A standard-alphabet key (the `+`, `/`, `=` a panel sometimes
# emits) fails that decode and xray errors `invalid "password"` at load.
_RE_REALITY_PBK = re.compile(r"^[A-Za-z0-9_-]{43}$")

# `pinnedPeerCertSha256` is hex-decoded into 32 bytes by `transport_internet.go`
# after every `:` is stripped from the value, so the check is: drop the colons,
# then 64 hex characters and nothing else.
_RE_PIN_SHA256 = re.compile(r"^[0-9a-f]{64}$", re.I)

# Stream-level `security=` values xray's loader knows. Anything else is
# `Unknown security "..."`, and `xtls` specifically is a removed feature; both
# are load failures. Scoped to the schemes that use the parameter for the stream
# (an `ss://` URL may carry `security=` meaning the cipher, not the transport).
_STREAM_SECURITY_VALUES = frozenset({"", "none", "tls", "reality"})
_STREAM_SECURITY_SCHEMES = ("vless://", "trojan://", "vmess://")


def _query_value(cfg: str, key: str) -> str | None:
    """A URL query parameter, percent-decoded, or None when the URL has none.

    Shared because seven rules read a parameter by hand and disagreed about the
    tail — one split on `#`, another did not — which is how a rule ends up
    judging text that was never part of the parameter. The remark is cut before
    the query is located for the same reason: `…?pbk=<valid>#sid=zz` carries no
    second `sid`, and a rule that searched the whole string would refuse a config
    xray builds without complaint.

    Parameter names are matched case-insensitively because YAML converters emit
    both `pbk` and `PBK`; the *value* keeps its original case, since a base64 key
    is case-sensitive.
    """
    body = cfg.split("#", 1)[0]
    if "?" not in body:
        return None
    query = body.split("?", 1)[1]
    match = re.search(rf"(?:^|&){key}=([^&]*)", query, re.IGNORECASE)
    return None if match is None else unquote(match.group(1))


def filter_xray_compatible(configs: list[str]) -> tuple[list[str], list[tuple[str, str]]]:
    """Filter configs that would crash xray at startup.

    Checks known xray-incompatible patterns on raw URL strings.
    Returns (compatible_configs, rejected_with_reasons) where
    rejected_with_reasons is a list of (url, reason) tuples.

    Run this BEFORE sending configs to XrayTester.test_batch().
    """
    compatible = []
    rejected = []

    for cfg in configs:
        reason = _xray_incompatible_reason(cfg)
        if reason:
            rejected.append((cfg, reason))
        else:
            compatible.append(cfg)

    if rejected:
        from collections import Counter

        counts = Counter(r for _, r in rejected)
        summary = ", ".join(f"{k}({v})" for k, v in counts.most_common(5))
        log(f"Xray compat filter: removed {len(rejected)} config(s) ({summary})")

    return compatible, rejected


def _xray_incompatible_reason(cfg: str) -> str:
    """Check a single config for xray-incompatible patterns.

    Returns empty string if OK, or a short reason string if rejected.
    """
    cfg_lower = cfg.lower()

    # ── Protocol-level rejects ────────────────────────────────────
    # Hysteria2 is absent on purpose (xray added it in v26.1.13); v1 is refused:
    if cfg_lower.startswith(("hysteria://", "hy1://")):
        return "hysteria v1 unsupported by xray (version != 2)"

    # A Hysteria2 node reachable only with the certificate check off has no xray
    # shape at all: xray removed `allowInsecure` and replaced it with a pinned
    # certificate hash. This is not a load failure — the parser emits a
    # verifying TLS config and xray starts happily — but the handshake can never
    # succeed, so the run spends a test slot on it and reports a timeout, which
    # reads exactly like a dead server. Refusing it names what it actually is.
    #
    # Read through `_query_value`, not as a substring of the whole URL: the flag's
    # own text appears in node names, and a name is not a setting either way --
    # `#old-insecure=1-node` used to refuse a node xray can verify, while a name
    # carrying `pinSHA256=` excused one that is not verifiable. Every truthy
    # spelling counts, because the flag is written as `1` by the spec and as `yes`
    # or `true` by the panels that generate these links.
    if cfg_lower.startswith(("hysteria2://", "hy2://")):
        insecure = _query_value(cfg, "insecure")
        pin = _query_value(cfg, "pinSHA256")
        if is_truthy(insecure) and not pin:
            return "hysteria2 needs verification off (xray removed allowInsecure)"

    # A malformed pin is worse than no pin: xray strips the colons from
    # `pinnedPeerCertSha256`, hex-decodes it and requires 32 bytes, so a short or
    # non-hex value aborts the load. Checked on every Hysteria2 URL that carries
    # one, including a node that verifies, because that is the shape the parser
    # emits — and the value this module's own tests used to pin (`deadbeef`) is
    # one xray rejects. An empty value is *no* pin rather than a broken one: xray
    # leaves the field unset, so refusing it would drop a working node.
    if cfg_lower.startswith(("hysteria2://", "hy2://")):
        pin = _query_value(cfg, "pinSHA256")
        if pin and not _RE_PIN_SHA256.match(pin.replace(":", "")):
            return "hysteria2 pinSHA256 is not 32 bytes of hex"

    # ── Shadowsocks cipher xray's loader does not know ────────────
    # `unknown cipher method` is a load failure, so a chunk of configs dies with
    # it. The set of methods that break is open-ended — `aes-192-gcm`, `table`,
    # `rc4-md5`, a string mangled by a failed base64 read — which is why the test
    # is an allowlist of what xray accepts rather than a list of known-bad names.
    # `none` and `plain` are inside that allowlist: xray loads them, so their
    # problem is the missing encryption, and that is the security filter's
    # decision, not this one.
    if cfg_lower.startswith(("ss://", "ssr://")):
        credentials = extract_ss_credentials(cfg)
        method = credentials[0] if credentials else ""
        if method and not is_xray_cipher(method):
            return f"unknown shadowsocks cipher: {method}"

    # ── VLESS user id: a junk filter, not a load-failure guard ──────
    # `common/uuid.ParseString` is far more forgiving than this rule: 32-36
    # characters of hex parse (dashed or not) and *any* string of 1-30 characters
    # is folded into a v5 UUID by SHA1 without an error. So a mangled id does not
    # crash xray -- it loads, connects, and fails authentication. This exists
    # because such a node can never work and would otherwise take a test slot and
    # a line in the results that reads like an offline server.
    # It is deliberately not a strict RFC-4122 check: 32 dashless hex characters
    # parse upstream, so refusing them here would drop working nodes.
    if cfg_lower.startswith("vless://"):
        try:
            after_proto = cfg[cfg.index("://") + 3 :]
            uuid_part = after_proto.split("@")[0] if "@" in after_proto else ""
            # Check for URL-encoded garbage (%25 repeated)
            if "%25" in uuid_part or "%2540" in uuid_part:
                return "invalid UUID (url-encoded garbage)"
            clean = unquote(uuid_part).strip().rstrip(".")
            if not _RE_UUID.match(clean) and not _RE_UUID_DASHLESS.match(clean):
                # Check if it looks like readable text (not a UUID at all)
                if len(clean) > 40 or not all(c in "0123456789abcdefABCDEF-" for c in clean):
                    return "invalid UUID (not a valid format)"
                # Dashed-but-broken, or a short junk string
                return "invalid UUID (bad format)"
        except (ValueError, IndexError):
            return "invalid UUID (parse error)"

    # ── VLESS encryption field ────────────────────────────────────
    if "encryption=none=@" in cfg or "encryption=none=/" in cfg:
        return "garbage encryption value"

    # ── VLESS flow: three values load, everything else is a load failure ──
    # Scoped to vless because that is the only account builder that reads a flow:
    # trojan's rule is further down, and vmess has no flow field.
    if cfg_lower.startswith("vless://"):
        flow = _query_value(cfg, "flow")
        if flow is not None and flow.lower() not in _VLESS_FLOWS:
            return f"flow xray does not support: {flow}"

    # ── Reality's own fields, bounded the way its client builder bounds them ──
    # Scoped to `security=reality`: the parsers emit realitySettings only for it,
    # so a `pbk=` or `sid=` on any other URL is text xray never reads, and
    # refusing it would drop a config that loads fine.
    if "security=reality" in cfg_lower:
        pbk = _query_value(cfg, "pbk") or _query_value(cfg, "password")
        if pbk and not _RE_REALITY_PBK.match(pbk):
            return "reality publicKey is not 32 bytes of raw url base64"
        sid = _query_value(cfg, "sid")
        if sid is not None and not _RE_SHORTID.match(sid):
            return "reality shortId is not whole hex bytes, 0-16 characters"

    # ── Transport and security names xray's loader cannot resolve ──
    # Not a slow handshake: `TransportProtocol.Build()` returns a removed-feature
    # error for the deleted names and `Config: unknown transport protocol:` for
    # anything it does not list, and both abort the shared process in batch mode.
    transport = _query_value(cfg, "type")
    if transport:
        name = transport.lower()
        if name in _REMOVED_TRANSPORTS:
            return f"transport removed from xray: {name}"
        if name not in _XRAY_TRANSPORTS:
            return f"unknown transport protocol: {name}"
        if name not in _REALITY_TRANSPORTS and "security=reality" in cfg_lower:
            # `StreamConfig.Build()` inspects the resolved protocol name for reality
            # (`transport_internet.go:1777-1780`, v26.3.27): anything that is not `tcp`,
            # `splithttp` or `grpc` returns `REALITY only supports RAW, XHTTP and gRPC
            # for now.` The names come from `TransportProtocol.Build()` (`:998-1024`),
            # which is also what folds the spelling, so `ws`, `websocket`, `httpupgrade`,
            # `kcp`, `mkcp` and `hysteria` all load-fail here -- and in batch mode one of
            # them costs every other config sharing the process.
            return f"reality over {name}, which xray's stream config rejects"

    if cfg_lower.startswith(_STREAM_SECURITY_SCHEMES):
        security_match = re.search(r"[?&]security=([^&#]+)", cfg_lower)
        if security_match:
            security = security_match.group(1).lower().split("&")[0].split("#")[0]
            if security not in _STREAM_SECURITY_VALUES:
                return f"unknown stream security: {security}"

    # A non-empty flow on trojan is a removed feature upstream
    # (`trojan.go`: `Flow for Trojan` → PrintRemovedFeatureError), so the config
    # never loads. VLESS keeps its flow: there xray accepts `xtls-rprx-vision`.
    if cfg_lower.startswith("trojan://") and "flow=" in cfg_lower:
        flow_match = re.search(r"[?&]flow=([^&#]*)", cfg_lower)
        if flow_match and flow_match.group(1).strip("&#"):
            return "trojan with a non-empty flow (removed from xray)"

    return ""

"""The configs xray cannot load, refused before verification.

Verification gates publication: whatever this module rejects never appears in a
verified file, however healthy the server behind it is. That makes a wrong rule
here worse than a slow pipeline — a false refusal silently shrinks what the
project publishes, which is exactly what happened to Hysteria2 for as long as the
filter claimed xray had removed it (it added the outbound in v26.1.13, and this
pipeline runs `releases/latest`).

The rules exist because these configs parse into an outbound and then fail when
xray loads the resulting JSON. In batch mode one xray process carries up to
`XRAY_BATCH_SIZE` configs, so a single unbuildable config costs every other
config in that chunk, not just itself — which is why the check runs on raw URL
strings before anything is built, rather than after.

Extracted from `utils/xray_tester.py`, which is over the repository's module-size
ceiling and can only hold debt; the filter is pure string inspection with two
callers, so it is the seam that closes.
"""

import re

from utils.logger import log

# Regex for validating UUIDs (standard format: 8-4-4-4-12 hex)
_RE_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I,
)

# Flow values removed or unsupported in current xray
_UNSUPPORTED_FLOWS = frozenset(
    {
        "xtls-rprx-direct",
        "xtls-rprx-direct-udp443",
        "xtls-rprx-splice",
        "xtls-rprx-splice-udp443",
        "xtls-rprx-vision-udp443",
        "xtls-rprx-origin",
    }
)

# Valid shortId: 2-32 hex characters
_RE_SHORTID_VALID = re.compile(r"^[0-9a-f]{2,32}$", re.I)

# Supported Reality transports (xray URL type= maps to raw transport)
_REALITY_TRANSPORTS = frozenset({"raw", "tcp", "xhttp", "grpc"})


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

    # ── UUID validation (vless, vmess) ────────────────────────────
    # Extract UUID: vless://uuid@host
    if cfg_lower.startswith("vless://"):
        try:
            after_proto = cfg[cfg.index("://") + 3 :]
            uuid_part = after_proto.split("@")[0] if "@" in after_proto else ""
            # URL-decode then strip non-hex
            from urllib.parse import unquote

            decoded = unquote(uuid_part)
            # Check for URL-encoded garbage (%25 repeated)
            if "%25" in uuid_part or "%2540" in uuid_part:
                return "invalid UUID (url-encoded garbage)"
            # Check for non-UUID text
            clean = decoded.strip().rstrip(".")
            if not _RE_UUID.match(clean):
                # Check if it looks like readable text (not a UUID at all)
                if len(clean) > 40 or not all(c in "0123456789abcdefABCDEF-" for c in clean):
                    return "invalid UUID (not a valid format)"
                # It's hex-like but wrong length or format
                return "invalid UUID (bad format)"
        except (ValueError, IndexError):
            return "invalid UUID (parse error)"

    # ── VLESS encryption field ────────────────────────────────────
    if "encryption=none=@" in cfg or "encryption=none=/" in cfg:
        return "garbage encryption value"

    # ── Flow validation (VLESS) — prefix match against deprecated flows ──
    if "flow=" in cfg_lower:
        flow_match = re.search(r"[?&]flow=([^&#]+)", cfg_lower)
        if flow_match:
            flow_val = flow_match.group(1).lower().split("&")[0].split("#")[0]
            from urllib.parse import unquote

            flow_val = unquote(flow_val)
            # Check if flow starts with a deprecated prefix (catches
            # both exact matches and malformed variants like
            # xtls-rprx-vision-udp443-udp443-udp443)
            for deprecated in _UNSUPPORTED_FLOWS:
                if flow_val == deprecated or flow_val.startswith(deprecated + "-"):
                    return f"unsupported flow: {flow_val}"

    # ── Reality password (no spaces) — checks both password= and pbk= ─
    if "password=" in cfg or "pbk=" in cfg:
        for param in ("password", "pbk"):
            pw_match = re.search(rf"(?:^|[?&]){param}=([^&#]+)", cfg)
            if pw_match:
                pw_val = pw_match.group(1)
                from urllib.parse import unquote

                pw_val = unquote(pw_val)
                if " " in pw_val:
                    return f"reality {param} contains space"

    # ── Reality shortId length ────────────────────────────────────
    if "sid=" in cfg:
        sid_match = re.search(r"sid=([^&#]+)", cfg)
        if sid_match:
            sid_val = sid_match.group(1)
            from urllib.parse import unquote

            sid_val = unquote(sid_val)
            if not _RE_SHORTID_VALID.match(sid_val):
                if len(sid_val) < 2:
                    return "reality shortId too short"
                if len(sid_val) > 32:
                    return "reality shortId too long"
                return "reality shortId invalid chars"

    # ── Reality transport compatibility ───────────────────────────
    if "security=reality" in cfg_lower and "type=" in cfg_lower:
        type_match = re.search(r"[?&]type=([^&#]+)", cfg_lower)
        if type_match:
            transport = type_match.group(1).lower().split("&")[0].split("#")[0]
            if transport not in _REALITY_TRANSPORTS:
                return f"reality with unsupported transport: {transport}"

    return ""

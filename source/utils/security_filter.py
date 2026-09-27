"""Security filtering for VPN configs.
Validates encryption, certificates, and protocol-specific security settings."""

import base64
import binascii
import json
import re
from functools import lru_cache

from utils.url_payload import base64_payload, decode_base64_token

# Unified weak cipher sets (single source of truth)
SS_WEAK_CIPHERS = {
    "rc4",
    "rc4-md5",
    "rc4-md5-6",
    "des",
    "bf-cfb",
    "cast5-cfb",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-cfb8",
    "aes-192-cfb8",
    "aes-256-cfb8",
    "aes-128-cfb1",
    "aes-192-cfb1",
    "aes-256-cfb1",
    "aes-128-cfb-fast",
    "aes-192-cfb-fast",
    "aes-256-cfb-fast",
    "aes-128-cfb-simple",
    "aes-192-cfb-simple",
    "aes-256-cfb-simple",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "camellia-128-cfb",
    "camellia-192-cfb",
    "camellia-256-cfb",
    "des-cfb",
    "idea-cfb",
    "rc2-cfb",
    "seed-cfb",
    "salsa20",
    "chacha20",
    "xsalsa20",
    "xchacha20",
}

# Two methods that load and select no encryption at all. They are the
# clearest case of "must not reach the secure files", and they are NOT a
# compatibility problem — see `SS_XRAY_CIPHERS`.
SS_PLAINTEXT_CIPHERS = {"none", "plain"}

# Expected key lengths for Shadowsocks 2022 ciphers (in bytes).
# The password for these ciphers must be a base64-encoded key of exactly this length.
# Ref: https://xtls.github.io/en/config/inbounds/shadowsocks.html
# This is also the authoritative list of 2022 methods xray accepts:
# `infra/conf/shadowsocks.go` matches them against `shadowaead_2022.List`, which
# is exactly these three names, compared case-sensitively.
_SS_2022_KEY_LENGTHS = {
    "2022-blake3-aes-128-gcm": 16,
    "2022-blake3-aes-256-gcm": 32,
    "2022-blake3-chacha20-poly1305": 32,
}

# The methods xray's Shadowsocks loader accepts, spelled as
# `cipherFromString` in `infra/conf/shadowsocks.go` matches them (v26.3.27, the
# release `releases/latest` serves). Anything else is `CipherType_UNKNOWN`, and
# the client builder returns `unknown cipher method: ...` — a config-load
# failure, so in batch mode one such config costs every other config in the
# chunk. That is why the check is an allowlist: the rejected set is open-ended
# (`aes-192-gcm`, `table`, `rc4-md5`, the garbage a failed base64 read
# produces), and `SS_WEAK_CIPHERS` names only the part of it that is a security
# problem rather than a syntax one.
SS_XRAY_CIPHERS = {
    "aes-128-gcm",
    "aead_aes_128_gcm",
    "aes-256-gcm",
    "aead_aes_256_gcm",
    "chacha20-poly1305",
    "chacha20-ietf-poly1305",
    "aead_chacha20_poly1305",
    "xchacha20-poly1305",
    "xchacha20-ietf-poly1305",
    "aead_xchacha20_poly1305",
    *_SS_2022_KEY_LENGTHS,
    *SS_PLAINTEXT_CIPHERS,
}

# What this project calls "secure": a method xray loads that also encrypts.
# `none`/`plain` load, so they are excluded here and flagged by
# `has_insecure_setting()` instead of being refused by the compatibility filter.
SS_SECURE_CIPHERS = SS_XRAY_CIPHERS - SS_PLAINTEXT_CIPHERS


def is_xray_cipher(method: str) -> bool:
    """Whether xray's Shadowsocks loader would accept this cipher method."""
    return method.strip().lower() in SS_XRAY_CIPHERS


def extract_ss_credentials(config_line: str) -> tuple[str, str] | None:
    """The cipher method and password a Shadowsocks or SSR URL carries.

    Covers the four encodings in circulation -- plain `ss://method:password@host`,
    the base64 credentials of `ss://b64(method:password)@host`, the whole config inside
    one token as `ss://b64(method:password@host:port)`, and the `ssr://` payload -- so
    every consumer that judges a cipher reads the same decode instead of re-deriving it
    and disagreeing. Returns None when the line is not an SS/SSR URL or cannot be
    decoded: that means "no verdict here", not "insecure".

    The third form is the one a cipher allowlist must not miss. Its address sits inside
    the token, so the URL carries no `@` and neither clear-text branch applies; reading
    only those two let a `none` tunnel -- which loads in xray and encrypts nothing --
    answer "no verdict", and no verdict is what the pipeline records as clean.
    """
    lower = config_line.lower()
    try:
        if lower.startswith("ss://"):
            body = base64_payload(config_line)
            if ":" in body and "@" in body and body.index(":") < body.index("@"):
                method, _, rest = body.partition(":")
                return method.strip().lower(), rest.split("@")[0]

            if "@" in body:
                decoded = decode_base64_token(body.split("@")[0])
                if decoded is None or ":" not in decoded:
                    return None
                method, _, password = decoded.partition(":")
                return method.strip().lower(), password

            # No `@` in the URL at all: the address is in the token with the credentials.
            decoded = decode_base64_token(body)
            if decoded is None or "@" not in decoded:
                return None
            credentials, _, address = decoded.rpartition("@")
            if ":" not in credentials or ":" not in address:
                return None
            method, _, password = credentials.partition(":")
            return method.strip().lower(), password

        if lower.startswith("ssr://"):
            payload = base64_payload(config_line)
            padding = len(payload) % 4
            decoded = base64.b64decode(
                payload + "=" * (4 - padding) if padding else payload
            ).decode("utf-8")
            parts = decoded.split(":")
            if len(parts) < 6:
                return None
            # host:port:protocol:method:obfs:password[_params]. The password is
            # itself base64 here and stays that way: no consumer of this helper
            # reads it, and decoding it would fail on the malformed payloads that
            # are exactly what the caller wants a verdict on.
            return parts[3].strip().lower(), ""
    except (ValueError, IndexError, UnicodeDecodeError, binascii.Error):
        return None
    return None


def _check_ss_2022_key(method: str, password: str) -> bool:
    """Check Shadowsocks 2022 cipher for valid base64 key length.

    Shadowsocks 2022 ciphers (2022-blake3-*) require the password to be a
    base64-encoded key of an exact length specific to each cipher.

    Note: multi-key format (key1:key2) used by 3x-ui/Xray-core is NOT rejected
    here — it's a legitimate Xray feature that embeds user identity into a flat
    ss:// URL. Xray-core users (majority) can use these configs normally.
    sing-box users will see "bad key length" but that's a client incompatibility,
    not a config issue.

    Returns True if the key length is invalid (broken in ALL clients).

    Args:
        method: The cipher method (e.g. '2022-blake3-aes-128-gcm')
        password: The password portion of the URL

    Returns:
        True if the key is invalid, False if valid or if the cipher is
        not a 2022 variant (pass-through).
    """
    method_lower = method.lower().strip()
    expected_len = _SS_2022_KEY_LENGTHS.get(method_lower)
    if expected_len is None:
        return False  # Not a 2022 cipher, nothing to check

    # Key length validation: the password should be a base64-encoded key
    # of exactly the expected length. Wrong length = broken everywhere.
    try:
        rem = len(password) % 4
        padded = password + "=" * (4 - rem) if rem else password
        decoded = base64.b64decode(padded)
        if len(decoded) != expected_len:
            return True
    except (ValueError, TypeError):
        # Not valid base64 — let it through, Xray-core will catch it
        # during testing if it's actually broken.
        pass

    return False


# Pre-compiled regex patterns for security checks.
#
# Every one of them is anchored at a parameter boundary (`?` or `&`) and closed by
# the next one, because a bare substring search reads a node's remark as a
# setting: `vless://…#tls-node-security=none` is not a config asking for no
# encryption, and flagging it costs a working node its place in the secure files.
# The search still runs over the whole URL rather than only the query — a
# `?security=none` that happens to follow the fragment is treated as the parameter
# it reads like, because guessing the other way would let an unencrypted tunnel
# into the secure tier. Being wrong here is only ever allowed in that direction.
_ALLOWINSECURE_PATTERN = re.compile(r"(?:\?|&)allowinsecure=([^&?#]+)")
_INSECURE_PATTERN = re.compile(r"(?:\?|&)insecure=([^&?#]+)")
_SKIPCERT_PATTERN = re.compile(r"(?:\?|&)skip-cert-verify=([^&?#]+)")
# Catch-all: match `?insecure=1`, `&insecure=1`, `#insecure=1`, or bare param
_INSECURE_CATCH_RE = re.compile(r"(?:\?|&)insecure=1(?:&|#|$)")
_VERIFY_CATCH_RE = re.compile(r"(?:\?|&)verify=0(?:&|#|$)")
_SECURITY_NONE_RE = re.compile(r"(?:\?|&)security=none(?:&|#|$)")
_ENCRYPTION_NONE_RE = re.compile(r"(?:\?|&)encryption=none(?:&|#|$)")
_SECURITY_ENCRYPTED_RE = re.compile(r"(?:\?|&)security=(?:tls|reality)(?:&|#|$)")


def _check_insecure_general(config_lower: str) -> bool:
    """Check for allowInsecure/insecure/skip-cert-verify query parameters."""
    if "allowinsecure=" in config_lower:
        allow_insecure_match = _ALLOWINSECURE_PATTERN.search(config_lower)
        if allow_insecure_match:
            value = allow_insecure_match.group(1).strip()
            if value in ["1", "true", "yes", "on"]:
                return True
    if "insecure=" in config_lower:
        insecure_match = _INSECURE_PATTERN.search(config_lower)
        if insecure_match:
            value = insecure_match.group(1).strip()
            if value in ["1", "true", "yes", "on"]:
                return True
    if "skip-cert-verify=" in config_lower:
        skip_cert_verify_match = _SKIPCERT_PATTERN.search(config_lower)
        if skip_cert_verify_match:
            value = skip_cert_verify_match.group(1).strip()
            if value in ["1", "true", "yes", "on", "enabled"]:
                return True
    return False


def _check_security_none(config_lower: str) -> bool:
    """Check for security=none (no encryption)."""
    return bool(_SECURITY_NONE_RE.search(config_lower))


def _check_encryption_none(config_lower: str) -> bool:
    """Check for encryption=none in VLESS configs (when not using TLS/REALITY)."""
    return bool(
        _ENCRYPTION_NONE_RE.search(config_lower) and not _SECURITY_ENCRYPTED_RE.search(config_lower)
    )


def _check_vless_no_tls(config_lower: str) -> bool:
    """VLESS without TLS/REALITY = no encryption = insecure."""
    return bool(
        config_lower.startswith("vless://") and not _SECURITY_ENCRYPTED_RE.search(config_lower)
    )


def _check_vmess_json(config_line: str, config_lower: str) -> bool:
    """Check for insecure settings in vmess base64 JSON configuration."""
    if config_lower.startswith("vmess://"):
        try:
            payload = base64_payload(config_line)
            rem = len(payload) % 4
            if rem:
                payload += "=" * (4 - rem)
            decoded = base64.b64decode(payload).decode("utf-8", errors="ignore")
            if decoded.startswith("{"):
                j = json.loads(decoded)
                insecure_setting = j.get("insecure") or j.get("allowInsecure")
                if insecure_setting in [True, "true", 1, "1"]:
                    return True
                security_setting = j.get("scy") or j.get("security")
                if security_setting and str(security_setting).lower() == "none":
                    return True
                alter_id = j.get("aid") or j.get("alterId")
                if alter_id is not None:
                    # `aid > 0` marks a deployment still on the deprecated MD5
                    # id-cycle: the client asks the server to accept derived extra
                    # IDs, and that cycle is the attack surface. It is a property of
                    # the node, not of the verifier -- current xray's `VMessAccount`
                    # reads only id/security/experiments from JSON, so the value is
                    # ignored when connecting and the handshake goes out with zero
                    # alter IDs.
                    alter_id_value = int(alter_id) if isinstance(alter_id, (int, str)) else 0
                    if alter_id_value > 0:
                        return True
        except (json.JSONDecodeError, ValueError, IndexError, TypeError):
            pass
    return False


def _check_ss_cipher(config_line: str, config_lower: str) -> bool:
    """Check for insecure Shadowsocks methods and invalid 2022 key lengths.

    `none` and `plain` are here as well as anywhere: xray loads them, and what it
    loads is a tunnel with no encryption at all, so they are the clearest case of
    "must not reach the secure files" — the compatibility filter correctly leaves
    them alone because they are not a load failure.
    """
    if not config_lower.startswith("ss://"):
        return False

    credentials = extract_ss_credentials(config_line)
    if credentials is None:
        return False

    method, password = credentials
    if method in SS_PLAINTEXT_CIPHERS:
        return True
    if method in SS_WEAK_CIPHERS:
        return True
    return _check_ss_2022_key(method, password)


def _check_ssr_method(config_line: str, config_lower: str) -> bool:
    """Check for insecure ShadowsocksR methods."""
    if not config_lower.startswith("ssr://"):
        return False

    credentials = extract_ss_credentials(config_line)
    if credentials is None:
        return False
    return credentials[0] in SS_WEAK_CIPHERS


def _check_catch_all(config_lower: str) -> bool:
    """Catch-all: insecure=1 / verify=0 as query params."""
    if (
        _INSECURE_CATCH_RE.search(config_lower)
        or config_lower.split("?")[-1].split("&")[0] == "insecure=1"
    ):
        return True
    return bool(
        _VERIFY_CATCH_RE.search(config_lower)
        or config_lower.split("?")[-1].split("&")[0] == "verify=0"
    )


@lru_cache(maxsize=65536)
def has_insecure_setting(config_line: str) -> bool:
    """Check if a VPN config has insecure settings that should be filtered.

    Performs comprehensive security checks for all supported protocols:
    - allowInsecure/insecure params in query string
    - security=none / encryption=none (without TLS)
    - VMess base64 JSON: insecure flags, alterId > 0
    - Shadowsocks: weak ciphers
    - ShadowsocksR: weak encryption methods

    Args:
        config_line: VPN config URL (vless://, vmess://, trojan://, etc.)

    Returns:
        True if config has insecure settings, False if secure
    """
    config_lower = config_line.lower()

    if _check_insecure_general(config_lower):
        return True
    if _check_security_none(config_lower):
        return True
    if _check_encryption_none(config_lower):
        return True
    if _check_vless_no_tls(config_lower):
        return True
    if _check_vmess_json(config_line, config_lower):
        return True
    if _check_ss_cipher(config_line, config_lower):
        return True
    if _check_ssr_method(config_line, config_lower):
        return True
    return _check_catch_all(config_lower)


def filter_secure_configs(configs: list[str]) -> list[str]:
    """Filter out configs with insecure settings using parallel processing.

    Args:
        configs: List of VPN config URLs

    Returns:
        List of secure configs only
    """
    from utils.executor_cache import get_regex_executor

    def check_secure(config: str) -> tuple:
        return (config, not has_insecure_setting(config))

    executor = get_regex_executor()
    results = list(executor.map(check_secure, configs))

    return [config for config, is_secure in results if is_secure]

"""Security filtering for VPN configs.
Validates encryption, certificates, and protocol-specific security settings."""

import base64
import json
import re
from functools import lru_cache

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

SS_SECURE_CIPHERS = {
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "chacha20-poly1305",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}

# Expected key lengths for Shadowsocks 2022 ciphers (in bytes).
# The password for these ciphers must be a base64-encoded key of exactly this length.
# Ref: https://xtls.github.io/en/config/inbounds/shadowsocks.html
_SS_2022_KEY_LENGTHS = {
    "2022-blake3-aes-128-gcm": 16,
    "2022-blake3-aes-256-gcm": 32,
    "2022-blake3-chacha20-poly1305": 32,
}


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


# Pre-compiled regex patterns for security checks
_ALLOWINSECURE_PATTERN = re.compile(r"allowinsecure=([^&?#]+)")
_INSECURE_PATTERN = re.compile(r"insecure=([^&?#]+)")
_SKIPCERT_PATTERN = re.compile(r"skip-cert-verify=([^&?#]+)")
# Catch-all: match `?insecure=1`, `&insecure=1`, `#insecure=1`, or bare param
_INSECURE_CATCH_RE = re.compile(r"(?:\?|&)insecure=1(?:&|#|$)")
_VERIFY_CATCH_RE = re.compile(r"(?:\?|&)verify=0(?:&|#|$)")


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
    if "security=none" in config_lower:
        return True
    return False


def _check_encryption_none(config_lower: str) -> bool:
    """Check for encryption=none in VLESS configs (when not using TLS/REALITY)."""
    if "encryption=none" in config_lower and (
        "security=tls" not in config_lower and "security=reality" not in config_lower
    ):
        return True
    return False


def _check_vless_no_tls(config_lower: str) -> bool:
    """VLESS without TLS/REALITY = no encryption = insecure."""
    if config_lower.startswith("vless://") and not config_lower.startswith("vmess://"):
        if "security=tls" not in config_lower and "security=reality" not in config_lower:
            return True
    return False


def _check_vmess_json(config_line: str, config_lower: str) -> bool:
    """Check for insecure settings in vmess base64 JSON configuration."""
    if config_lower.startswith("vmess://"):
        try:
            payload = config_line[8:]
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
                    alter_id_value = int(alter_id) if isinstance(alter_id, (int, str)) else 0
                    if alter_id_value > 0:
                        return True
        except (json.JSONDecodeError, ValueError, IndexError, TypeError):
            pass
    return False


def _check_ss_cipher(config_line: str, config_lower: str) -> bool:
    """Check for insecure Shadowsocks methods and invalid 2022 key lengths."""
    if not config_lower.startswith("ss://"):
        return False

    try:
        ss_part = config_line[5:]
        # Strip fragment/query tail for clean parsing
        if "#" in ss_part:
            ss_part = ss_part.split("#")[0]
        url_clean = ss_part.split("?")[0] if "?" in ss_part else ss_part

        if ":" in url_clean and "@" in url_clean and url_clean.index(":") < url_clean.index("@"):
            # Plaintext format: method:password@host:port
            method = url_clean.split(":")[0].lower()
            if method in SS_WEAK_CIPHERS:
                return True
            # Extract password for 2022 key validation
            password = url_clean.split(":", 1)[1].split("@")[0]
            if _check_ss_2022_key(method, password):
                return True
        else:
            # Base64-encoded format: base64(method:password)@host:port
            if "@" in url_clean:
                encoded_part = url_clean.split("@")[0]
                rem = 4 - len(encoded_part) % 4
                if rem != 4:
                    padded_encoded_part = encoded_part + "=" * rem
                else:
                    padded_encoded_part = encoded_part
                try:
                    decoded_credentials = base64.b64decode(padded_encoded_part).decode("utf-8")
                    if ":" in decoded_credentials:
                        method = decoded_credentials.split(":")[0].lower()
                        password = decoded_credentials.split(":", 1)[1]
                        if method in SS_WEAK_CIPHERS:
                            return True
                        if _check_ss_2022_key(method, password):
                            return True
                except (ValueError, IndexError, UnicodeDecodeError):
                    pass
    except (ValueError, IndexError, UnicodeDecodeError):
        pass
    return False


def _check_ssr_method(config_line: str, config_lower: str) -> bool:
    """Check for insecure ShadowsocksR methods."""
    if config_lower.startswith("ssr://"):
        try:
            payload = config_line[6:]
            rem = len(payload) % 4
            if rem:
                payload += "=" * (4 - rem)
            decoded = base64.b64decode(payload).decode("utf-8")
            parts = decoded.split(":")
            if len(parts) >= 6:
                method = parts[3].lower()
                if method in SS_WEAK_CIPHERS:
                    return True
        except (ValueError, IndexError, UnicodeDecodeError):
            pass
    return False


def _check_catch_all(config_lower: str) -> bool:
    """Catch-all: insecure=1 / verify=0 as query params."""
    if (
        _INSECURE_CATCH_RE.search(config_lower)
        or config_lower.split("?")[-1].split("&")[0] == "insecure=1"
    ):
        return True
    if (
        _VERIFY_CATCH_RE.search(config_lower)
        or config_lower.split("?")[-1].split("&")[0] == "verify=0"
    ):
        return True
    return False


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
    if _check_catch_all(config_lower):
        return True

    return False


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

"""Tests for security_filter.py — security checks for VPN configs."""

import base64

import pytest

from utils.security_filter import (
    SS_PLAINTEXT_CIPHERS,
    SS_SECURE_CIPHERS,
    SS_WEAK_CIPHERS,
    SS_XRAY_CIPHERS,
    extract_ss_credentials,
    filter_secure_configs,
    has_insecure_setting,
    is_xray_cipher,
)

pytestmark = pytest.mark.unit


class TestCipherConstants:
    """Cipher sets contain expected values."""

    def test_weak_ciphers_not_empty(self):
        assert len(SS_WEAK_CIPHERS) > 10

    def test_secure_ciphers_not_empty(self):
        assert len(SS_SECURE_CIPHERS) >= 5

    def test_no_overlap(self):
        """A cipher should not be in both sets."""
        overlap = SS_WEAK_CIPHERS & SS_SECURE_CIPHERS
        assert len(overlap) == 0, f"overlapping ciphers: {overlap}"


class TestHasInsecureSetting:
    """Test the main security check function."""

    def test_allow_insecure_param_true(self):
        assert (
            has_insecure_setting("vless://uuid@host:443?allowInsecure=1&security=tls#test") is True
        )

    def test_allow_insecure_param_false(self):
        assert (
            has_insecure_setting("vless://uuid@host:443?allowInsecure=0&security=tls#test") is False
        )

    def test_insecure_param_true(self):
        assert has_insecure_setting("vless://uuid@host:443?insecure=1&security=tls#test") is True

    def test_security_none(self):
        assert has_insecure_setting("vless://uuid@host:443?security=none") is True

    def test_encryption_none_without_tls(self):
        """encryption=none without TLS/REALITY is insecure."""
        assert has_insecure_setting("vless://uuid@host:443?encryption=none") is True

    def test_encryption_none_with_tls_is_ok(self):
        """encryption=none WITH security=tls is acceptable (not insecure)."""
        assert has_insecure_setting("vless://uuid@host:443?encryption=none&security=tls") is False

    def test_skip_cert_verify_true(self):
        """TUIC style skip-cert-verify=1 should be caught."""
        assert has_insecure_setting("tuic://uuid@host:443?skip-cert-verify=1") is True

    def test_skip_cert_verify_false(self):
        assert has_insecure_setting("tuic://uuid@host:443?skip-cert-verify=0") is False

    def test_vmess_insecure_json(self):
        """VMess JSON with insecure=true should be flagged."""
        import base64

        cfg = '{"add":"host","port":443,"id":"uuid","aid":"0","insecure":true}'
        b64 = base64.b64encode(cfg.encode()).decode()
        assert has_insecure_setting(f"vmess://{b64}") is True

    def test_vmess_alter_id_positive(self):
        """VMess with alterId > 0 (MD5 auth vulnerability)."""
        import base64

        cfg = '{"add":"host","port":443,"id":"uuid","aid":"1"}'
        b64 = base64.b64encode(cfg.encode()).decode()
        assert has_insecure_setting(f"vmess://{b64}") is True

    def test_vmess_alter_id_zero(self):
        """VMess with alterId=0 is fine."""
        import base64

        cfg = '{"add":"host","port":443,"id":"uuid","aid":"0"}'
        b64 = base64.b64encode(cfg.encode()).decode()
        assert has_insecure_setting(f"vmess://{b64}") is False

    def test_vmess_security_none(self):
        """VMess with security=none in JSON."""
        import base64

        cfg = '{"add":"host","port":443,"id":"uuid","aid":"0","security":"none"}'
        b64 = base64.b64encode(cfg.encode()).decode()
        assert has_insecure_setting(f"vmess://{b64}") is True

    def test_vmess_malformed_json(self):
        """Malformed VMess base64 shouldn't crash."""
        assert has_insecure_setting("vmess://not-valid-base64!!!") is False

    def test_ss_weak_cipher_in_url(self):
        """Shadowsocks URL with weak cipher (method in plain text before @)."""
        assert has_insecure_setting("ss://rc4-md5:password@host:443") is True

    def test_ss_weak_cipher_base64_encoded(self):
        """Shadowsocks URL with base64-encoded weak cipher."""
        import base64

        creds = base64.b64encode(b"rc4-md5:password").decode()
        assert has_insecure_setting(f"ss://{creds}@host:443") is True

    def test_ss_secure_cipher(self):
        """Shadowsocks with strong cipher is secure."""
        assert has_insecure_setting("ss://chacha20-ietf-poly1305:password@host:443") is False

    def test_ss_2022_valid_key_16(self):
        """2022-blake3-aes-128-gcm with correct 16-byte base64 key is secure."""
        import base64

        key = base64.b64encode(b"\x01" * 16).decode()
        assert has_insecure_setting(f"ss://2022-blake3-aes-128-gcm:{key}@host:443") is False

    def test_ss_2022_valid_key_32(self):
        """2022-blake3-aes-256-gcm with correct 32-byte base64 key is secure."""
        import base64

        key = base64.b64encode(b"\x01" * 32).decode()
        assert has_insecure_setting(f"ss://2022-blake3-aes-256-gcm:{key}@host:443") is False

    def test_ss_2022_colon_separated_keys(self):
        """2022-blake3 with key1:key2 (3x-ui format) is a valid Xray-core feature."""
        import base64

        key1 = base64.b64encode(b"\x01" * 16).decode()
        key2 = base64.b64encode(b"\x02" * 16).decode()
        assert has_insecure_setting(f"ss://2022-blake3-aes-128-gcm:{key1}:{key2}@host:443") is False

    def test_ss_2022_wrong_key_length(self):
        """2022-blake3 with base64 key of wrong length is insecure."""
        import base64

        # 8-byte key for aes-128-gcm (expects 16) — wrong
        key_wrong = base64.b64encode(b"\x01" * 8).decode()
        assert has_insecure_setting(f"ss://2022-blake3-aes-128-gcm:{key_wrong}@host:443") is True

    def test_ss_2022_base64_valid(self):
        """2022-blake3 valid key in base64-encoded URL format is secure."""
        import base64

        key = base64.b64encode(b"\x01" * 16).decode()
        creds = base64.b64encode(f"2022-blake3-aes-128-gcm:{key}".encode()).decode()
        assert has_insecure_setting(f"ss://{creds}@host:443") is False

    def test_ss_2022_base64_colon_separated(self):
        """2022-blake3 multi-key in base64-encoded URL format is valid Xray-core."""
        import base64

        key1 = base64.b64encode(b"\x01" * 16).decode()
        key2 = base64.b64encode(b"\x02" * 16).decode()
        creds = base64.b64encode(f"2022-blake3-aes-128-gcm:{key1}:{key2}".encode()).decode()
        assert has_insecure_setting(f"ss://{creds}@host:443") is False

    def test_ss_non_2022_not_affected(self):
        """Regular ss:// with non-2022 cipher is not affected by new check."""
        assert has_insecure_setting("ss://aes-256-gcm:somepassword@host:443") is False

    def test_ssr_weak_cipher(self):
        """ShadowsocksR with weak method should be flagged."""
        import base64

        decoded = "host:443:origin:rc4-md5:tls1.2_ticket_auth:base64pass"
        payload = base64.b64encode(decoded.encode()).decode()
        assert has_insecure_setting(f"ssr://{payload}") is True

    def test_ssr_short_payload_no_crash(self):
        """SSR with <6 parts (short form) should not crash."""
        import base64

        decoded = "host:443"
        payload = base64.b64encode(decoded.encode()).decode()
        assert has_insecure_setting(f"ssr://{payload}") is False

    def test_ssr_malformed_no_crash(self):
        """Malformed SSR should not crash."""
        assert has_insecure_setting("ssr://!!!not-base64!!!") is False

    def test_catch_all_insecure_1(self):
        """Catch-all: insecure=1 anywhere in the URL."""
        assert has_insecure_setting("trojan://pass@host?insecure=1") is True

    def test_catch_all_verify_0(self):
        """Catch-all: verify=0 anywhere."""
        assert has_insecure_setting("vless://uuid@host?verify=0&security=tls") is True

    def test_secure_config_no_flags(self):
        """A clean secure config should return False."""
        assert (
            has_insecure_setting("vless://uuid@host:443?security=tls&sni=example.com#test") is False
        )


class TestFilterSecureConfigs:
    """filter_secure_configs filters out insecure configs."""

    def test_filters_insecure(self):
        configs = [
            "vless://a@host1:443?security=tls",
            "vless://b@host2:443?insecure=1",
            "vless://c@host3:443?security=tls",
        ]
        result = filter_secure_configs(configs)
        assert len(result) == 2
        assert all("insecure" not in c for c in result)

    def test_empty_input(self):
        assert filter_secure_configs([]) == []

    def test_all_secure(self):
        configs = [
            "vless://a@host:443?security=tls",
            "trojan://pass@host:443?security=tls",
        ]
        result = filter_secure_configs(configs)
        assert len(result) == 2


class TestShadowsocksCipherAllowlist:
    """The methods xray's Shadowsocks loader accepts, and what that set is for.

    `cipherFromString` in xray's `infra/conf/shadowsocks.go` is a switch, so any
    name outside it becomes CipherType_UNKNOWN and the client builder returns
    "unknown cipher method" — a config-load failure, not a slow handshake. The
    accepted spellings below are the switch's own cases (checked at v26.3.27),
    including the `aead_*` aliases it lists next to each real name.
    """

    @pytest.mark.parametrize(
        "method",
        [
            "aes-128-gcm",
            "aes-256-gcm",
            "chacha20-poly1305",
            "chacha20-ietf-poly1305",
            "xchacha20-poly1305",
            "xchacha20-ietf-poly1305",
            "aead_aes_128_gcm",
            "aead_aes_256_gcm",
            "aead_chacha20_poly1305",
            "aead_xchacha20_poly1305",
            "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305",
            "none",
            "plain",
        ],
    )
    def test_a_method_xray_names_is_accepted(self, method):
        assert is_xray_cipher(method) is True

    @pytest.mark.parametrize(
        "method",
        [
            "aes-192-gcm",  # a real AEAD cipher the switch omits
            "2022-blake3-aes-192-gcm",  # the 2022 list holds exactly three names
            "2022-blake3-chacha20-ietf-poly1305",  # a plausible spelling that is absent
            "chacha20",  # stream cipher, and in SS_WEAK_CIPHERS besides
            "rc4-md5",
            "table",
            "sodium:chacha20",
            "",
        ],
    )
    def test_a_method_xray_does_not_name_is_refused(self, method):
        assert is_xray_cipher(method) is False

    def test_no_cipher_the_security_filter_calls_weak_is_loadable(self):
        """Overlap would mean the allowlist grew past what xray actually accepts."""
        overlap = SS_WEAK_CIPHERS & SS_XRAY_CIPHERS
        assert not overlap, f"weak ciphers inside the allowlist: {overlap}"

    def test_the_secure_set_is_the_allowlist_minus_the_plaintext_methods(self):
        """One source of truth: secure is "xray loads it" minus "no crypto"."""
        assert SS_SECURE_CIPHERS == SS_XRAY_CIPHERS - SS_PLAINTEXT_CIPHERS

    def test_case_and_surrounding_space_are_normalised(self):
        assert is_xray_cipher("  AES-256-GCM ") is True

    def test_a_plaintext_method_loads_so_the_security_filter_has_to_flag_it(self):
        """`none` and `plain` are xray-compatible *and* insecure.

        The two filters answer different questions, so both have to say something
        here: if this check ever returns False an unencrypted tunnel is treated as
        encrypted and reaches the secure files.
        """
        assert has_insecure_setting("ss://none:somepassword@h.example.com:443") is True
        assert has_insecure_setting("ss://plain:somepassword@h.example.com:443") is True
        assert has_insecure_setting("ss://aes-256-gcm:somepassword@h.example.com:443") is False

    def test_an_unloadable_cipher_is_not_a_security_verdict(self):
        """`aes-192-gcm` has no known weakness; xray just cannot read it.

        Pinned because the compatibility filter refuses it while the security
        filter does not, and the split is what keeps ss-secure.txt (built before
        verification) from silently losing configs for the wrong reason.
        """
        assert has_insecure_setting("ss://aes-192-gcm:somepassword@h.example.com:443") is False


class TestExtractSsCredentials:
    """The three URL encodings one helper has to cover."""

    def test_plaintext_form(self):
        url = "ss://aes-256-gcm:pw@h.example.com:443"
        assert extract_ss_credentials(url) == ("aes-256-gcm", "pw")

    def test_base64_form(self):
        token = base64.b64encode(b"chacha20-ietf-poly1305:secretpw").decode()
        assert extract_ss_credentials(f"ss://{token}@h.example.com:443") == (
            "chacha20-ietf-poly1305",
            "secretpw",
        )

    def test_remark_and_params_are_stripped_before_parsing(self):
        url = "ss://aes-128-gcm:pw@h.example.com:443?plugin=obfs-local#name"
        assert extract_ss_credentials(url) == ("aes-128-gcm", "pw")

    def test_ssr_form_returns_the_method_without_decoding_the_password(self):
        """SSR nests a second base64 layer in the password; nobody reads it."""
        raw = b"h.example.com:443:origin:aes-256-cfb:tls1.2_ticket_auth:cGFzcw"
        assert extract_ss_credentials(f"ssr://{base64.b64encode(raw).decode()}") == (
            "aes-256-cfb",
            "",
        )

    @pytest.mark.parametrize(
        "url",
        [
            "vless://12345678-1234-1234-1234-123456789012@h.example.com:443",
            "ss://!!!not-base64!!!@h.example.com:443",
            "ssr://aGVsbG8",  # decodes to fewer than the six fields SSR has
            "ss://YWJjZA==",  # base64 with no "@" — the host is inside the blob
        ],
    )
    def test_no_verdict_is_none_rather_than_a_guess(self, url):
        """Both callers read None as "leave this config alone".

        Returning a guessed method instead would decide a config's tier from text
        that was never a cipher name, and the compatibility filter would refuse
        configs it cannot read.
        """
        assert extract_ss_credentials(url) is None


class TestParameterBoundaries:
    """A setting is a query parameter, not a substring of the URL.

    These checks used to search the whole string for `security=none` and friends,
    so a node's remark could set one off and cost a working config its place in the
    secure files. The direction of the fix is what matters: a parameter is still
    read from anywhere in the string — a `?security=none` that follows a fragment
    counts — because the one mistake not allowed here is letting an unencrypted
    tunnel into the secure tier.
    """

    def test_a_remark_that_names_a_setting_is_not_one(self):
        assert (
            has_insecure_setting("vless://uuid@host:443?security=tls#node-security=none") is False
        )

    def test_a_remark_cannot_vouch_for_the_transport(self):
        """The opposite case, and the one that used to be a false negative.

        The remark's `security=tls` text satisfied the "is this encrypted" search,
        so a vless URL with no security parameter at all read as secure.
        """
        assert has_insecure_setting("vless://uuid@host:443#say-security=tls") is True

    def test_security_none_after_a_fragment_still_counts(self):
        assert has_insecure_setting("vless://uuid@host:443#name?security=none") is True

    def test_encryption_none_with_reality_is_not_flagged(self):
        url = "vless://uuid@host:443?encryption=none&security=reality"

        assert has_insecure_setting(url) is False

    def test_allow_insecure_is_read_as_a_parameter(self):
        assert has_insecure_setting("vless://uuid@host:443?allowInsecure=1&security=tls") is True
        assert has_insecure_setting("vless://uuid@host:443#allowInsecure=1x?security=tls") is False

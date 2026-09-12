"""Tests for security_filter.py — security checks for VPN configs."""


from utils.security_filter import (
    SS_SECURE_CIPHERS,
    SS_WEAK_CIPHERS,
    filter_secure_configs,
    has_insecure_setting,
)


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
        assert has_insecure_setting(
            "vless://uuid@host:443?allowInsecure=1&security=tls#test"
        ) is True

    def test_allow_insecure_param_false(self):
        assert has_insecure_setting(
            "vless://uuid@host:443?allowInsecure=0&security=tls#test"
        ) is False

    def test_insecure_param_true(self):
        assert has_insecure_setting(
            "vless://uuid@host:443?insecure=1&security=tls#test"
        ) is True

    def test_security_none(self):
        assert has_insecure_setting(
            "vless://uuid@host:443?security=none"
        ) is True

    def test_encryption_none_without_tls(self):
        """encryption=none without TLS/REALITY is insecure."""
        assert has_insecure_setting(
            "vless://uuid@host:443?encryption=none"
        ) is True

    def test_encryption_none_with_tls_is_ok(self):
        """encryption=none WITH security=tls is acceptable (not insecure)."""
        assert has_insecure_setting(
            "vless://uuid@host:443?encryption=none&security=tls"
        ) is False

    def test_skip_cert_verify_true(self):
        """TUIC style skip-cert-verify=1 should be caught."""
        assert has_insecure_setting(
            "tuic://uuid@host:443?skip-cert-verify=1"
        ) is True

    def test_skip_cert_verify_false(self):
        assert has_insecure_setting(
            "tuic://uuid@host:443?skip-cert-verify=0"
        ) is False

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
        assert has_insecure_setting(
            "ss://rc4-md5:password@host:443"
        ) is True

    def test_ss_weak_cipher_base64_encoded(self):
        """Shadowsocks URL with base64-encoded weak cipher."""
        import base64
        creds = base64.b64encode(b"rc4-md5:password").decode()
        assert has_insecure_setting(f"ss://{creds}@host:443") is True

    def test_ss_secure_cipher(self):
        """Shadowsocks with strong cipher is secure."""
        assert has_insecure_setting(
            "ss://chacha20-ietf-poly1305:password@host:443"
        ) is False

    def test_ss_2022_valid_key_16(self):
        """2022-blake3-aes-128-gcm with correct 16-byte base64 key is secure."""
        import base64
        key = base64.b64encode(b'\x01' * 16).decode()
        assert has_insecure_setting(
            f"ss://2022-blake3-aes-128-gcm:{key}@host:443"
        ) is False

    def test_ss_2022_valid_key_32(self):
        """2022-blake3-aes-256-gcm with correct 32-byte base64 key is secure."""
        import base64
        key = base64.b64encode(b'\x01' * 32).decode()
        assert has_insecure_setting(
            f"ss://2022-blake3-aes-256-gcm:{key}@host:443"
        ) is False

    def test_ss_2022_colon_separated_keys(self):
        """2022-blake3 with key1:key2 (3x-ui format) is a valid Xray-core feature."""
        import base64
        key1 = base64.b64encode(b'\x01' * 16).decode()
        key2 = base64.b64encode(b'\x02' * 16).decode()
        assert has_insecure_setting(
            f"ss://2022-blake3-aes-128-gcm:{key1}:{key2}@host:443"
        ) is False

    def test_ss_2022_wrong_key_length(self):
        """2022-blake3 with base64 key of wrong length is insecure."""
        import base64
        # 8-byte key for aes-128-gcm (expects 16) — wrong
        key_wrong = base64.b64encode(b'\x01' * 8).decode()
        assert has_insecure_setting(
            f"ss://2022-blake3-aes-128-gcm:{key_wrong}@host:443"
        ) is True

    def test_ss_2022_base64_valid(self):
        """2022-blake3 valid key in base64-encoded URL format is secure."""
        import base64
        key = base64.b64encode(b'\x01' * 16).decode()
        creds = base64.b64encode(f"2022-blake3-aes-128-gcm:{key}".encode()).decode()
        assert has_insecure_setting(f"ss://{creds}@host:443") is False

    def test_ss_2022_base64_colon_separated(self):
        """2022-blake3 multi-key in base64-encoded URL format is valid Xray-core."""
        import base64
        key1 = base64.b64encode(b'\x01' * 16).decode()
        key2 = base64.b64encode(b'\x02' * 16).decode()
        creds = base64.b64encode(
            f"2022-blake3-aes-128-gcm:{key1}:{key2}".encode()
        ).decode()
        assert has_insecure_setting(f"ss://{creds}@host:443") is False

    def test_ss_non_2022_not_affected(self):
        """Regular ss:// with non-2022 cipher is not affected by new check."""
        assert has_insecure_setting(
            "ss://aes-256-gcm:somepassword@host:443"
        ) is False

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
        assert has_insecure_setting(
            "trojan://pass@host?insecure=1"
        ) is True

    def test_catch_all_verify_0(self):
        """Catch-all: verify=0 anywhere."""
        assert has_insecure_setting(
            "vless://uuid@host?verify=0&security=tls"
        ) is True

    def test_secure_config_no_flags(self):
        """A clean secure config should return False."""
        assert has_insecure_setting(
            "vless://uuid@host:443?security=tls&sni=example.com#test"
        ) is False

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

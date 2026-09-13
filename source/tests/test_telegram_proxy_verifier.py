"""Tests for Telegram proxy verifier — pure logic (no subprocess needed).

The full TelegramProxyVerifier has heavy asyncio/subprocess deps (socket,
curl_cffi, xray). These tests cover the pure-logic methods that can be
tested without mocking sockets or network: parse_proxy_url and
_create_handshake_packet.
"""

import pytest

from utils.telegram_proxy_verifier import TelegramProxyVerifier

pytestmark = pytest.mark.unit


class TestParseProxyUrl:
    """Test parse_proxy_url static method — pure string parsing."""

    def test_mtproto_tme_format(self):
        """https://t.me/proxy?server=host.com&port=443&secret=abc"""
        result = TelegramProxyVerifier.parse_proxy_url(
            "https://t.me/proxy?server=proxy.example.com&port=443&secret=eeabcd"
        )
        assert result["server"] == "proxy.example.com"
        assert result["port"] == 443
        assert result["secret"] == "eeabcd"
        assert result["type"] == "mtproto"
        assert result["username"] is None
        assert result["password"] is None

    def test_mtproto_tg_format(self):
        """tg://proxy?server=host.com&port=443&secret=abc"""
        result = TelegramProxyVerifier.parse_proxy_url(
            "tg://proxy?server=tg.example.com&port=1080&secret=xyz"
        )
        assert result["server"] == "tg.example.com"
        assert result["port"] == 1080
        assert result["secret"] == "xyz"
        assert result["type"] == "mtproto"

    def test_socks5_tme_format(self):
        """https://t.me/socks?server=host.com&port=1080"""
        result = TelegramProxyVerifier.parse_proxy_url(
            "https://t.me/socks?server=socks.example.com&port=1080"
        )
        assert result["server"] == "socks.example.com"
        assert result["port"] == 1080
        assert result["type"] == "socks5"

    def test_socks5_with_auth(self):
        """https://t.me/socks?server=host.com&port=1080&user=u&pass=p"""
        result = TelegramProxyVerifier.parse_proxy_url(
            "https://t.me/socks?server=auth.example.com&port=1080&user=myuser&pass=mypass"
        )
        assert result["server"] == "auth.example.com"
        assert result["port"] == 1080
        assert result["username"] == "myuser"
        assert result["password"] == "mypass"
        assert result["type"] == "socks5"

    def test_socks5_uri_format(self):
        """socks5://user:pass@host:1080"""
        result = TelegramProxyVerifier.parse_proxy_url(
            "socks5://socksuser:sockspass@socks-uri.example.com:1080"
        )
        assert result["server"] == "socks-uri.example.com"
        assert result["port"] == 1080
        assert result["username"] == "socksuser"
        assert result["password"] == "sockspass"
        assert result["type"] == "socks5"

    def test_socks5_uri_no_auth(self):
        """socks5://host:1080"""
        result = TelegramProxyVerifier.parse_proxy_url("socks5://noauth.example.com:1080")
        assert result["server"] == "noauth.example.com"
        assert result["port"] == 1080
        assert result["username"] is None
        assert result["password"] is None
        assert result["type"] == "socks5"

    def test_missing_port_defaults_to_zero(self):
        """URL without port should return port=0."""
        result = TelegramProxyVerifier.parse_proxy_url(
            "https://t.me/proxy?server=noport.example.com"
        )
        assert result["server"] == "noport.example.com"
        assert result["port"] == 0

    def test_tg_socks_format(self):
        """tg://socks?server=host&port=1080"""
        result = TelegramProxyVerifier.parse_proxy_url(
            "tg://socks?server=tgsocks.example.com&port=1080"
        )
        assert result["server"] == "tgsocks.example.com"
        assert result["port"] == 1080
        assert result["type"] == "socks5"


class TestCreateHandshakePacket:
    """Test _create_handshake_packet — pure binary construction.

    The packet structure is: random_data[:8] + secret_bytes[:16] + random_data[24:]
    = 8 + min(16, secret_len) + 32 = typically 56 bytes for 16-byte secrets.
    """

    def test_returns_56_bytes_for_hex_secret(self):
        """32-char hex secret produces a 16-byte key → 8 + 16 + 32 = 56 bytes."""
        secret = "ee" * 16  # 32 hex chars = 16 bytes
        packet = TelegramProxyVerifier()._create_handshake_packet(secret)
        assert len(packet) == 56

    def test_hex_secret_in_packet(self):
        """The secret bytes should appear at positions 8-23 in the packet."""
        verifier = TelegramProxyVerifier()
        secret = "ee" * 16
        packet = verifier._create_handshake_packet(secret)
        # Bytes 8-23 (inclusive) should be the secret
        expected_secret = bytes.fromhex(secret)
        assert packet[8:24] == expected_secret

    def test_base64_secret(self):
        """Base64-encoded secret should be decoded and placed at positions 8-23."""
        import base64

        secret_bytes = b"a" * 16
        secret_b64 = base64.b64encode(secret_bytes).decode()
        packet = TelegramProxyVerifier()._create_handshake_packet(secret_b64)
        assert len(packet) == 56
        assert packet[8:24] == secret_bytes

    def test_short_secret_padded_to_16(self):
        """Short secret (<16 bytes) produces a shorter packet."""
        packet = TelegramProxyVerifier()._create_handshake_packet("short")
        # 8 + min(16, 5) + 32 = 8 + 5 + 32 = 45
        assert len(packet) == 45

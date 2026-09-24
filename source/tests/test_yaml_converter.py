"""Tests for yaml_converter.py — YAML → VPN config URL conversion."""

import pytest

from fetchers.yaml_converter import (
    _build_hysteria_url,
    _build_shadowsocks_url,
    _build_shadowsocksr_url,
    _build_trojan_url,
    _build_tuic_url,
    _build_vless_url,
    _convert_vmess_to_url,
    _is_proxy_config,
    _try_convert_to_url,
    convert_yaml_to_vpn_configs,
)

pytestmark = pytest.mark.unit


class TestIsProxyConfig:
    """Detect proxy config dictionaries."""

    def test_vmess_config_detected(self):
        """A dict with 'type': 'vmess' is a proxy config."""
        assert _is_proxy_config({"type": "vmess", "server": "a.com", "port": 443}) is True

    def test_config_with_server_and_port(self):
        """A dict with 'server' and 'port' but no type is still a proxy config."""
        assert _is_proxy_config({"server": "a.com", "port": 443}) is True

    def test_empty_dict_not_proxy(self):
        """Empty dict has fewer than 2 indicators."""
        assert _is_proxy_config({}) is False

    def test_one_indicator_not_enough(self):
        """Single field is not enough."""
        assert _is_proxy_config({"name": "my server"}) is False


class TestConvertVmess:
    """VMess config → vmess:// URL."""

    def test_basic_vmess(self):
        url = _convert_vmess_to_url(
            {
                "name": "test",
                "server": "1.2.3.4",
                "port": 443,
                "uuid": "abc-123",
                "network": "ws",
                "tls": True,
                "path": "/ws",
                "host": "example.com",
            }
        )
        assert url.startswith("vmess://")
        # Decode base64 payload to verify content
        import base64

        payload = url[8:]
        rem = len(payload) % 4
        if rem:
            payload += "=" * (4 - rem)
        decoded = base64.b64decode(payload).decode("utf-8")
        assert '"add":"1.2.3.4"' in decoded
        assert '"port":"443"' in decoded

    def test_vmess_missing_fields(self):
        """Missing fields produce a URL with empty values (builder is lenient)."""
        url = _convert_vmess_to_url({"name": "incomplete"})
        # Builder still produces a URL — it uses .get() with empty defaults
        assert url.startswith("vmess://")

    def test_vmess_empty_returns_url(self):
        """Empty dict still produces a URL with default/empty values."""
        url = _convert_vmess_to_url({})
        assert url.startswith("vmess://")


class TestBuildVless:
    """Build VLESS URL from config dict."""

    def test_basic_vless(self):
        url = _build_vless_url(
            {
                "server": "vless.host",
                "port": 443,
                "uuid": "uuid-789",
                "network": "tcp",
                "tls": True,
                "servername": "vless.host",
            }
        )
        assert url.startswith("vless://")
        assert "uuid-789" in url
        assert "vless.host" in url
        assert "security=tls" in url

    def test_vless_missing_fields(self):
        """Missing uuid returns empty."""
        assert _build_vless_url({"server": "x.com", "port": 443}) == ""


class TestBuildTrojan:
    """Build Trojan URL from config dict."""

    def test_basic_trojan(self):
        url = _build_trojan_url(
            {
                "server": "trojan.host",
                "port": 443,
                "password": "pass123",
                "sni": "trojan.host",
            }
        )
        assert url.startswith("trojan://")
        assert "pass123" in url
        assert "security=tls" in url

    def test_trojan_missing_fields(self):
        assert _build_trojan_url({"server": "x.com"}) == ""


class TestBuildShadowsocks:
    """Build Shadowsocks URL from config dict."""

    def test_basic_ss(self):
        url = _build_shadowsocks_url(
            {
                "server": "ss.host",
                "port": 1080,
                "password": "secret",
                "cipher": "chacha20-ietf-poly1305",
            }
        )
        assert url.startswith("ss://")
        assert "ss.host" in url

    def test_ss_missing_password(self):
        assert _build_shadowsocks_url({"server": "x.com", "port": 1080}) == ""


class TestBuildShadowsocksR:
    """Build SSR URL from config dict."""

    def test_basic_ssr(self):
        url = _build_shadowsocksr_url(
            {
                "server": "ssr.host",
                "port": 1080,
                "password": "secret",
                "cipher": "aes-256-cfb",
            }
        )
        assert url.startswith("ssr://")

    def test_ssr_missing_fields(self):
        assert _build_shadowsocksr_url({"server": "x.com"}) == ""


class TestBuildTUIC:
    """Build TUIC URL from config dict."""

    def test_basic_tuic(self):
        url = _build_tuic_url(
            {
                "server": "tuic.host",
                "port": 443,
                "uuid": "tuic-uuid",
                "sni": "tuic.host",
            }
        )
        assert url.startswith("tuic://")
        assert "tuic.host" in url

    def test_tuic_with_password(self):
        url = _build_tuic_url(
            {
                "server": "tuic.host",
                "port": 443,
                "uuid": "uuid",
                "password": "pass",
            }
        )
        assert "uuid:pass" in url

    def test_tuic_missing_server(self):
        assert _build_tuic_url({"port": 443}) == ""


class TestBuildHysteria:
    """Build a Hysteria URL from a Clash proxy dict."""

    def test_basic_hysteria2(self):
        url = _build_hysteria_url(
            {
                "server": "hy.host",
                "port": 443,
                "auth_str": "token123",
                "type": "hysteria2",
            }
        )
        # The token belongs in the userinfo, where the hysteria2 URI scheme puts
        # it; `auth=` in the query is what no consumer of this URL reads.
        assert url == "hysteria2://token123@hy.host:443/#Hysteria2%20Config"

    def test_hysteria2_carries_only_scheme_parameters(self):
        url = _build_hysteria_url(
            {
                "server": "hy.host",
                "port": 443,
                "password": "tok",
                "type": "hysteria2",
                "sni": "hy.example.com",
                "obfs": "salamander",
                "obfs-password": "secret",
                "skip-cert-verify": True,
                "name": "node",
            }
        )
        assert url.startswith("hysteria2://tok@hy.host:443/?")
        assert "sni=hy.example.com" in url
        assert "obfs=salamander" in url
        assert "obfs-password=secret" in url
        assert "insecure=1" in url
        # `type=webtransport` was invented here and read by nothing.
        assert "webtransport" not in url

    def test_hysteria_v1_is_not_labelled_as_version_two(self):
        """xray implements v2 only, so a v1 node must arrive as v1.

        Emitted as `hysteria://`, the compatibility filter refuses it with
        "version != 2"; emitted as `hysteria2://` it would have been verified as a
        v2 node whose parameters were dropped, and reported as a dead server.
        """
        url = _build_hysteria_url(
            {
                "server": "hy1.host",
                "port": 443,
                "type": "hysteria",
                "auth_str": "a1",
                "protocol": "udp",
                "up": 100,
                "down": 200,
                "name": "v1node",
            }
        )
        assert url.startswith("hysteria://a1@hy1.host:443/?")
        assert "protocol=udp" in url
        assert "upmbps=100" in url
        assert "downmbps=200" in url

    def test_a_built_hysteria2_url_parses_into_an_xray_outbound(self):
        """The end of this converter is the start of the xray parser."""
        from utils.protocol_parsers import parse_hysteria2_to_outbound

        url = _build_hysteria_url(
            {
                "server": "hy.host",
                "port": 443,
                "auth_str": "token123",
                "type": "hysteria2",
                "sni": "hy.example.com",
                "obfs": "salamander",
                "obfs-password": "secret",
            }
        )
        outbound = parse_hysteria2_to_outbound(url)

        assert outbound is not None
        assert outbound["protocol"] == "hysteria"
        assert outbound["settings"] == {"version": 2, "address": "hy.host", "port": 443}
        assert outbound["streamSettings"]["hysteriaSettings"]["auth"] == "token123"
        assert outbound["streamSettings"]["tlsSettings"]["serverName"] == "hy.example.com"
        assert outbound["streamSettings"]["finalmask"]["udp"][0]["type"] == "salamander"

    def test_hysteria_missing_server(self):
        assert _build_hysteria_url({"port": 443}) == ""

    def test_special_characters_in_the_token_survive_the_round_trip(self):
        """A token with `@` or `/` in it must not break the URL's structure."""
        from urllib.parse import urlparse

        url = _build_hysteria_url(
            {"server": "hy.host", "port": 443, "auth_str": "a@b/c", "type": "hysteria2"}
        )
        parsed = urlparse(url)

        assert parsed.username == "a%40b%2Fc"
        assert parsed.hostname == "hy.host"
        assert parsed.port == 443


class TestTryConvertToUrl:
    """Fallback heuristic for unknown types."""

    def test_detect_vless_from_uuid_and_security(self):
        url = _try_convert_to_url(
            {
                "uuid": "u",
                "security": "tls",
                "server": "x.com",
                "port": 443,
            }
        )
        assert url.startswith("vless://")

    def test_detect_trojan_from_password_and_sni(self):
        url = _try_convert_to_url(
            {
                "password": "p",
                "sni": "x.com",
                "server": "x.com",
                "port": 443,
            }
        )
        assert url.startswith("trojan://")

    def test_detect_ss_from_cipher_and_password(self):
        url = _try_convert_to_url(
            {
                "cipher": "aes-128-gcm",
                "password": "p",
                "server": "x.com",
                "port": 443,
            }
        )
        assert url.startswith("ss://")

    def test_unrecognized_returns_empty(self):
        assert _try_convert_to_url({"name": "unknown"}) == ""


class TestConvertYaml:
    """Full YAML → VPN config conversion."""

    CLASH_YAML = """
proxies:
  - name: "🇯🇵 JP Server"
    type: vmess
    server: jp.example.com
    port: 443
    uuid: jp-uuid-123
    alterId: 0
    cipher: auto
    network: ws
    tls: true
    ws-path: /jp
    ws-headers:
      Host: jp.example.com

  - name: "🇺🇸 US Server"
    type: vless
    server: us.example.com
    port: 8443
    uuid: us-uuid-456
    network: tcp
    tls: true
    servername: us.example.com
"""

    def test_convert_clash_yaml(self):
        configs = convert_yaml_to_vpn_configs(self.CLASH_YAML)
        assert len(configs) >= 2
        # VMess config is base64-encoded in the URL; check decoded payload
        import base64

        vmess_url = [c for c in configs if c.startswith("vmess://")]
        assert len(vmess_url) >= 1
        payload = vmess_url[0][8:]
        rem = len(payload) % 4
        if rem:
            payload += "=" * (4 - rem)
        decoded = base64.b64decode(payload).decode("utf-8")
        assert "jp.example.com" in decoded or "jp" in decoded.lower(), (
            f"expected JP server in decoded vmess payload: {decoded[:200]}"
        )
        assert any("us.example.com" in c for c in configs), (
            f"expected US server, got: {configs[:2]}"
        )

    def test_empty_yaml(self):
        assert convert_yaml_to_vpn_configs("") == []

    def test_invalid_yaml(self):
        assert convert_yaml_to_vpn_configs("not: yaml: broken: [[]") == []

    def test_yaml_without_proxies(self):
        assert convert_yaml_to_vpn_configs("key: value") == []

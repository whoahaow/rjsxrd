"""Unit tests for `extract_host_port()` — the address a bypass filter matches against.

The SNI/CIDR filter and the TCP ping both read the `(host, port)` pair this function
returns, while the verifier parses the same URL through a different module. A form the
two disagree about is a node that gets tested and then dropped from the published
bypass files, so every scheme-specific encoding handled here is pinned: the vmess
JSON object, the SSR payload, the fully base64-encoded `ss://` blob, and the bracketed
IPv6 address each of them can carry.
"""

from __future__ import annotations

import base64
import ipaddress
import json

import pytest

from utils.file_utils import (
    _decode_generic_host_port,
    _decode_ssr_host_port,
    _decode_vmess_host_port,
    extract_host_port,
)

pytestmark = pytest.mark.unit


class TestExtractHostPortDispatch:
    """Test extract_host_port() refactored to use a handler dispatch table.

    Each scheme-specific handler is now a public (leading-underscore) function
    that can be tested in isolation. The dispatch table routes to the right
    handler based on the scheme prefix.
    """

    def test_vmess_handler_in_isolation(self):
        """The vmess handler is independently callable."""
        payload = base64.b64encode(b'{"add":"1.2.3.4","port":443}').decode()
        result = _decode_vmess_host_port(f"vmess://{payload}")
        assert result == ("1.2.3.4", 443)

    def test_ssr_handler_in_isolation(self):
        """The ssr handler is independently callable."""
        payload = base64.b64encode(
            b"server.com:8388:auth_aes128_md5:aes-128-cfb:auth_aes128_md5:password"
        ).decode()
        result = _decode_ssr_host_port(f"ssr://{payload}")
        assert result == ("server.com", 8388)

    def test_dispatch_routes_via_scheme_prefix(self):
        """The main extract_host_port correctly dispatches to the right handler."""
        # vless — should use generic handler
        assert extract_host_port("vless://uuid@example.com:443") == ("example.com", 443)
        # trojan — generic handler
        assert extract_host_port("trojan://pass@example.com:443") == ("example.com", 443)
        # ss — generic handler
        assert extract_host_port("ss://pass@example.com:8388") == ("example.com", 8388)

    def test_empty_input_returns_none(self):
        assert extract_host_port("") is None
        assert extract_host_port(None) is None

    def test_garbage_input_returns_none(self):
        assert extract_host_port("not-a-url") is None
        assert extract_host_port("vless://") is None
        assert extract_host_port("vmess://garbage-not-base64!!!") is None

    def test_case_insensitive_vmess_match(self):
        """VMESS:// (uppercase) now matches because the dispatch table uses
        line.lower().startswith(prefix). This fixes a pre-existing bug where
        uppercase VMESS:// URLs would silently fail to parse."""
        payload = base64.b64encode(b'{"add":"1.2.3.4","port":443}').decode()
        # Pre-fix: returned None. Post-fix: returns ("1.2.3.4", 443).
        result = extract_host_port(f"VMESS://{payload}")
        assert result == ("1.2.3.4", 443), f"uppercase VMESS should now match, got {result}"


class TestExtractHostPortEdgeCases:
    """Edge cases in the host/port extraction pipeline."""

    def test_vmess_missing_host_port_returns_none(self):
        """vmess JSON with empty add/port should return None."""
        payload = base64.b64encode(b'{"add":"","port":0,"aid":"0"}').decode()
        result = _decode_vmess_host_port(f"vmess://{payload}")
        assert result is None

    def test_vmess_invalid_json_returns_none(self):
        """vmess with malformed JSON payload returns None."""
        payload = base64.b64encode(b"not json at all").decode()
        result = _decode_vmess_host_port(f"vmess://{payload}")
        assert result is None

    def test_generic_fallback_without_at_sign(self):
        """_decode_generic_host_port with no @ and no urlparse host returns None."""
        assert _decode_generic_host_port("not-a-url") is None

    def test_extract_host_port_handles_bad_input(self):
        """extract_host_port with empty or None input returns None."""
        assert extract_host_port("") is None
        assert extract_host_port(None) is None

    def test_non_vmess_handlers_pass_through(self):
        """A vless URL should NOT trigger the vmess/ssr handlers."""
        result = extract_host_port("vless://uuid@example.com:443")
        assert result is not None
        assert result[0] == "example.com"
        assert result[1] == 443


def _b64url(payload: bytes) -> str:
    """Base64 with its padding stripped, which is how share links write it."""
    return base64.b64encode(payload).decode().rstrip("=")


def _ss_url(payload: bytes, *, pad: bool = True) -> str:
    """An `ss://` URL whose userinfo is the given payload, base64-encoded."""
    token = base64.b64encode(payload).decode()
    return "ss://" + (token if pad else token.rstrip("="))


_SS_BLOB_IPV6 = _ss_url(b"aes:pw@[2001:db8::9]:8388")
_SSR_IPV6 = "ssr://" + _b64url(b"[2001:db8::8]:8388:origin:aes-256-gcm:plain:cw")
_VMESS_IPV6 = "vmess://" + _b64url(b'{"add":"[2001:db8::7]","port":"443","id":"x"}')


class TestPortsThatAreNotPorts:
    """A handler that raises hands its exception to whoever happened to be iterating.

    `extract_host_port()` is documented to answer with a pair or None, and every caller
    treats None as "this config has no readable address". A raise is a different
    animal: `_sni_worker` swallows it and loses one config, `simple_tester` has no guard
    at all, and `verify_config_file` catches `ValueError` around the whole file and
    returns an empty result -- one line with a clash multi-port field zeroes a
    verification pass. The producers are real: `_convert_vmess_to_url` writes
    `str(config["port"])`, and clash states several ports as `"443,8443"`.
    """

    @pytest.mark.parametrize(
        "port",
        ["443,8443", "8443 443", "http", "", "0", "-1", "99999", "65536", None],
    )
    def test_vmess_answers_none_for_a_port_it_cannot_use(self, port):
        payload = _b64url(json.dumps({"add": "p.example.com", "port": port, "id": "x"}).encode())

        assert extract_host_port(f"vmess://{payload}") is None

    def test_a_vmess_port_that_is_a_number_in_a_string_still_works(self):
        payload = _b64url(json.dumps({"add": "p.example.com", "port": "2082", "id": "x"}).encode())

        assert extract_host_port(f"vmess://{payload}") == ("p.example.com", 2082)

    @pytest.mark.parametrize(
        "url",
        [
            _ss_url(b"aes-256-gcm:pw@65536.example.com:65536"),
            "ss://" + _b64url(b"aes-256-gcm:pw@p.example.com:99999"),
            "ssr://" + _b64url(b"p.example.com:70000:origin:aes-256-gcm:plain:cw"),
            "vless://12345678-1234-1234-1234-123456789012@p.example.com:70000",
        ],
    )
    def test_no_scheme_gives_a_port_above_the_wire_limit(self, url):
        """The generic path already refuses these through `urlparse.port`; the
        base64 forms read the number themselves and have to hold the same line."""
        assert extract_host_port(url) is None

    def test_the_top_of_the_range_is_still_a_port(self):
        assert extract_host_port("ss://" + _b64url(b"aes-256-gcm:pw@p.example.com:65535")) == (
            "p.example.com",
            65535,
        )


class TestEncodedShadowsocksBlob:
    """`ss://base64(method:password@host:port)` keeps its address in one token.

    With no `@` left in the URL, urlparse sees no hostname and the generic path
    returned None — so the config could never be matched against the SNI whitelist
    and dropped out of the bypass files, while the verifier parsed the same form
    without complaint (`_decode_ss_base64` in utils/protocol_parsers.py). A node
    that can be tested has to be able to be filtered.
    """

    def test_the_blob_form_reveals_its_host_and_port(self):
        url = _ss_url(b"aes-256-gcm:pass123@ss-blob.example.com:8388")

        assert extract_host_port(url) == ("ss-blob.example.com", 8388)

    def test_a_blob_without_its_padding_is_the_same_config(self):
        url = _ss_url(b"aes-256-gcm:pass123@ss-blob.example.com:8388", pad=False)

        assert extract_host_port(url) == ("ss-blob.example.com", 8388)

    def test_urlsafe_alphabet_and_a_remark_still_decode(self):
        token = base64.urlsafe_b64encode(
            b"chacha20-ietf-poly1305:a+b/c@host-a.example.com:443"
        ).decode()
        url = f"ss://{token.rstrip('=')}#%D0%9D%D0%BE%D0%B4%D0%B0"

        assert extract_host_port(url) == ("host-a.example.com", 443)

    def test_the_clear_forms_keep_using_the_generic_path(self):
        """`b64(method:password)@host:port` has the host in the open already."""
        creds = base64.b64encode(b"aes-256-gcm:pw").decode()

        assert extract_host_port(f"ss://{creds}@ss-compat.example.com:8388") == (
            "ss-compat.example.com",
            8388,
        )
        assert extract_host_port("ss://aes-256-gcm:pw@ss-plain.example.com:8388#n") == (
            "ss-plain.example.com",
            8388,
        )

    def test_a_blob_holding_no_host_is_still_no_host(self):
        # credentials only: there is no address in the blob to find
        assert extract_host_port(_ss_url(b"aes-256-gcm:pass123")) is None
        assert extract_host_port("ss://!!!not-base64!!!") is None
        # base64 that decodes, but not to anything with a host in it
        assert extract_host_port(_ss_url(b"not-an-ss-payload")) is None


class TestIPv6HostsAreReturnedBare:
    """`ipaddress.ip_address()` and the TCP ping both refuse a bracketed address.

    urlparse returns `2001:db8::1` bare, while a vmess `"add"`, a decoded SSR
    payload or an ss blob carries `[2001:db8::1]`. The same node therefore looked
    like two different hosts depending on the scheme that shipped it, and the
    bracketed one could never match the CIDR whitelist at all.
    """

    @pytest.mark.parametrize(
        "url",
        [
            "vless://uuid@[2001:db8::5]:443?security=tls",
            _SS_BLOB_IPV6,
            _SSR_IPV6,
            _VMESS_IPV6,
        ],
    )
    def test_a_bracketed_host_comes_back_without_brackets(self, url):
        host, _port = extract_host_port(url)

        assert not host.startswith("["), host
        ipaddress.ip_address(host)  # must not raise: the CIDR check does this

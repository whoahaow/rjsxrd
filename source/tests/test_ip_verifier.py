"""Tests for ip_verifier.py — proxy setup and cleanup utilities."""

import os
from unittest.mock import MagicMock, patch

import pytest

import utils.ip_verifier as ip_verifier
from utils.ip_verifier import (
    _PROXY_ENV_VARS,
    _clear_proxy_env_vars,
    _json_ip_field,
    _plain_text_body,
    _wait_for_tcp_port,
    get_proxy_ip,
    get_real_ip,
    setup_global_proxy,
    setup_proxy_chain,
    verify_protection,
)

pytestmark = pytest.mark.unit


class TestProxyEnvVarsConstant:
    """_PROXY_ENV_VARS is the single source of truth."""

    def test_constant_contains_expected_vars(self):
        assert "HTTP_PROXY" in _PROXY_ENV_VARS
        assert "HTTPS_PROXY" in _PROXY_ENV_VARS
        assert "ALL_PROXY" in _PROXY_ENV_VARS
        assert len(_PROXY_ENV_VARS) == 3

    def test_clear_removes_env_vars(self):
        os.environ["HTTP_PROXY"] = "http://test:8080"
        os.environ["HTTPS_PROXY"] = "http://test:8080"
        os.environ["ALL_PROXY"] = "http://test:8080"
        _clear_proxy_env_vars()
        for var in _PROXY_ENV_VARS:
            assert var not in os.environ, f"{var} should be cleared"

    def test_clear_no_op_when_unset(self):
        for var in _PROXY_ENV_VARS:
            os.environ.pop(var, None)
        _clear_proxy_env_vars()  # must not raise


class TestWaitForTcpPort:
    """TCP port polling utility."""

    def test_port_open_returns_true(self):
        with patch("socket.socket") as mock_socket:
            instance = MagicMock()
            instance.connect_ex.return_value = 0
            mock_socket.return_value = instance
            assert _wait_for_tcp_port("127.0.0.1", 8080, timeout=1.0) is True
            instance.connect_ex.assert_called_with(("127.0.0.1", 8080))

    def test_port_closed_returns_false(self):
        with patch("socket.socket") as mock_socket:
            instance = MagicMock()
            instance.connect_ex.return_value = 1
            mock_socket.return_value = instance
            assert _wait_for_tcp_port("127.0.0.1", 8080, timeout=0.2) is False

    def test_connection_refused_returns_false(self):
        with patch("socket.socket") as mock_socket:
            instance = MagicMock()
            instance.connect_ex.side_effect = ConnectionRefusedError()
            mock_socket.return_value = instance
            assert _wait_for_tcp_port("127.0.0.1", 8080, timeout=0.2) is False


class _FakeResponse:
    """Stand-in for the untyped curl_cffi/requests response object."""

    def __init__(self, json_payload=None, text="", json_error=None):
        self._json_payload = json_payload
        self._json_error = json_error
        self.text = text

    def json(self):
        if self._json_error is not None:
            raise self._json_error
        return self._json_payload


class TestJsonIpField:
    """The ``ip`` field is validated, not asserted.

    The HTTP clients are untyped, so a provider answering 200 with a
    non-string ``ip`` — or a body that is not a JSON object at all — must not
    leak that value out of a function declared to return ``str | None``.
    """

    def test_reads_a_string_ip(self):
        assert _json_ip_field(_FakeResponse({"ip": "203.0.113.7"})) == "203.0.113.7"

    def test_rejects_a_non_string_ip(self):
        assert _json_ip_field(_FakeResponse({"ip": 123})) is None

    def test_rejects_a_missing_ip(self):
        assert _json_ip_field(_FakeResponse({"country": "NL"})) is None

    def test_rejects_a_non_object_payload(self):
        """A JSON array body used to escape as an AttributeError."""
        assert _json_ip_field(_FakeResponse([{"ip": "203.0.113.7"}])) is None


class TestPlainTextBody:
    """The bare-text provider body is validated before it is returned."""

    def test_strips_a_string_body(self):
        assert _plain_text_body(_FakeResponse(text="  203.0.113.7\n")) == "203.0.113.7"

    def test_rejects_a_non_string_body(self):
        assert _plain_text_body(_FakeResponse(text=b"203.0.113.7")) is None


class TestIpHelpersHonourTheirReturnType:
    """The public helpers return a str or None, never whatever the provider sent."""

    def test_get_real_ip_never_returns_a_non_string(self):
        with patch("utils.ip_verifier._make_request", return_value=_FakeResponse({"ip": 123})):
            assert get_real_ip() is None

    def test_get_proxy_ip_never_returns_a_non_string(self):
        with patch("utils.ip_verifier._make_request", return_value=_FakeResponse({"ip": 123})):
            assert get_proxy_ip("socks5h://127.0.0.1:1080") is None

    def test_get_real_ip_falls_through_when_a_provider_answers_a_non_json_body(self):
        responses = [
            _FakeResponse(json_error=ValueError("not json")),
            _FakeResponse({"ip": "203.0.113.7"}),
        ]
        with patch("utils.ip_verifier._make_request", side_effect=responses):
            assert get_real_ip() == "203.0.113.7"


@pytest.fixture
def proxy_env(monkeypatch):
    """Keep a proxy-setting call from leaking env vars or saved originals."""
    for var in _PROXY_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(ip_verifier, "_original_env_vars", {})


def _ipwho_sequence(*payloads):
    """A ``_make_request`` that answers ipwho.is with ``payloads``, in order.

    Any other provider raises: the chain loop stops at the first answer it can
    read, so being asked a fallback is itself the failure. The two payloads a
    chain setup needs are the hop-1 probe (its own temporary port) and then the
    full chain — in that order.
    """
    remaining = list(payloads)

    def response_for(url, **kwargs):
        assert "ipwho.is" in url, f"{url} should not be asked: the first provider answered"
        assert remaining, f"{url} was asked more times than the test provides payloads"
        return _FakeResponse(remaining.pop(0))

    return response_for


CHAIN_URLS = [
    "vless://user@a.example:443?security=tls",
    "vless://user@b.example:443?security=tls",
]


class TestValidatedJsonFields:
    """A JSON body is validated before any field is read out of it.

    Both HTTP clients are untyped, so a provider answering 200 with an array, a
    scalar, or an ``asn`` that is not an object used to escape as an
    ``AttributeError`` naming neither the provider nor the call site. Every read
    of a JSON body goes through one of these readers instead.
    """

    def test_reads_a_string_field(self):
        assert ip_verifier._json_str_field(_FakeResponse({"country": "NL"}), "country") == "NL"

    def test_rejects_a_non_string_field(self):
        assert ip_verifier._json_str_field(_FakeResponse({"country": 31}), "country") is None

    def test_rejects_a_missing_field(self):
        response = _FakeResponse({"ip": "203.0.113.7"})
        assert ip_verifier._json_str_field(response, "country") is None

    def test_rejects_an_array_body(self):
        assert ip_verifier._json_str_field(_FakeResponse([{"country": "NL"}]), "country") is None

    def test_rejects_a_scalar_body(self):
        assert ip_verifier._json_str_field(_FakeResponse("203.0.113.7"), "country") is None

    def test_reads_a_nested_string_field(self):
        response = _FakeResponse({"asn": {"org": "Example AS"}})
        assert ip_verifier._json_nested_str_field(response, "asn", "org") == "Example AS"

    def test_rejects_a_nested_field_whose_parent_is_not_an_object(self):
        """``"asn": "AS64500"`` is a non-answer, not a crash."""
        response = _FakeResponse({"asn": "AS64500"})
        assert ip_verifier._json_nested_str_field(response, "asn", "org") is None

    def test_rejects_a_nested_field_on_a_non_object_body(self):
        assert ip_verifier._json_nested_str_field(_FakeResponse([]), "asn", "org") is None

    def test_an_absent_org_reads_as_the_empty_string(self):
        """``asn.org`` has always been reported as "" when there is none."""
        assert ip_verifier._json_org_field(_FakeResponse({"ip": "203.0.113.7"})) == ""


class TestVerifyProtectionCountryReadIsValidated:
    """``verify_protection`` reads the country through the validator.

    The path runs on every run without ``--no-proxy-check``; what fails is a
    provider answering with something that is not a JSON object, which used to
    escape the function as an ``AttributeError`` that neither the inner
    ``:115`` tuple nor the outer ``:122`` tuple names.
    """

    def test_an_array_payload_reads_as_no_country(self):
        response = _FakeResponse([{"ip": "203.0.113.7", "country": "NL"}])
        with patch("utils.ip_verifier._make_request", return_value=response):
            result = verify_protection(proxy_port=1080, timeout=5.0)
        assert result["country"] is None
        assert result["error"] is None

    def test_a_scalar_payload_reads_as_no_country(self):
        response = _FakeResponse("203.0.113.7")
        with patch("utils.ip_verifier._make_request", return_value=response):
            result = verify_protection(proxy_port=1080, timeout=5.0)
        assert result["country"] is None
        assert result["error"] is None

    def test_a_well_formed_payload_still_reads_its_country(self):
        """The validator must not change a provider that answers properly."""
        response = _FakeResponse({"ip": "203.0.113.7", "country": "NL"})
        with patch("utils.ip_verifier._make_request", return_value=response):
            result = verify_protection(proxy_port=1080, timeout=5.0)
        assert result["country"] == "NL"
        assert result["error"] is None


class TestSetupGlobalProxyCountryReadIsValidated:
    """Both country reads in ``setup_global_proxy`` go through the validator.

    One per branch — the SOCKS/HTTP URL branch and the raw-protocol branch,
    which differ only in how the proxy is started. Neither enclosing ``except``
    names ``AttributeError``, so a non-object body used to end the call outright
    with an exception instead of a reported result.
    """

    def test_socks_branch_survives_an_array_payload(self, proxy_env):
        response = _FakeResponse([{"ip": "203.0.113.7"}])
        with patch("utils.ip_verifier._make_request", return_value=response):
            result = setup_global_proxy("socks5://127.0.0.1:1080", timeout=5.0)
        assert result["country"] is None
        assert result["error"] is None

    def test_protocol_branch_survives_a_scalar_payload(self, proxy_env):
        tester = MagicMock()
        tester.create_single_outbound_config.return_value = {"inbounds": []}
        tester.start_xray_instance.return_value = (True, MagicMock(), None)
        with (
            patch("utils.ip_verifier._make_request", return_value=_FakeResponse("203.0.113.7")),
            patch("utils.ip_verifier._wait_for_tcp_port", return_value=True),
            patch("utils.download_xray.ensure_xray_installed", return_value="xray.exe"),
            patch("utils.xray_tester.XrayTester", return_value=tester),
        ):
            result = setup_global_proxy("vless://user@a.example:443?security=tls", timeout=5.0)
        assert result["country"] is None
        assert result["error"] is None


class TestSetupProxyChainReadsAreValidated:
    """Every IP-check read in ``setup_proxy_chain`` goes through a validator.

    The core is stubbed where it is not under test: ``ensure_xray_installed``,
    ``XrayTester`` and the port wait answer as if Xray had started, leaving the
    HTTP reads and the loop that consumes them as the real behaviour.
    """

    @pytest.fixture
    def chain_seams(self, monkeypatch):
        tester = MagicMock()
        tester.create_chain_config.return_value = {"inbounds": []}
        tester.create_single_outbound_config.return_value = {"inbounds": []}
        tester.start_xray_instance.return_value = (True, MagicMock(), None)
        monkeypatch.setattr(ip_verifier, "get_real_ip", lambda timeout=5.0: "198.51.100.10")
        monkeypatch.setattr(ip_verifier, "_wait_for_tcp_port", lambda *args, **kwargs: True)
        monkeypatch.setattr("utils.download_xray.ensure_xray_installed", lambda: "xray.exe")
        monkeypatch.setattr("utils.xray_tester.XrayTester", lambda *args, **kwargs: tester)
        # The hop-1 details read goes through `requests.get` directly, so it is
        # stubbed here rather than left to reach the network.
        monkeypatch.setattr(
            ip_verifier.requests,
            "get",
            lambda *args, **kwargs: _FakeResponse(
                {"ip": "198.51.100.5", "country": "Hopland", "asn": {"org": "Example AS"}}
            ),
        )
        return tester

    def test_a_provider_answering_a_non_object_body_is_skipped(self, chain_seams, proxy_env):
        """A body no validator can read is a provider that failed."""

        def response_for(url, **kwargs):
            if "ipwho.is" in url:
                return _FakeResponse([{"ip": "203.0.113.7"}])
            if "ipify" in url:
                return _FakeResponse("203.0.113.7")
            return _FakeResponse(json_payload=None, text="203.0.113.9\n")

        with patch("utils.ip_verifier._make_request", side_effect=response_for):
            result = setup_proxy_chain(CHAIN_URLS, timeout=5.0)

        assert result["proxy_ip"] == "203.0.113.9"
        assert result["error"] is None

    def test_no_provider_naming_an_ip_is_a_reportable_failure(self, chain_seams, proxy_env):
        """Three non-answers are the documented error, not a silent success."""

        def response_for(url, **kwargs):
            if "ipwho.is" in url:
                return _FakeResponse([])
            if "ipify" in url:
                return _FakeResponse(7)
            return _FakeResponse(json_payload=None, text="   ")

        with patch("utils.ip_verifier._make_request", side_effect=response_for):
            result = setup_proxy_chain(CHAIN_URLS, timeout=5.0)

        assert result["active"] is False
        assert result["proxy_ip"] is None
        assert result["error"] == "Failed to get IP through proxy chain"

    def test_a_well_formed_payload_still_yields_its_fields(self, chain_seams, proxy_env):
        """The validator must not change a provider that answers properly."""
        answers = _ipwho_sequence(
            {"ip": "198.51.100.5", "country": "Hopland"},
            {"ip": "203.0.113.7", "country": "NL", "asn": {"org": "Example AS"}},
        )
        with patch("utils.ip_verifier._make_request", side_effect=answers):
            result = setup_proxy_chain(CHAIN_URLS, timeout=5.0)

        assert result["proxy_ip"] == "203.0.113.7"
        assert result["country"] == "NL"
        assert result["asn"] == "Example AS"
        assert result["error"] is None

    def test_an_asn_that_is_not_an_object_reads_as_the_empty_org(self, chain_seams, proxy_env):
        """The nested read is the one that cannot survive a scalar ``asn``."""
        answers = _ipwho_sequence(
            {"ip": "198.51.100.5", "country": "Hopland"},
            {"ip": "203.0.113.7", "country": "NL", "asn": "AS64500"},
        )
        with patch("utils.ip_verifier._make_request", side_effect=answers):
            result = setup_proxy_chain(CHAIN_URLS, timeout=5.0)

        assert result["country"] == "NL"
        assert result["asn"] == ""
        assert result["error"] is None

    def test_a_payload_without_an_asn_still_reports_the_empty_org(self, chain_seams, proxy_env):
        """The pre-fix read defaulted to "" here; the validator must keep that."""
        answers = _ipwho_sequence(
            {"ip": "198.51.100.5", "country": "Hopland"},
            {"ip": "203.0.113.7", "country": "NL"},
        )
        with patch("utils.ip_verifier._make_request", side_effect=answers):
            result = setup_proxy_chain(CHAIN_URLS, timeout=5.0)

        assert result["asn"] == ""
        assert result["error"] is None

    def test_hop1_details_survive_an_asn_that_is_not_an_object(self, chain_seams, proxy_env):
        """The hop-1 log read is the same nested read, in a logged-skip path."""
        answers = _ipwho_sequence(
            {"ip": "198.51.100.5", "country": "Hopland"},
            {"ip": "203.0.113.7", "country": "NL", "asn": {"org": "Example AS"}},
        )
        hop1 = _FakeResponse({"ip": "198.51.100.5", "country": "Hopland", "asn": "AS64500"})
        with (
            patch("utils.ip_verifier._make_request", side_effect=answers),
            patch("utils.ip_verifier.requests.get", return_value=hop1),
        ):
            result = setup_proxy_chain(CHAIN_URLS, timeout=5.0)

        assert result["active"] is True
        assert result["error"] is None

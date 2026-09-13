"""Tests for ip_verifier.py — proxy setup and cleanup utilities."""

import os
from unittest.mock import MagicMock, patch

import pytest

from utils.ip_verifier import (
    _PROXY_ENV_VARS,
    _clear_proxy_env_vars,
    _json_ip_field,
    _plain_text_body,
    _wait_for_tcp_port,
    get_proxy_ip,
    get_real_ip,
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

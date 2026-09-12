"""Tests for ip_verifier.py — proxy setup and cleanup utilities."""

import os
from unittest.mock import MagicMock, patch

from utils.ip_verifier import (
    _PROXY_ENV_VARS,
    _clear_proxy_env_vars,
    _wait_for_tcp_port,
)


class TestProxyEnvVarsConstant:
    """_PROXY_ENV_VARS is the single source of truth."""

    def test_constant_contains_expected_vars(self):
        assert 'HTTP_PROXY' in _PROXY_ENV_VARS
        assert 'HTTPS_PROXY' in _PROXY_ENV_VARS
        assert 'ALL_PROXY' in _PROXY_ENV_VARS
        assert len(_PROXY_ENV_VARS) == 3

    def test_clear_removes_env_vars(self):
        os.environ['HTTP_PROXY'] = 'http://test:8080'
        os.environ['HTTPS_PROXY'] = 'http://test:8080'
        os.environ['ALL_PROXY'] = 'http://test:8080'
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
        with patch('socket.socket') as mock_socket:
            instance = MagicMock()
            instance.connect_ex.return_value = 0
            mock_socket.return_value = instance
            assert _wait_for_tcp_port('127.0.0.1', 8080, timeout=1.0) is True
            instance.connect_ex.assert_called_with(('127.0.0.1', 8080))

    def test_port_closed_returns_false(self):
        with patch('socket.socket') as mock_socket:
            instance = MagicMock()
            instance.connect_ex.return_value = 1
            mock_socket.return_value = instance
            assert _wait_for_tcp_port('127.0.0.1', 8080, timeout=0.2) is False

    def test_connection_refused_returns_false(self):
        with patch('socket.socket') as mock_socket:
            instance = MagicMock()
            instance.connect_ex.side_effect = ConnectionRefusedError()
            mock_socket.return_value = instance
            assert _wait_for_tcp_port('127.0.0.1', 8080, timeout=0.2) is False

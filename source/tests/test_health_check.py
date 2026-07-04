"""Tests for health_check.py — internet connectivity and system health checks."""

import sys
import os
from unittest.mock import patch

from utils.health_check import (
    check_internet_connectivity, health_check,
    check_disk_space, check_memory, check_xray_binary, check_github_token,
    DNS_SERVERS, CHECK_INTERNET_TIMEOUT,
)


class TestDNSServers:
    """DNS_SERVERS constant is configured correctly."""

    def test_first_server_is_cloudflare(self):
        """Primary DNS should be Cloudflare (1.1.1.1)."""
        assert DNS_SERVERS[0] == ("1.1.1.1", 53)

    def test_google_dns_is_fallback(self):
        """Google DNS (8.8.8.8) should be the first fallback."""
        assert DNS_SERVERS[1] == ("8.8.8.8", 53)

    def test_at_least_three_servers(self):
        """Should have at least 3 DNS servers for redundancy."""
        assert len(DNS_SERVERS) >= 3

    def test_all_servers_on_port_53(self):
        """All DNS servers should use standard DNS port."""
        for host, port in DNS_SERVERS:
            assert port == 53, f"{host} uses non-standard port {port}"

    def test_no_duplicates(self):
        """No duplicate (host, port) pairs."""
        assert len(DNS_SERVERS) == len(set(DNS_SERVERS))

    def test_timeout_is_reasonable(self):
        """Timeout should be between 0.5 and 10 seconds."""
        assert 0.5 <= CHECK_INTERNET_TIMEOUT <= 10.0


class TestCheckInternetConnectivity:
    """Internet connectivity check with DNS fallback."""

    def test_first_server_success(self):
        """Should return True when first DNS server responds."""
        with patch('utils.health_check.socket.create_connection') as mock_conn:
            mock_conn.return_value = object()  # fake socket

            result = check_internet_connectivity()

            assert result is True
            # Should only try the first server
            assert mock_conn.call_count == 1
            args, _ = mock_conn.call_args
            assert args[0] == DNS_SERVERS[0]

    def test_fallback_to_second_server(self):
        """Should try next server when first fails."""
        with patch('utils.health_check.socket.create_connection') as mock_conn:
            # First call raises, second succeeds
            mock_conn.side_effect = [OSError("timeout"), object()]

            result = check_internet_connectivity()

            assert result is True
            assert mock_conn.call_count == 2

    def test_all_servers_fail(self):
        """Should return False when all DNS servers are unreachable."""
        with patch('utils.health_check.socket.create_connection') as mock_conn:
            mock_conn.side_effect = OSError("connection refused")

            result = check_internet_connectivity()

            assert result is False
            assert mock_conn.call_count == len(DNS_SERVERS)

    def test_third_server_succeeds_after_two_failures(self):
        """Should fall through multiple failures before finding a working server."""
        with patch('utils.health_check.socket.create_connection') as mock_conn:
            mock_conn.side_effect = [
                OSError("first failed"),
                OSError("second failed"),
                object(),  # third succeeds
            ]

            result = check_internet_connectivity()

            assert result is True
            assert mock_conn.call_count == 3

    def test_uses_default_timeout_per_server(self):
        """Each probe should use CHECK_INTERNET_TIMEOUT."""
        with patch('utils.health_check.socket.create_connection') as mock_conn:
            mock_conn.side_effect = OSError("fail")

            check_internet_connectivity()

            for call_args, _ in mock_conn.call_args_list:
                _host_port, kwargs = mock_conn.call_args_list[0]
                assert kwargs.get('timeout') == CHECK_INTERNET_TIMEOUT


class TestCheckDiskSpace:
    """Disk space check."""

    def test_success(self):
        has_space, _ = check_disk_space()
        assert isinstance(has_space, bool)

    def test_returns_available_mb(self):
        _, available = check_disk_space()
        assert isinstance(available, (int, float))


class TestCheckMemory:
    """Memory check."""

    def test_returns_bool_and_value(self):
        ok, mb = check_memory()
        assert isinstance(ok, bool)
        assert isinstance(mb, (int, float))


class TestCheckXrayBinary:
    """Xray binary check."""

    def test_non_existent_path(self):
        assert check_xray_binary("/nonexistent/xray") is False


class TestCheckGithubToken:
    """GitHub token validation."""

    def test_empty_token(self):
        assert check_github_token("") is False

    def test_short_token(self):
        assert check_github_token("abc") is False

    def test_min_length_token(self):
        assert check_github_token("x" * 10) is True

    def test_none_token(self):
        assert check_github_token(None) is False


class TestHealthCheck:
    """Combined health_check function."""

    def test_returns_dict_with_expected_keys(self):
        results = health_check()
        expected_keys = {'internet', 'disk_space', 'memory',
                         'xray_installed', 'github_token'}
        assert expected_keys.issubset(results.keys()), (
            f"Missing keys: {expected_keys - set(results.keys())}"
        )

    def test_all_keys_are_bool(self):
        results = health_check()
        for key, value in results.items():
            assert isinstance(value, bool), f"{key} is not bool: {type(value)}"

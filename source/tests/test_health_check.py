"""Tests for health_check.py — internet connectivity and system health checks."""

from unittest.mock import MagicMock, patch

import pytest

from utils.health_check import (
    CHECK_INTERNET_TIMEOUT,
    DNS_SERVERS,
    check_disk_space,
    check_github_token,
    check_internet_connectivity,
    check_memory,
    check_xray_binary,
    check_xray_version,
    health_check,
)

pytestmark = pytest.mark.unit


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
        with patch("utils.health_check.socket.create_connection") as mock_conn:
            mock_conn.return_value = MagicMock()  # fake socket

            result = check_internet_connectivity()

            assert result is True
            # Should only try the first server
            assert mock_conn.call_count == 1
            args, _ = mock_conn.call_args
            assert args[0] == DNS_SERVERS[0]

    def test_fallback_to_second_server(self):
        """Should try next server when first fails."""
        with patch("utils.health_check.socket.create_connection") as mock_conn:
            # First call raises, second succeeds
            mock_conn.side_effect = [OSError("timeout"), MagicMock()]

            result = check_internet_connectivity()

            assert result is True
            assert mock_conn.call_count == 2

    def test_all_servers_fail(self):
        """Should return False when all DNS servers are unreachable."""
        with patch("utils.health_check.socket.create_connection") as mock_conn:
            mock_conn.side_effect = OSError("connection refused")

            result = check_internet_connectivity()

            assert result is False
            assert mock_conn.call_count == len(DNS_SERVERS)

    def test_third_server_succeeds_after_two_failures(self):
        """Should fall through multiple failures before finding a working server."""
        with patch("utils.health_check.socket.create_connection") as mock_conn:
            mock_conn.side_effect = [
                OSError("first failed"),
                OSError("second failed"),
                MagicMock(),  # third succeeds
            ]

            result = check_internet_connectivity()

            assert result is True
            assert mock_conn.call_count == 3

    def test_closes_the_probe_socket_on_success(self):
        """A successful probe must close its socket, not drop it."""
        with patch("utils.health_check.socket.create_connection") as mock_conn:
            probe = MagicMock()
            mock_conn.return_value = probe

            result = check_internet_connectivity()

            assert result is True
            probe.close.assert_called_once_with()

    def test_uses_default_timeout_per_server(self):
        """Each probe should use CHECK_INTERNET_TIMEOUT."""
        with patch("utils.health_check.socket.create_connection") as mock_conn:
            mock_conn.side_effect = OSError("fail")

            check_internet_connectivity()

            for _host_port, kwargs in mock_conn.call_args_list:
                assert kwargs.get("timeout") == CHECK_INTERNET_TIMEOUT


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

    @pytest.fixture(autouse=True)
    def _stub_dns_probe(self, monkeypatch):
        """Keep this class offline — health_check() probes a DNS server.

        These tests assert the shape of the returned dict, not the probe, so
        the probe is stubbed. Without the stub the module's `unit` marker
        would be false: `pytest -m unit` would open a real TCP connection.
        """
        monkeypatch.setattr("utils.health_check.socket.create_connection", MagicMock())

    def test_returns_dict_with_expected_keys(self):
        results = health_check()
        expected_keys = {"internet", "disk_space", "memory", "xray_installed", "github_token"}
        assert expected_keys.issubset(results.keys()), (
            f"Missing keys: {expected_keys - set(results.keys())}"
        )

    def test_all_keys_are_bool(self):
        results = health_check()
        for key, value in results.items():
            assert isinstance(value, bool), f"{key} is not bool: {type(value)}"


class TestCheckXrayVersion:
    """What the run logs about the xray build it is verifying with.

    The compatibility rules and the outbound shapes were read from one release of
    xray-core; the binary comes from `releases/latest` unless `XRAY_VERSION` pins
    it. When those two stop being the same program, a renamed field or a deleted
    transport changes what is published while every rule keeps refusing on a reading
    nobody re-checked — so the log has to carry the version of the run that drifted.

    Offline: `xray version` is a subprocess, and it is stubbed here. The assertion
    is about the message, not the probe.
    """

    @staticmethod
    def _stub_probe(monkeypatch, version):
        monkeypatch.setattr("utils.download_xray.get_current_xray_version", lambda path: version)

    def test_the_pinned_release_logs_no_warning(self, monkeypatch):
        from utils.xray_compat import RULES_VERIFIED_AGAINST

        self._stub_probe(monkeypatch, RULES_VERIFIED_AGAINST)
        with patch("utils.health_check.log") as logged:
            version = check_xray_version("/nonexistent/xray")

        assert version == RULES_VERIFIED_AGAINST
        lines = [call.args[0] for call in logged.call_args_list]
        assert not [line for line in lines if line.startswith("WARNING")], lines

    def test_a_newer_binary_is_named_against_the_rules(self, monkeypatch):
        from utils.xray_compat import RULES_VERIFIED_AGAINST

        self._stub_probe(monkeypatch, "v26.9.9")
        with patch("utils.health_check.log") as logged:
            assert check_xray_version("/nonexistent/xray") == "v26.9.9"

        warning = [c.args[0] for c in logged.call_args_list if c.args[0].startswith("WARNING")]
        assert len(warning) == 1, warning
        assert "v26.9.9" in warning[0] and RULES_VERIFIED_AGAINST in warning[0]
        assert "XRAY_VERSION" in warning[0]

    def test_an_older_binary_is_warned_about_separately(self, monkeypatch):
        self._stub_probe(monkeypatch, "v1.0.0")
        with patch("utils.health_check.log") as logged:
            check_xray_version("/nonexistent/xray")

        warning = [c.args[0] for c in logged.call_args_list if c.args[0].startswith("WARNING")]
        assert len(warning) == 1 and "older" in warning[0], warning

    def test_an_unreadable_version_is_still_reported(self, monkeypatch):
        """Silence is the failure mode: an unknown version means invisible drift."""
        self._stub_probe(monkeypatch, None)
        with patch("utils.health_check.log") as logged:
            assert check_xray_version("/nonexistent/xray") is None

        warning = [c.args[0] for c in logged.call_args_list if c.args[0].startswith("WARNING")]
        assert len(warning) == 1 and "unknown" in warning[0], warning

    def test_health_check_does_not_probe_a_missing_binary(self, monkeypatch):
        """No path, or a path that is not executable: nothing to ask for a version."""
        called = []
        monkeypatch.setattr("utils.health_check.check_xray_version", called.append)

        with patch("utils.health_check.socket.create_connection", MagicMock()):
            health_check()
            assert not called

            missing = "/definitely/not/here/xray"
            assert check_xray_binary(missing) is False
            health_check(xray_path=missing)
            assert not called

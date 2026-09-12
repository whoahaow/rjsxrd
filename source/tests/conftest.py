"""Pytest configuration and fixtures."""

import os
import sys

import pytest

# Add source directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture(scope="session")
def sample_vless_config():
    """Sample VLESS config for testing."""
    return "vless://55555555-5555-5555-5555-555555555555@example.com:443?security=tls&fp=chrome#Sample-VLESS"


@pytest.fixture(scope="session")
def sample_vmess_config():
    """Sample VMess config for testing."""
    # Base64 encoded JSON: {"add":"example.com","aid":"0","id":"55555555-5555-5555-5555-555555555555","net":"ws","port":"443","ps":"Sample-VMess","tls":"tls","v":"2"}
    return "vmess://eyJhZGQiOiJleGFtcGxlLmNvbSIsImFpZCI6IjAiLCJpZCI6IjU1NTU1NTU1LTU1NTUtNTU1NS01NTU1LTU1NTU1NTU1NTU1NSIsIm5ldCI6IndzIiwicG9ydCI6IjQ0MyIsInBzIjoiU2FtcGxlLVZNZXNzIiwidGxzIjoidGxzIiwidiI6IjIifQ=="


@pytest.fixture(scope="session")
def sample_trojan_config():
    """Sample Trojan config for testing."""
    return "trojan://password123@example.com:443?security=tls&sni=example.com#Sample-Trojan"


@pytest.fixture(scope="session")
def sample_ss_config():
    """Sample Shadowsocks config for testing."""
    # Base64 encoded: aes-256-gcm:password123
    return "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQxMjM=@example.com:8388#Sample-SS"


@pytest.fixture(scope="session")
def mixed_config_list(sample_vless_config, sample_vmess_config, sample_trojan_config):
    """Mixed list of configs for testing."""
    return [
        sample_vless_config,
        sample_vmess_config,
        sample_trojan_config,
        "invalid text",
        "# Comment line",
        "",
        "ss://YWVzLTI1Ni1nY206cGFzcw==@host.com:8388#tag",
    ]


@pytest.fixture(scope="session")
def sample_mtproto_proxy():
    """Sample MTProto proxy for testing."""
    return "https://t.me/proxy?server=1.2.3.4&port=443&secret=dd000000000000000000000000000000"


@pytest.fixture(scope="session")
def sample_socks5_proxy():
    """Sample SOCKS5 proxy for testing."""
    return "https://t.me/socks?server=proxy.example.com&port=1080&user=admin&pass=secret"


@pytest.fixture
def temp_file(tmp_path):
    """Create a temporary file."""
    file_path = tmp_path / "test_file.txt"
    yield file_path
    # Cleanup happens automatically with tmp_path


@pytest.fixture
def mock_logger():
    """Mock logger for testing."""
    from unittest.mock import MagicMock

    mock_log = MagicMock()
    return mock_log

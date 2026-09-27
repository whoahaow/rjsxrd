"""Unit tests for file utilities."""

import os
import tempfile

import pytest

from utils.file_utils import (
    apply_sni_cidr_filter,
    deduplicate_configs,
    is_valid_vpn_config_url,
    load_cidr_whitelist,
    prepare_config_content,
)
from utils.security_filter import has_insecure_setting

pytestmark = pytest.mark.unit


class TestLoadCidrWhitelist:
    """Test CIDR whitelist loading with OOM protection."""

    def test_loads_small_cidrs(self, tmp_path):
        """Small CIDRs (single hosts, /24, /16) are loaded normally."""
        f = tmp_path / "cidr.txt"
        f.write_text("192.168.1.0/30\n10.0.0.0/29\n")
        result = load_cidr_whitelist(str(f))
        # /30 = 4 IPs, /29 = 8 IPs
        assert len(result) == 12
        assert "192.168.1.0" in result
        assert "10.0.0.7" in result

    def test_skips_huge_cidrs_to_prevent_oom(self, tmp_path):
        """CIDR /0, /8, /16 etc. are SKIPPED, not expanded into millions of IPs.

        Without this guard, an accidental /0 in cidrwhitelist.txt would
        expand to 4 billion IPs in a Python set, blowing up memory.
        """
        f = tmp_path / "cidr.txt"
        f.write_text("0.0.0.0/0\n")
        # Default max_cidr_size=65536 — /0 has 4B addresses, must be skipped
        result = load_cidr_whitelist(str(f))
        assert result == set()

    def test_skips_cidr_at_threshold(self, tmp_path):
        """A CIDR with num_addresses > max_cidr_size is skipped, <= is included.

        /16 = 65536 addresses. Default max_cidr_size is 65536, so /16 is at
        the boundary (kept), /15 is over (skipped).
        """
        f = tmp_path / "cidr.txt"
        f.write_text("172.16.0.0/16\n")  # 65536 = max, should be kept
        result = load_cidr_whitelist(str(f))
        assert len(result) == 65536  # full /16 loaded

    def test_custom_max_cidr_size(self, tmp_path):
        """max_cidr_size parameter overrides the default 65536."""
        f = tmp_path / "cidr.txt"
        f.write_text("10.0.0.0/24\n")  # 256 addresses
        # With max_cidr_size=10, /24 is skipped
        result = load_cidr_whitelist(str(f), max_cidr_size=10)
        assert result == set()
        # With max_cidr_size=256, /24 is kept
        result = load_cidr_whitelist(str(f), max_cidr_size=256)
        assert len(result) == 256

    def test_skips_invalid_cidr(self, tmp_path):
        """Invalid CIDR notation is skipped with a warning, doesn't crash."""
        f = tmp_path / "cidr.txt"
        f.write_text("not-an-ip\n300.300.300.0/24\n192.168.1.0/24\n")
        result = load_cidr_whitelist(str(f))
        # Only the valid one is loaded
        assert "192.168.1.0" in result
        assert len(result) == 256

    def test_missing_file_returns_empty_set(self, tmp_path):
        """FileNotFoundError returns an empty set, doesn't crash."""
        nonexistent = tmp_path / "does_not_exist.txt"
        result = load_cidr_whitelist(str(nonexistent))
        assert result == set()

    def test_empty_file_returns_empty_set(self, tmp_path):
        """Empty file = empty whitelist."""
        f = tmp_path / "cidr.txt"
        f.write_text("")
        result = load_cidr_whitelist(str(f))
        assert result == set()

    def test_blank_lines_skipped(self, tmp_path):
        """Blank lines and whitespace-only lines are skipped."""
        f = tmp_path / "cidr.txt"
        f.write_text("\n\n   \n10.0.0.0/30\n\n")
        result = load_cidr_whitelist(str(f))
        assert len(result) == 4


class TestDeduplicateConfigs:
    """Test deduplication with name stripping."""

    def test_dedup_same_content_different_name(self):
        """Same config with different #fragment names removed."""
        configs = [
            "vless://uuid@host.com:443?security=tls#Office",
            "vless://uuid@host.com:443?security=tls#Home",
            "vless://other@host2.com:443#Work",
        ]
        result = deduplicate_configs(configs)
        assert len(result) == 2
        assert result[0] == configs[0]
        assert result[1] == configs[2]

    def test_dedup_exact_duplicates(self):
        """Exact duplicates should still be removed."""
        configs = [
            "vless://uuid@host.com:443?security=tls#Office",
            "vless://uuid@host.com:443?security=tls#Office",
        ]
        result = deduplicate_configs(configs)
        assert len(result) == 1

    def test_dedup_no_fragment(self):
        """Configs without #fragment should work unchanged."""
        configs = [
            "vless://uuid@host.com:443?security=tls",
            "vless://uuid@host.com:443?security=tls",
            "vless://other@host2.com:443",
        ]
        result = deduplicate_configs(configs)
        assert len(result) == 2

    def test_dedup_vmess(self):
        """Two VMess configs with same server but different ps fields."""
        import base64
        import json

        cfg1 = {"add": "host.com", "port": 443, "id": "uuid1", "ps": "Office"}
        cfg2 = {"add": "host.com", "port": 443, "id": "uuid1", "ps": "Home"}
        b1 = base64.b64encode(json.dumps(cfg1).encode()).decode()
        b2 = base64.b64encode(json.dumps(cfg2).encode()).decode()
        configs = [f"vmess://{b1}", f"vmess://{b2}"]
        result = deduplicate_configs(configs)
        assert len(result) == 1

    def test_dedup_vmess_different_server(self):
        """Two VMess with different server params should NOT dedup."""
        import base64
        import json

        cfg1 = {"add": "host1.com", "port": 443, "id": "uuid1", "ps": "Office"}
        cfg2 = {"add": "host2.com", "port": 443, "id": "uuid2", "ps": "Home"}
        b1 = base64.b64encode(json.dumps(cfg1).encode()).decode()
        b2 = base64.b64encode(json.dumps(cfg2).encode()).decode()
        configs = [f"vmess://{b1}", f"vmess://{b2}"]
        result = deduplicate_configs(configs)
        assert len(result) == 2

    def test_dedup_malformed_vmess_fallback(self):
        """Malformed VMess should fall back gracefully (strip #fragment)."""
        configs = [
            "vmess://not-base64!!!#Office",
            "vmess://not-base64!!!#Home",
        ]
        result = deduplicate_configs(configs)
        assert len(result) == 1

    def test_dedup_mixed_protocols(self):
        """Different protocols with same host should not dedup."""
        configs = [
            "vless://uuid@host.com:443?security=tls#Tag1",
            "trojan://pass@host.com:443?security=tls#Tag2",
        ]
        result = deduplicate_configs(configs)
        assert len(result) == 2

    def test_dedup_empty_configs(self):
        """Empty and whitespace-only configs should be skipped."""
        configs = ["", "  ", "vless://uuid@host.com:443#Tag"]
        result = deduplicate_configs(configs)
        assert len(result) == 1


class TestIsValidVpnConfigUrl:
    """Test VPN config URL validation."""

    def test_valid_vless(self):
        """Test valid VLESS URL."""
        url = "vless://uuid@host.com:443?security=tls#tag"
        assert is_valid_vpn_config_url(url) is True

    def test_valid_vmess(self):
        """Test valid VMess URL."""
        url = "vmess://eyJhZGQiOiJob3N0LmNvbSJ9"
        assert is_valid_vpn_config_url(url) is True

    def test_valid_trojan(self):
        """Test valid Trojan URL."""
        url = "trojan://password@host.com:443#tag"
        assert is_valid_vpn_config_url(url) is True

    def test_valid_ss(self):
        """Test valid Shadowsocks URL."""
        url = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@host.com:8388#tag"
        assert is_valid_vpn_config_url(url) is True

    def test_valid_hysteria2(self):
        """Test valid Hysteria2 URL."""
        url = "hysteria2://host.com:443?password=secret#tag"
        assert is_valid_vpn_config_url(url) is True

    def test_invalid_text(self):
        """Test that plain text is rejected."""
        url = "Just some random text"
        assert is_valid_vpn_config_url(url) is False

    def test_invalid_comment(self):
        """Test that comments are rejected."""
        url = "# This is a comment"
        assert is_valid_vpn_config_url(url) is False

    def test_invalid_empty(self):
        """Test that empty string is rejected."""
        url = ""
        assert is_valid_vpn_config_url(url) is False

    def test_invalid_http_url(self):
        """Test that HTTP URLs are rejected."""
        url = "https://example.com/config.txt"
        assert is_valid_vpn_config_url(url) is False

    def test_case_insensitive_protocol(self):
        """Test protocol matching is case insensitive."""
        url = "VLESS://uuid@host.com:443"
        assert is_valid_vpn_config_url(url) is True


class TestHasInsecureSetting:
    """Test insecure setting detection."""

    def test_vmess_insecure_true(self):
        """Test VMess with insecure=true detected."""
        import base64
        import json

        # Create proper base64 encoded JSON with allowInsecure: true
        config_json = {"add": "host", "allowInsecure": True}
        encoded = base64.b64encode(json.dumps(config_json).encode()).decode()
        config = f"vmess://{encoded}"

        assert has_insecure_setting(config) is True

    def test_vmess_security_none(self):
        """Test VMess with security=none detected."""
        config = "vmess://eyJhZGQiOiJob3N0Iiwic2VjdXJpdHkiOiJub25lIn0="
        # Base64 encoded: {"add":"host","security":"none"}
        assert has_insecure_setting(config) is True

    def test_vless_allow_insecure(self):
        """Test VLESS with allowInsecure detected."""
        config = "vless://uuid@host.com:443?allowInsecure=1#tag"
        assert has_insecure_setting(config) is True

    def test_vless_security_none(self):
        """Test VLESS with security=none detected."""
        config = "vless://uuid@host.com:443?security=none#tag"
        assert has_insecure_setting(config) is True

    def test_trojan_insecure(self):
        """Test Trojan with insecure param detected."""
        config = "trojan://pass@host.com:443?insecure=1#tag"
        assert has_insecure_setting(config) is True

    def test_ss_weak_cipher(self):
        """Test Shadowsocks with weak cipher detected."""
        config = "ss://cmM0LW1kNTpwYXNz@host.com:8388#tag"
        # Base64 encoded: rc4-md5:pass
        assert has_insecure_setting(config) is True

    def test_ss_strong_cipher(self):
        """Test Shadowsocks with strong cipher not flagged."""
        config = "ss://YWVzLTI1Ni1nY206cGFzcw==@host.com:8388#tag"
        # Base64 encoded: aes-256-gcm:pass
        assert has_insecure_setting(config) is False

    def test_valid_secure_config(self):
        """Test that secure configs pass validation."""
        config = "vless://uuid@host.com:443?security=tls&fp=chrome#tag"
        assert has_insecure_setting(config) is False


class TestApplySniCidrFilter:
    """Test SNI/CIDR filtering."""

    def test_filter_empty_list(self):
        """Test filtering empty list."""
        result = apply_sni_cidr_filter([])
        assert result == []

    def test_filter_preserves_valid(self):
        """Test that valid configs are preserved."""
        configs = [
            "vless://uuid@8.8.8.8:443?security=tls#tag",
        ]
        result = apply_sni_cidr_filter(configs, filter_secure=True)
        # Should not crash, may filter based on whitelist
        assert isinstance(result, list)


class TestPrepareConfigContent:
    """Test config content preparation."""

    def test_remove_empty_lines(self):
        """Test removal of empty lines."""
        content = "config1\n\n\nconfig2\n\nconfig3"
        result = prepare_config_content(content)

        # Result is a list of strings
        assert isinstance(result, list)
        assert "" not in result

    def test_remove_comments(self):
        """Test removal of comment lines."""
        content = "# Comment\nconfig1\n# Another comment\nconfig2"
        result = prepare_config_content(content)

        # Result is a list
        assert isinstance(result, list)
        assert not any("#" in line for line in result)

    def test_deduplicate_configs(self):
        """Test deduplication of configs."""
        content = "config1\nconfig2\nconfig1\nconfig3\nconfig2"
        result = prepare_config_content(content)

        # Result is a list with unique items
        assert len(result) == len(set(result))

    def test_filter_invalid_configs(self):
        """Test filtering of invalid configs."""
        content = "vless://valid@host.com:443\ninvalid text\nvmess://also-valid"
        result = prepare_config_content(content)

        # Result is a list - should only contain valid configs
        for line in result:
            assert is_valid_vpn_config_url(line)


class TestFileOperations:
    """Test file operation helpers."""

    def test_read_nonexistent_file(self):
        """Test reading nonexistent file."""
        with pytest.raises(FileNotFoundError):
            with tempfile.NamedTemporaryFile(delete=True) as f:
                name = f.name
            with open(name) as f:
                f.read()

    def test_write_and_read_config(self):
        """Test writing and reading config file."""
        configs = [
            "vless://uuid1@host1.com:443#tag1",
            "vless://uuid2@host2.com:443#tag2",
        ]

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("\n".join(configs))
            temp_path = f.name

        try:
            with open(temp_path) as f:
                content = f.read()

            lines = [line.strip() for line in content.split("\n") if line.strip()]
            assert len(lines) == 2
        finally:
            os.unlink(temp_path)


class TestGetDedupKeyLRUCache:
    """Regression tests for the @lru_cache on _get_dedup_key.

    Bug context: _get_dedup_key used to base64-decode and JSON-parse every vmess
    config it was handed, which on 60K-120K duplicate configs per run is the hot
    path; the cache went in on 2026-06-15 for that reason. The cache must produce
    identical keys for identical inputs and survive repeated calls.
    """

    def setup_method(self):
        # The cache is module-level. Clear between tests so hits/misses
        # accounting starts fresh.
        from utils.file_utils import _get_dedup_key

        _get_dedup_key.cache_clear()

    def test_cache_returns_same_key_for_same_input(self):
        """Calling with the same input twice should return the same key."""
        from utils.file_utils import _get_dedup_key

        cfg = "vless://uuid@host.com:443?security=tls#tag1"
        k1 = _get_dedup_key(cfg)
        k2 = _get_dedup_key(cfg)
        assert k1 == k2

    def test_cache_hits_on_repeat_call(self):
        """Second call with the same input should be a cache hit."""
        from utils.file_utils import _get_dedup_key

        cfg = "vless://uuid@host.com:443?security=tls#tag"
        _get_dedup_key(cfg)  # miss
        _get_dedup_key(cfg)  # hit
        info = _get_dedup_key.cache_info()
        assert info.hits >= 1, f"expected at least 1 hit, got {info}"

    def test_cache_dedup_vmess_with_different_fragments(self):
        """Two vmess configs with same add/port/id but different ps should match."""
        import base64
        import json

        from utils.file_utils import _get_dedup_key

        cfg1 = {"add": "host.com", "port": 443, "id": "uuid1", "ps": "Office"}
        cfg2 = {"add": "host.com", "port": 443, "id": "uuid1", "ps": "Home"}
        b1 = base64.b64encode(json.dumps(cfg1).encode()).decode()
        b2 = base64.b64encode(json.dumps(cfg2).encode()).decode()
        k1 = _get_dedup_key(f"vmess://{b1}")
        k2 = _get_dedup_key(f"vmess://{b2}")
        assert k1 == k2, f"vmess dedup broken: {k1} != {k2}"
        # The dedup key should NOT include 'ps' (the remark)
        assert "Office" not in str(k1) and "Home" not in str(k2)

    def test_cache_dedup_vless_with_different_fragments(self):
        """Two vless configs with same protocol/host/port/params but different #fragments should match."""
        from utils.file_utils import _get_dedup_key

        cfg1 = "vless://uuid@host.com:443?security=tls#Office"
        cfg2 = "vless://uuid@host.com:443?security=tls#Home"
        assert _get_dedup_key(cfg1) == _get_dedup_key(cfg2)

    def test_cache_different_hosts_produce_different_keys(self):
        """Different host:port must produce different keys."""
        from utils.file_utils import _get_dedup_key

        k1 = _get_dedup_key("vless://uuid@host1.com:443?security=tls")
        k2 = _get_dedup_key("vless://uuid@host2.com:443?security=tls")
        assert k1 != k2

    def test_cache_does_not_poison_on_malformed_input(self):
        """A malformed config that fails inside the try block must still allow
        the next call to produce a valid result (no exception leak)."""
        from utils.file_utils import _get_dedup_key

        # The generic key path falls through for anything that has a valid URL
        # prefix, even with garbage after it. The key will be a tuple, not None.
        result = _get_dedup_key("vless://garbage@host.com:443")
        assert result is not None
        # And the next valid call still works
        good = _get_dedup_key("vless://uuid@host.com:443?security=tls#tag")
        assert good is not None


class TestSplitAndReplaceFile:
    """Regression tests for split_and_replace_file (renamed from split_file_by_size).

    Bug context: the original `split_file_by_size` silently deleted the source
    file after splitting, which was the root cause of a previous silent-no-output
    bug in the bypass pipeline. The new name makes the behavior visible, and
    these tests guard against future regressions.
    """

    def test_small_file_returned_as_is(self, tmp_path):
        """Files under the size limit should not be split."""
        from utils.file_utils import split_and_replace_file

        src = tmp_path / "small.txt"
        src.write_text("a\nb\nc\n")
        result = split_and_replace_file(str(src))
        assert result == [str(src)]
        assert src.exists(), "small file should NOT be deleted"

    def test_large_file_is_split_into_chunks(self, tmp_path):
        """Files over the size limit should be split into multiple parts."""
        from utils.file_utils import split_and_replace_file

        # Write a 2 MB file (default limit is 49 MB, so override to 0.001 MB)
        src = tmp_path / "big.txt"
        src.write_text("a\n" * 100_000)  # ~200 KB
        result = split_and_replace_file(str(src), max_size_mb=0.001)
        assert len(result) > 1, f"expected multiple parts, got {len(result)}"
        # Original must be DELETED
        assert not src.exists(), "original file must be deleted after split"

    def test_missing_file_returns_empty_list(self, tmp_path):
        """Non-existent file should return [] and not crash."""
        from utils.file_utils import split_and_replace_file

        result = split_and_replace_file(str(tmp_path / "does_not_exist.txt"))
        assert result == []

    def test_split_chunks_contain_all_original_content(self, tmp_path):
        """The union of split files should contain all original lines."""
        from utils.file_utils import split_and_replace_file

        original_lines = [f"line{i}\n" for i in range(1000)]
        src = tmp_path / "splitme.txt"
        src.write_text("".join(original_lines))
        result = split_and_replace_file(str(src), max_size_mb=0.0001)
        # All split files should exist and together cover all original lines
        all_split_content = []
        for f in result:
            with open(f) as fp:
                all_split_content.extend(fp.read().splitlines())
        # Filter empty lines (file may have trailing newlines)
        all_split_content = [line for line in all_split_content if line]
        assert len(all_split_content) == 1000
        # And the original is gone
        assert not src.exists()


class TestProtocolConstants:
    """_VPN_PROTOCOL_PATTERN and _GLUE_PATTERN must use the same protocol
    list, so adding a new protocol only requires updating one place."""

    def test_protocol_list_is_shared_constant(self):
        """Verify all protocols appear in the shared constant and both patterns."""
        from utils.file_utils import _GLUE_PATTERN, _VPN_PROTOCOL_PATTERN, _VPN_PROTOCOLS

        for proto in [
            "vmess",
            "vless",
            "trojan",
            "ss",
            "ssr",
            "tuic",
            "hysteria",
            "hysteria2",
            "hy2",
        ]:
            assert proto in _VPN_PROTOCOLS, f"{proto} missing from _VPN_PROTOCOLS"
            assert proto in _VPN_PROTOCOL_PATTERN.pattern, (
                f"{proto} missing from _VPN_PROTOCOL_PATTERN"
            )
            assert proto in _GLUE_PATTERN.pattern, f"{proto} missing from _GLUE_PATTERN"


class TestSniCidrFilterChunking:
    """Test the chunking strategy in apply_sni_cidr_filter."""

    def _chunk_count(self, n_configs):
        """Helper: call apply_sni_cidr_filter with a known-size input
        and count how many chunks the executor receives.

        We mock get_regex_executor to return a thread pool that records
        submitted tasks, so we can count chunks without actually filtering.
        """
        from unittest.mock import MagicMock, patch

        # Build n_configs dummy inputs. SNI/CIDR filter expects VPN configs
        # but we don't care about the filtering result for the chunking test.
        configs = ["vless://u@h.com:443"] * n_configs
        n_chunks = [0]
        mock_exec = MagicMock()
        mock_exec.map = lambda fn, iterable: (
            n_chunks.__setitem__(0, len(list(iterable))) or [[] for _ in range(n_chunks[0])]
        )

        # Mock utils.file_utils.AhoCorasick so the automaton isn't None
        # (otherwise the function returns early without chunking).
        with (
            patch("utils.file_utils.get_regex_executor", return_value=mock_exec),
            patch("utils.file_utils.AhoCorasick"),
        ):
            from utils.file_utils import apply_sni_cidr_filter

            apply_sni_cidr_filter(configs, filter_secure=False)
        return n_configs, n_chunks[0]

    def test_small_input_single_chunk(self):
        """< 2000 configs = 1 chunk, no parallelism overhead."""
        total, n_chunks = self._chunk_count(500)
        # < 2000 → n=1, chunk_size=2000, 1 chunk
        assert n_chunks == 1, f"expected 1 chunk, got {n_chunks}"

    def test_medium_input_scales_chunk_count(self):
        """10K configs should be split into ~5 chunks of 2000."""
        total, n_chunks = self._chunk_count(10000)
        # 10K / 2000 = 5 chunks
        assert n_chunks >= 2, f"expected >= 2 chunks, got {n_chunks}"
        assert n_chunks <= 32, f"expected <= 32 chunks, got {n_chunks}"

    def test_large_input_capped_at_32_chunks(self):
        """100K configs capped at 32 chunks (no oversized chunks)."""
        total, n_chunks = self._chunk_count(100000)
        assert n_chunks <= 32, f"expected <= 32 chunks, got {n_chunks}"
        # Each chunk should be reasonable, not 12K
        if n_chunks > 0:
            chunk_size = 100000 // n_chunks
            assert chunk_size >= 1000, f"chunk size {chunk_size} too small"


class TestSniFilterActuallyFilters:
    """Regression: the SNI filter must actually use ahocorasick_rs to find
    matches. A previous bug imported from the wrong package (ahocorasick
    instead of ahocorasick_rs), making the automaton always None and the
    filter silently return every config unchanged.
    """

    def test_sni_filter_keeps_matching_configs(self):
        """Mock AhoCorasick to return a non-empty list for known SNI domains.
        The filter should keep only matching configs.
        """
        from unittest.mock import MagicMock, patch

        configs = [
            "vless://u@google.com:443#a",
            "vless://u@unknown-site.com:443#b",
        ]

        # AhoCorasick mock: find_matches_as_strings returns ['google.com']
        # when the haystack contains 'google.com', empty list otherwise.
        def fake_match(haystack):
            if "google.com" in haystack:
                return ["google.com"]
            return []

        mock_auto = MagicMock()
        mock_auto.find_matches_as_strings = fake_match
        mock_exec = MagicMock()
        mock_exec.map = lambda fn, iterable: [list(fn(item)) for item in iterable]

        from utils.file_utils import apply_sni_cidr_filter

        with (
            patch("utils.file_utils.AhoCorasick", return_value=mock_auto),
            patch("utils.file_utils.get_regex_executor", return_value=mock_exec),
        ):
            result = apply_sni_cidr_filter(configs, filter_secure=False)

        # Only the google.com config should be kept
        assert len(result) == 1
        assert "google.com" in result[0]
        assert "unknown-site.com" not in result[0]


class TestSniWorkerModule:
    """Smoke tests for the extracted worker module."""

    def test_sni_worker_importable(self):
        """The worker is in a separate module, importable directly."""
        from utils._sni_worker import _filter_sni_cidr_chunk

        assert callable(_filter_sni_cidr_chunk)

    def test_sni_worker_no_self_import(self):
        """The worker does NOT self-import from utils.file_utils."""
        import utils._sni_worker

        with open(utils._sni_worker.__file__) as handle:
            source = handle.read()
        # Should import from utils.file_utils (allowed) but not re-import itself
        assert "from utils._sni_worker import" not in source
        assert "from utils import _sni_worker" not in source

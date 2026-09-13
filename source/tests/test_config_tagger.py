"""Tests for ConfigTagger — single-pass metadata collection.

ConfigTagger tags configs with protocol and source metadata on first
encounter, so downstream stages don't need to re-parse URLs.
"""

import ast
from pathlib import Path

import pytest

import utils
from utils.config_tagger import ConfigTagger

pytestmark = pytest.mark.unit


class TestPackageImportCost:
    """Importing anything under `utils` must not run imports on its behalf."""

    def test_package_init_declares_no_imports(self):
        """`utils/__init__.py` is import-free, so `utils.*` stays cheap.

        The package used to re-export GitHubHandler, which pulled PyGithub into
        every process that imported any utils module — a venv without PyGithub
        could not collect this very file. The check is static on purpose: it
        holds in any test order, unlike a `sys.modules` assertion.
        """
        tree = ast.parse(Path(utils.__file__).read_text(encoding="utf-8"))
        imports = [
            node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
        ]
        assert imports == [], (
            "utils/__init__.py must declare no imports; import from the defining module instead"
        )


class TestConfigTaggerTag:
    """Test the tag() method — core functionality."""

    def test_tag_adds_protocol(self):
        tagger = ConfigTagger()
        tagger.tag("vless://uuid@host:443", source="URLS.txt")
        assert tagger.get_protocol("vless://uuid@host:443") == "vless"

    def test_tag_extracts_protocol_from_scheme(self):
        tagger = ConfigTagger()
        tagger.tag("vmess://base64stuff", source="test")
        assert tagger.get_protocol("vmess://base64stuff") == "vmess"

    def test_tag_skips_url_without_protocol(self):
        tagger = ConfigTagger()
        tagger.tag("not-a-valid-url", source="test")
        assert tagger.get_protocol("not-a-valid-url") is None

    def test_tag_skips_empty_url(self):
        tagger = ConfigTagger()
        tagger.tag("", source="test")
        assert tagger.all_urls == []

    def test_tag_adds_source(self):
        tagger = ConfigTagger()
        tagger.tag("ss://method:pass@host:443", source="yaml")
        sources = tagger.get_sources("ss://method:pass@host:443")
        assert "yaml" in sources

    def test_tag_no_source_does_not_add(self):
        tagger = ConfigTagger()
        tagger.tag("trojan://pass@host:443")
        assert tagger.get_sources("trojan://pass@host:443") == []

    def test_tag_multiple_sources_merge(self):
        tagger = ConfigTagger()
        url = "hysteria2://auth@hy2.example.com:443"
        tagger.tag(url, source="URLS.txt")
        tagger.tag(url, source="DAILY_REPO")
        sources = tagger.get_sources(url)
        assert len(sources) == 2
        assert "URLS.txt" in sources
        assert "DAILY_REPO" in sources


class TestConfigTaggerTagBatch:
    """Test tag_batch() for bulk tagging."""

    def test_tag_batch_all_tagged(self):
        tagger = ConfigTagger()
        urls = [
            "vless://a@host:443",
            "vmess://b@host:443",
            "trojan://c@host:443",
        ]
        tagger.tag_batch(urls, source="batch_source")
        for url in urls:
            assert tagger.get_protocol(url) is not None
            assert "batch_source" in tagger.get_sources(url)

    def test_tag_batch_empty_list(self):
        tagger = ConfigTagger()
        tagger.tag_batch([], source="test")
        assert tagger.all_urls == []

    def test_tag_batch_no_source(self):
        tagger = ConfigTagger()
        urls = ["vless://a@host:443", "ss://m:p@host:1080"]
        tagger.tag_batch(urls)
        for url in urls:
            assert tagger.get_protocol(url) is not None
            assert tagger.get_sources(url) == []


class TestConfigTaggerProtocols:
    """Test the protocols() grouping method."""

    def test_protocols_groups_by_protocol(self):
        tagger = ConfigTagger()
        tagger.tag("vless://a@host:443")
        tagger.tag("vless://b@host:8443")
        tagger.tag("vmess://c@host:443")
        groups = tagger.protocols()
        assert len(groups["vless"]) == 2
        assert len(groups["vmess"]) == 1

    def test_protocols_empty_when_no_tags(self):
        tagger = ConfigTagger()
        assert tagger.protocols() == {}

    def test_protocols_case_normalized(self):
        """Protocol is always lowercased."""
        tagger = ConfigTagger()
        tagger.tag("VLess://a@host:443")
        tagger.tag("VMess://b@host:443")
        groups = tagger.protocols()
        assert "vless" in groups
        assert "vmess" in groups


class TestConfigTaggerAllUrls:
    """Test the all_urls property."""

    def test_all_urls_returns_tagged_urls(self):
        tagger = ConfigTagger()
        tagger.tag("vless://a@host:443")
        tagger.tag("ss://m:p@host:1080")
        assert len(tagger.all_urls) == 2

    def test_all_urls_empty_initially(self):
        tagger = ConfigTagger()
        assert tagger.all_urls == []


class TestConfigTaggerReset:
    """Test reset() clears all state."""

    def test_reset_clears_protocols(self):
        tagger = ConfigTagger()
        tagger.tag("vless://a@host:443", source="test")
        tagger.reset()
        assert tagger.all_urls == []
        assert tagger.protocols() == {}

    def test_reset_clears_sources(self):
        tagger = ConfigTagger()
        tagger.tag("vless://a@host:443", source="test")
        tagger.reset()
        assert tagger.get_sources("vless://a@host:443") == []

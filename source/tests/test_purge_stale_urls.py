"""Tests for scripts/purge_stale_urls.py — cache loading.

`load_cache` is declared to return a dict and `run()` immediately calls
`cache.get(...)` on it, so the payload on disk has to be validated rather than
assumed.
"""

import importlib

import pytest

pytestmark = pytest.mark.unit

purge = importlib.import_module("scripts.purge_stale_urls")


class TestLoadCache:
    """The on-disk cache is untrusted input."""

    def test_non_object_cache_loads_as_empty(self, tmp_path, monkeypatch):
        """A cache file holding a JSON array must not become the cache.

        `run()` does `cache = load_cache()` then `cache.get(cache_key)`, which
        raises `AttributeError: 'list' object has no attribute 'get'` on the
        first URL if the payload is not an object.
        """
        cache_file = tmp_path / "stale_urls_cache.json"
        cache_file.write_text('["not", "an", "object"]', encoding="utf-8")
        monkeypatch.setattr(purge, "CACHE_PATH", str(cache_file))

        assert purge.load_cache() == {}

    def test_missing_cache_file_loads_as_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr(purge, "CACHE_PATH", str(tmp_path / "absent.json"))

        assert purge.load_cache() == {}

    def test_object_cache_is_returned_unchanged(self, tmp_path, monkeypatch):
        cache_file = tmp_path / "stale_urls_cache.json"
        cache_file.write_text('{"owner/repo@main": {"date": "2026-01-01"}}', encoding="utf-8")
        monkeypatch.setattr(purge, "CACHE_PATH", str(cache_file))

        assert purge.load_cache() == {"owner/repo@main": {"date": "2026-01-01"}}

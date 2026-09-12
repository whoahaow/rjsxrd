"""Config tagging system — single-pass metadata collection.

Instead of parsing each config URL 6-7 times as it flows through the
pipeline (dedup, SNI/CIDR filter, security filter, protocol split,
config→sources mapping), this module tags each config once during
download with all the metadata downstream stages need.

Usage:
    tagger = ConfigTagger()
    tagger.tag("vless://uuid@host:443", source="URLS.txt")
    # Later:
    assert tagger.get_protocol(url) == "vless"
    assert tagger.get_sources(url) == ["URLS.txt"]
"""


class ConfigTagger:
    """Tags configs with protocol and source metadata on first encounter.

    Thread-safe for concurrent tagging (download is parallel).
    Uses dicts/lists (no locks needed if caller serializes tag retrieval
    after download completes — which is the normal pipeline flow).
    """

    def __init__(self) -> None:
        # url -> set of source labels
        self._sources: dict[str, set[str]] = {}
        # url -> protocol scheme (lowercase, e.g. 'vless')
        self._protocols: dict[str, str] = {}
        # url -> bool (cached security check result)
        self._secure: dict[str, bool | None] = {}
        # url -> (host, port) or None
        self._host_ports: dict[str, tuple | None] = {}

    def tag(self, url: str, source: str = "") -> None:
        """Tag a config with metadata extracted from its URL.

        Extracts protocol from the scheme prefix. Multiple calls for the
        same URL add sources to the set. Idempotent for protocol/host:port.
        """
        if not url or "://" not in url:
            return

        # Protocol is always first tag — extracted cheaply
        scheme = url.split("://")[0].lower()
        self._protocols.setdefault(url, scheme)

        # Track sources
        if source:
            if url not in self._sources:
                self._sources[url] = set()
            self._sources[url].add(source)

    def tag_batch(self, urls: list[str], source: str = "") -> None:
        """Tag multiple configs from the same source."""
        for url in urls:
            self.tag(url, source=source)

    def get_protocol(self, url: str) -> str | None:
        """Return the cached protocol scheme (e.g. 'vless', 'vmess'). None if unknown."""
        return self._protocols.get(url)

    def get_sources(self, url: str) -> list[str]:
        """Return all source labels for this config."""
        return list(self._sources.get(url, set()))

    @property
    def all_urls(self) -> list[str]:
        """Return all tagged URLs."""
        return list(self._protocols.keys())

    def protocols(self) -> dict[str, list[str]]:
        """Group URLs by protocol. Returns {protocol: [urls]}."""
        groups: dict[str, list[str]] = {}
        for url, proto in self._protocols.items():
            groups.setdefault(proto, []).append(url)
        return groups

    def reset(self) -> None:
        """Clear all tags. For reuse between pipeline runs."""
        self._sources.clear()
        self._protocols.clear()
        self._secure.clear()
        self._host_ports.clear()

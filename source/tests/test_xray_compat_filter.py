"""Every rule that decides whether a config is verified at all.

`filter_xray_compatible()` runs immediately before xray gets the configs, and
verification is what gates publication: a config it refuses never appears in a
verified file, however good the server behind it is. The filter also runs inside
the batch builder, where one xray process carries many configs, so a rule that
misses a genuinely broken config risks the whole batch rather than one entry.

Nothing tested it. That is how `hysteria2://` came to be refused with the reason
"hysteria2 unsupported by xray" — a protocol xray added an outbound for in
v26.1.13, on a pipeline that downloads `releases/latest` — while the same file's
docstring claimed full Hysteria2 support. A rule with no test is a claim with no
evidence, so each rule is pinned with the config shape it exists for, and the
accepted cases are pinned just as hard: removing a rule that should stay has to
fail here rather than in production.

Offline by construction: `_xray_incompatible_reason()` is a pure function over a
config string, and `filter_xray_compatible()` only partitions a list. Neither
opens a socket, resolves a name or starts xray.
"""

import pytest

from utils.xray_compat import _xray_incompatible_reason, filter_xray_compatible

pytestmark = pytest.mark.unit

HY2_URL = "hysteria2://token@hy2.example.com:443?sni=hy2.example.com"
HY2_ALIAS_URL = "hy2://token@hy2.example.com:443"
VLESS_OK = "vless://12345678-1234-1234-1234-123456789012@v.example.com:443?security=tls"
VLESS_BAD_UUID = "vless://not-a-uuid@v.example.com:443?security=tls"
VLESS_DEAD_FLOW = (
    "vless://12345678-1234-1234-1234-123456789012@v.example.com:443?flow=xtls-rprx-direct"
)


class TestHysteria2IsVerified:
    """Hysteria2 belongs in xray today, so the filter must not refuse it."""

    @pytest.mark.parametrize("url", [HY2_URL, HY2_ALIAS_URL])
    def test_a_hysteria2_config_is_not_refused(self, url: str) -> None:
        assert _xray_incompatible_reason(url) == ""

    def test_the_filter_keeps_both_spellings_of_the_scheme(self) -> None:
        compatible, rejected = filter_xray_compatible([HY2_URL, HY2_ALIAS_URL])

        assert compatible == [HY2_URL, HY2_ALIAS_URL]
        assert rejected == []


class TestHysteriaV1IsRefused:
    """v1 is the one hysteria xray genuinely cannot load.

    `infra/conf/hysteria.go` returns "version != 2" while building the outbound,
    which is a config-load failure: in batch mode one shared xray process carries
    up to `XRAY_BATCH_SIZE` configs, so a single v1 URL would take the whole
    chunk's results down with it.
    """

    @pytest.mark.parametrize(
        "url",
        [
            "hysteria://hy1.example.com:443?protocol=udp",
            "hysteria://hy1.example.com:443?insecure=1",
            "hy1://hy1.example.com:443",
        ],
    )
    def test_a_hysteria_v1_config_is_refused_with_its_reason(self, url: str) -> None:
        reason = _xray_incompatible_reason(url)

        assert "hysteria v1" in reason
        assert "version != 2" in reason

    def test_the_filter_drops_v1_and_keeps_v2(self) -> None:
        compatible, rejected = filter_xray_compatible(
            ["hysteria://hy1.example.com:443?protocol=udp", HY2_URL]
        )

        assert compatible == [HY2_URL]
        assert [url for url, _ in rejected] == ["hysteria://hy1.example.com:443?protocol=udp"]


class TestTheRulesThatStay:
    """The refusals that are real — pinned so a hy2 fix cannot take them too.

    Each of these would parse into an outbound and then fail when xray loads the
    config, which in batch mode costs every other config sharing the process.
    """

    def test_a_malformed_uuid_is_refused(self) -> None:
        reason = _xray_incompatible_reason(VLESS_BAD_UUID)

        assert "UUID" in reason

    def test_a_flow_removed_from_xray_is_refused(self) -> None:
        assert "unsupported flow" in _xray_incompatible_reason(VLESS_DEAD_FLOW)

    def test_a_wellformed_vless_config_is_not_refused(self) -> None:
        assert _xray_incompatible_reason(VLESS_OK) == ""


class TestThePartitionIsFaithful:
    """What the caller reads: two lists, every config in exactly one of them."""

    def test_a_rejected_config_leaves_the_compatible_list_and_is_reported(self) -> None:
        compatible, rejected = filter_xray_compatible([VLESS_OK, VLESS_BAD_UUID, HY2_URL])

        assert compatible == [VLESS_OK, HY2_URL]
        assert [url for url, _ in rejected] == [VLESS_BAD_UUID]

    def test_an_empty_batch_partitions_to_two_empty_lists(self) -> None:
        """The stage runs this on a run where every source was dead."""
        assert filter_xray_compatible([]) == ([], [])

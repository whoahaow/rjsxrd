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

import base64

import pytest

from utils.xray_compat import _xray_incompatible_reason, filter_xray_compatible

pytestmark = pytest.mark.unit

HY2_URL = "hysteria2://token@hy2.example.com:443?sni=hy2.example.com"
HY2_ALIAS_URL = "hy2://token@hy2.example.com:443"
HY1_URL = "hysteria://hy1.example.com:443?protocol=udp"
HY2_INSECURE_URL = "hy2://token@hy2.example.com:443?insecure=1"
VLESS_OK = "vless://12345678-1234-1234-1234-123456789012@v.example.com:443?security=tls"
VLESS_BAD_UUID = "vless://not-a-uuid@v.example.com:443?security=tls"
VLESS_DEAD_FLOW = (
    "vless://12345678-1234-1234-1234-123456789012@v.example.com:443?flow=xtls-rprx-direct"
)

# A publicKey and a pinned certificate hash that xray actually accepts: 32 bytes
# as unpadded raw-url base64, and 32 bytes as hex. The fixtures in this file used
# to carry `pbk=key` and `pinSHA256=deadbeef`, and both of those abort xray's
# config load — a test that pinned a broken config and called it the accepted
# shape.
PBK = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
PIN_SHA256 = "bfb3e4b6547b43ffa7bd708e678442072debc4dcb470fc7b6bfe056e38e84c99"
REALITY = "vless://12345678-1234-1234-1234-123456789012@h.example.com:443?security=reality"


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


class TestAHysteria2NodeNeedingNoVerification:
    """`insecure=1` is not a setting xray has any more, so it cannot be tested.

    xray removed `allowInsecure` and replaced it with `pinnedPeerCertSha256`,
    which is what `pinSHA256=` in a hysteria2 URL maps onto. A node that asks for
    verification to be switched off with nothing to check instead has no config
    shape: it is refused by name, because the alternative is that it fails like a
    dead server and gets aged out of `URLS.txt` for a security property.
    """

    @pytest.mark.parametrize(
        "url",
        [
            "hy2://token@hy2.example.com:443?insecure=1",
            "hysteria2://token@hy2.example.com:443?insecure=true&sni=hy2.example.com",
        ],
    )
    def test_insecure_without_a_pin_is_refused(self, url: str) -> None:
        reason = _xray_incompatible_reason(url)

        assert "allowInsecure" in reason

    def test_the_same_node_with_a_pin_is_testable(self) -> None:
        """A pinned hash verifies the peer; it is not `allowInsecure`."""
        url = f"hy2://token@hy2.example.com:443?insecure=1&pinSHA256={PIN_SHA256}"

        assert _xray_incompatible_reason(url) == ""

    def test_a_pin_xray_cannot_decode_is_refused(self) -> None:
        """The hash goes through `hex.DecodeString` into 32 bytes after its colons
        are stripped, so a short value aborts the config load."""
        assert (
            _xray_incompatible_reason("hy2://token@h.example.com:443?pinSHA256=deadbeef")
            == "hysteria2 pinSHA256 is not 32 bytes of hex"
        )

    def test_a_colon_separated_pin_of_the_right_length_is_accepted(self) -> None:
        """xray strips `:` before decoding, and cert tools print the hash that way."""
        colonated = ":".join(PIN_SHA256[i : i + 2] for i in range(0, 64, 2))

        assert (
            _xray_incompatible_reason(f"hy2://token@h.example.com:443?pinSHA256={colonated}") == ""
        )

    def test_a_non_hex_pin_is_refused(self) -> None:
        reason = _xray_incompatible_reason(f"hy2://token@h.example.com:443?pinSHA256={'z' * 64}")

        assert "pinSHA256" in reason

    def test_a_verified_hysteria2_node_is_unaffected(self) -> None:
        """The rule reads the parameter, not the scheme."""
        assert _xray_incompatible_reason(HY2_URL) == ""

    def test_the_parameter_is_read_at_a_query_boundary_not_as_a_substring(self) -> None:
        """A node's name is not a setting, in either direction.

        The rule was `any(flag in cfg_lower ...)`, so a remark that happened to
        contain the text `insecure=1` refused a Hysteria2 node xray could verify --
        and, the other way round, a name carrying `pinSHA256=` excused a node that
        genuinely asks for verification off. `insecure=yes` was also missed: the
        hysteria2 spec writes the flag as a number, and every client that spells it
        out says `yes` or `true`.
        """
        named = "hy2://token@hy2.example.com:443?sni=hy2.example.com#old-insecure=1-node"
        excused = "hy2://token@hy2.example.com:443?insecure=1#see-pinSHA256=docs"

        assert _xray_incompatible_reason(named) == "", "a remark must not refuse the node"
        assert "allowInsecure" in _xray_incompatible_reason(excused)

    @pytest.mark.parametrize("flag", ["1", "true", "TRUE", "yes", "on"])
    def test_every_truthy_spelling_of_insecure_is_refused(self, flag: str) -> None:
        url = f"hy2://token@hy2.example.com:443?insecure={flag}"

        assert "allowInsecure" in _xray_incompatible_reason(url)

    @pytest.mark.parametrize("flag", ["0", "false", "no"])
    def test_a_node_that_verifies_is_testable(self, flag: str) -> None:
        url = f"hy2://token@hy2.example.com:443?insecure={flag}&sni=hy2.example.com"

        assert _xray_incompatible_reason(url) == ""

    def test_an_empty_pin_is_no_pin(self) -> None:
        """`pinSHA256=` proves the parameter exists, not that xray can check anything."""
        url = "hy2://token@hy2.example.com:443?insecure=1&pinSHA256="

        assert "allowInsecure" in _xray_incompatible_reason(url)


class TestBothModesRefuseTheSameConfig:
    """Batch and single verification must reach the same verdict for one URL.

    Batch mode applies the filter while building the shared xray config; single
    mode never gets there, so it asks through `_quick_validate_url()`. Without
    that second call site a URL is refused in one mode and reported to the error
    stats as a parse failure in the other, and which one you see depends on a
    setting that has nothing to do with the config.
    """

    @staticmethod
    def _tester():
        """An XrayTester with no xray binary: the validator is pure string work."""
        import threading

        from utils.xray_tester import XrayTester

        tester = XrayTester.__new__(XrayTester)
        tester.xray_path = None
        tester._error_stats = {}
        tester._lock = threading.Lock()
        return tester

    @pytest.mark.parametrize("url", [HY1_URL, HY2_INSECURE_URL])
    def test_single_mode_refuses_what_the_filter_refuses(self, url: str) -> None:
        tester = self._tester()
        valid, error = tester._quick_validate_url(url)

        assert valid is False
        assert error == _xray_incompatible_reason(url)

    def test_single_mode_still_accepts_a_testable_config(self) -> None:
        tester = self._tester()

        assert tester._quick_validate_url(VLESS_OK) == (True, "")
        assert tester._quick_validate_url(HY2_URL) == (True, "")


class TestConfigsThatFailAtConfigLoad:
    """Names xray's loader rejects outright — a handshake timeout is not the issue.

    `infra/conf/transport_internet.go` returns `PrintRemovedFeatureError` for the
    deleted HTTP/QUIC transports and `unknown transport protocol` for anything it
    does not register, and `trojan.go` rejects a non-empty flow the same way. Each
    of those aborts `xray -c` before it listens, so in batch mode one such config
    costs the chunk — up to `XRAY_BATCH_SIZE` configs — rather than itself.
    """

    @pytest.mark.parametrize("transport", ["h2", "http", "quic", "h3"])
    def test_a_removed_transport_is_refused_whatever_the_protocol(self, transport: str) -> None:
        url = f"vless://12345678-1234-1234-1234-123456789012@h.example.com:443?security=tls&type={transport}"

        assert f"transport removed from xray: {transport}" == _xray_incompatible_reason(url)

    @pytest.mark.parametrize("transport", ["ray", "webtransport", "kcp2"])
    def test_a_transport_name_xray_does_not_register_is_refused(self, transport: str) -> None:
        """`default:` in `TransportProtocol.Build()` is an error, not a fallback."""
        url = f"vless://12345678-1234-1234-1234-123456789012@h.example.com:443?type={transport}"

        assert f"unknown transport protocol: {transport}" == _xray_incompatible_reason(url)

    @pytest.mark.parametrize(
        "transport",
        ["splithttp", "xhttp", "kcp", "mkcp", "ws", "websocket", "httpupgrade", "raw"],
    )
    def test_every_name_the_transport_builder_resolves_is_testable(self, transport: str) -> None:
        """The aliases are the trap here: `splithttp` is xhttp and `mkcp` still builds.

        Refusing a name xray accepts is the mistake this filter has now made twice
        (Hysteria2, and `mkcp`/`splithttp` here), so the accepted spelling of every
        alias is pinned rather than the ones that happen to be common.
        """
        url = f"vless://12345678-1234-1234-1234-123456789012@h.example.com:443?security=tls&type={transport}"

        assert _xray_incompatible_reason(url) == ""

    def test_a_removed_transport_on_vmess_is_refused_too(self) -> None:
        """The vmess parser has no h2 branch left, and nothing asks for one."""
        url = "vless://12345678-1234-1234-1234-123456789012@h.example.com:443?type=h2"

        assert "transport removed from xray" in _xray_incompatible_reason(url)

    def test_an_unknown_stream_security_is_refused(self) -> None:
        url = "vless://12345678-1234-1234-1234-123456789012@h.example.com:443?security=xtls"

        assert "unknown stream security" in _xray_incompatible_reason(url)

    @pytest.mark.parametrize("security", ["tls", "reality", "none"])
    def test_the_security_values_xray_knows_are_left_alone(self, security: str) -> None:
        url = f"vless://12345678-1234-1234-1234-123456789012@h.example.com:443?security={security}"

        assert _xray_incompatible_reason(url) == ""

    def test_security_on_an_ss_url_is_the_cipher_and_stays_out_of_it(self) -> None:
        """The scoped schemes exist because `ss://?security=` means something else.

        Refusing on the parameter name alone would drop valid Shadowsocks configs
        whose `security` carries the method.
        """
        assert (
            _xray_incompatible_reason(
                "ss://aes-256-gcm:pass@h.example.com:443?security=aes-256-gcm"
            )
            == ""
        )

    def test_a_trojan_flow_is_refused(self) -> None:
        """`trojan.go` returns a removed-feature error for any non-empty flow."""
        url = "trojan://pass@h.example.com:443?security=tls&sni=h.example.com&flow=xtls-rprx-vision"

        assert "trojan with a non-empty flow" in _xray_incompatible_reason(url)

    def test_a_trojan_without_flow_is_testable(self) -> None:
        assert _xray_incompatible_reason("trojan://pass@h.example.com:443?security=tls") == ""

    def test_the_same_flow_on_vless_is_still_accepted(self) -> None:
        """The rule is about trojan, not about the word `flow`."""
        url = "vless://12345678-1234-1234-1234-123456789012@h.example.com:443?security=tls&flow=xtls-rprx-vision"

        assert _xray_incompatible_reason(url) == ""

    @pytest.mark.parametrize("flow", ["", "xtls-rprx-vision", "xtls-rprx-vision-udp443"])
    def test_the_flows_xray_switches_on_are_testable(self, flow: str) -> None:
        """`vless.go` accepts exactly these three, and `-udp443` is one of them.

        The rule this replaces was a denylist that named `xtls-rprx-vision-udp443`
        as unsupported, so every Vision node with the udp443 variant was dropped
        from the published files for a reason that was simply wrong.
        """
        url = f"vless://12345678-1234-1234-1234-123456789012@h.example.com:443?security=tls&flow={flow}"

        assert _xray_incompatible_reason(url) == ""

    @pytest.mark.parametrize("flow", ["xtls-rprx-direct", "xtls-rprx-splice", "auto", "tls"])
    def test_any_other_flow_is_refused_because_xray_errors_on_it(self, flow: str) -> None:
        """The rejected set is open-ended, which is why the rule is an allowlist."""
        url = f"vless://12345678-1234-1234-1234-123456789012@h.example.com:443?security=tls&flow={flow}"

        assert f"flow xray does not support: {flow}" == _xray_incompatible_reason(url)


class TestTheOlderRules:
    """The rules that predate this module, now pinned one case at a time.

    Each of these was written against a config observed to make xray fail at
    startup and none had a test, so "the filter catches it" was a claim about a
    string pattern nobody re-checked. The expected reason strings are copied from
    what the function actually returns, so a change here is a deliberate change of
    verdict and not a regression.
    """

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            (
                "vless://12345678-1234-1234-1234-123456789012@h.example.com:443?encryption=none=@x",
                "garbage encryption value",
            ),
            (
                "vless://12%2540345678-1234-1234-1234-123456789012@h.example.com:443",
                "invalid UUID (url-encoded garbage)",
            ),
            (
                "vless://readable-text-not-a-uuid@h.example.com:443",
                "invalid UUID (not a valid format)",
            ),
            ("vless://1234@h.example.com:443", "invalid UUID (bad format)"),
            (f"{REALITY}&pbk=abc%20def", "reality publicKey is not 32 bytes of raw url base64"),
            (f"{REALITY}&pbk=key", "reality publicKey is not 32 bytes of raw url base64"),
            (
                f"{REALITY}&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh+",
                "reality publicKey is not 32 bytes of raw url base64",
            ),
            (f"{REALITY}&sid=a", "reality shortId is not whole hex bytes, 0-16 characters"),
            (
                f"{REALITY}&sid=" + "a" * 34,
                "reality shortId is not whole hex bytes, 0-16 characters",
            ),
            (f"{REALITY}&sid=abc", "reality shortId is not whole hex bytes, 0-16 characters"),
            (
                "vless://12345678-1234-1234-1234-123456789012@h.example.com:443?flow=xtls-rprx-direct-udp443",
                "flow xray does not support: xtls-rprx-direct-udp443",
            ),
        ],
    )
    def test_a_broken_config_is_refused_with_its_reason(self, url: str, expected: str) -> None:
        assert _xray_incompatible_reason(url) == expected

    def test_a_complete_reality_config_is_testable(self) -> None:
        """The rules reject the broken field, not the whole protocol."""
        url = f"{REALITY}&type=raw&pbk={PBK}&sid=ab&sni=h.example.com"

        assert _xray_incompatible_reason(url) == ""

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("sid", ""),  # no shortId at all is the common case, and it is legal
            ("sid", "0123456789abcdef"),  # 16 hex fills xray's 8-byte buffer
            ("sid", "ABCDEF"),  # hex is matched case-insensitively upstream
            ("pbk", PBK),
        ],
    )
    def test_a_value_xrays_decoder_accepts_is_testable(self, field: str, value: str) -> None:
        assert _xray_incompatible_reason(f"{REALITY}&{field}={value}&sni=h.example.com") == ""

    def test_reality_over_a_transport_it_rejects_is_refused(self) -> None:
        """`StreamConfig.Build()` inspects the resolved transport when security is reality.

        `transport_internet.go:1777-1780` at v26.3.27: with `security=reality`, any
        config whose protocol name is not `tcp`, `splithttp` or `grpc` returns
        `REALITY only supports RAW, XHTTP and gRPC for now.` That is a config-load
        failure, so in batch mode one such URL costs every other config sharing the
        process. `TransportProtocol.Build()` (`:998-1006`) is what turns the URL's
        spelling into those names, and it lowercases first -- so the accepted spellings
        are exactly raw, tcp, xhttp, splithttp and grpc, in either case, and everything
        else that still builds (ws, httpupgrade, kcp, hysteria) is refused here rather
        than handed to xray.

        This rule was removed on the reading that reality's *client* builder never looks
        at the transport. That is true of `RealityConfig.Build()` and irrelevant: the
        check is one level up, in the stream config both directions share.
        """
        for transport in ("raw", "tcp", "xhttp", "splithttp", "grpc", "TCP", "XHttp"):
            assert _xray_incompatible_reason(f"{REALITY}&pbk={PBK}&type={transport}") == ""

        for transport in ("ws", "websocket", "httpupgrade", "kcp", "mkcp", "hysteria", "WS"):
            reason = _xray_incompatible_reason(f"{REALITY}&pbk={PBK}&type={transport}")

            assert "reality" in reason, f"{transport}: {reason}"

    def test_a_transport_rule_that_is_not_reality_leaves_ws_alone(self) -> None:
        """The refusal belongs to reality, not to WebSocket."""
        assert _xray_incompatible_reason(f"{REALITY}&pbk={PBK}") == ""  # no type= means tcp
        plain_ws = (
            "vless://12345678-1234-1234-1234-123456789012@w.example.com:443?security=tls&type=ws"
        )
        assert _xray_incompatible_reason(plain_ws) == ""

    @pytest.mark.parametrize(
        "url",
        [
            "trojan://pass@h.example.com:443?pbk=key&sid=zz",
            "ss://aes-256-gcm:p@h.example.com:443?sid=zz",
        ],
    )
    def test_the_reality_bounds_apply_only_where_reality_settings_are_built(self, url: str) -> None:
        """A `pbk=`/`sid=` outside `security=reality` is text xray never reads.

        The parsers build realitySettings only for that security value, so an
        unscoped check would refuse configs that load and connect unchanged.
        """
        assert _xray_incompatible_reason(url) == ""

    def test_a_parameter_shape_inside_the_remark_is_not_read_as_a_parameter(self) -> None:
        """The node name is free text; only the query is a source of parameters.

        `#old-node?sid=zz` sets no shortId — it is a remark that happens to contain
        `?` and `=`. A rule that searched the whole URL found `sid=zz` there and
        refused a config xray builds without complaint, so the case is pinned on
        both sides: the real parameters pass, and the remark cannot trigger them.
        """
        url = f"{REALITY}&pbk={PBK}&sni=h.example.com#old-node?sid=zz&type=h2"

        assert _xray_incompatible_reason(url) == ""

    def test_a_dashless_uuid_is_not_junk(self) -> None:
        """`common/uuid.ParseString` accepts 32-36 characters of hex, dashes or not.

        The user-id rule is a junk filter rather than a crash guard, and being
        stricter than xray here is how the filter loses nodes xray verifies fine.
        """
        assert (
            _xray_incompatible_reason(
                "vless://1234567890abcdef1234567890abcdef@h.example.com:443?security=tls"
            )
            == ""
        )

    def test_the_uuid_rule_is_scoped_to_vless(self) -> None:
        """vmess carries its user id in base64 JSON, so a raw check would be wrong.

        Pinned because the rule reads like a general one: applying it to vmess
        would refuse configs xray parses happily.
        """
        assert _xray_incompatible_reason("vmess://readable-text@h.example.com:443") == ""

    def test_tuic_is_not_a_filter_concern(self) -> None:
        """TUIC is xray's gap, but this filter refuses by pattern, not by protocol.

        The typed parser resolves no outbound for it, which is the path that
        handles TUIC; the filter staying silent is deliberate rather than an
        oversight.
        """
        assert _xray_incompatible_reason("tuic://uuid:pass@h.example.com:443") == ""


class TestTheShadowsocksCipherAllowlist:
    """A cipher name xray's loader does not know kills the process at startup.

    The rejected set is open-ended — stream ciphers, removed experimental ones,
    `aes-192-gcm` (a real AEAD cipher the switch omits), and whatever a failed
    base64 read leaves behind — so the rule is an allowlist read off
    `cipherFromString` in `infra/conf/shadowsocks.go` rather than a list of
    known-bad names. `none` and `plain` are loadable and therefore absent here:
    their problem is the missing encryption, and
    `has_insecure_setting()` is what has to catch them.
    """

    @pytest.mark.parametrize(
        "cipher",
        [
            "aes-256-gcm",
            "aead_aes_256_gcm",
            "chacha20-ietf-poly1305",
            "xchacha20-poly1305",
            "2022-blake3-aes-256-gcm",
            "none",
            "plain",
        ],
    )
    def test_a_cipher_xray_loads_is_testable(self, cipher: str) -> None:
        assert _xray_incompatible_reason(f"ss://{cipher}:secretpw@h.example.com:443") == ""

    @pytest.mark.parametrize(
        "cipher",
        [
            "aes-256-cfb",
            "rc4-md5",
            "chacha20",
            "aes-192-gcm",
            "2022-blake3-aes-192-gcm",
            "table",
        ],
    )
    def test_a_cipher_xray_does_not_load_is_refused_by_name(self, cipher: str) -> None:
        reason = _xray_incompatible_reason(f"ss://{cipher}:secretpw@h.example.com:443")

        assert reason == f"unknown shadowsocks cipher: {cipher}"

    def test_the_base64_form_of_a_url_is_read_as_well_as_the_plain_one(self) -> None:
        """The cipher sits inside a base64 blob in half the corpus."""
        blob = base64.b64encode(b"rc4-md5:secretpw").decode()

        assert "unknown shadowsocks cipher" in _xray_incompatible_reason(
            f"ss://{blob}@h.example.com:443"
        )

    def test_the_form_whose_address_is_inside_the_blob_is_read_too(self) -> None:
        """SIP003 keeps `method:password@host:port` in one token, `@` and all.

        The URL has no `@`, so a rule that only reads the two clear forms never sees
        the cipher -- and "never sees it" was recorded as "loads fine": these configs
        were verified with a method xray cannot build, and the `none` among them was
        certified secure. Same cipher, same verdict, whichever spelling carried it.
        """
        for cipher, expected in (
            ("rc4-md5", "unknown shadowsocks cipher: rc4-md5"),
            ("aes-192-gcm", "unknown shadowsocks cipher: aes-192-gcm"),
            ("aes-256-gcm", ""),
            ("none", ""),  # loads in xray; calling it insecure is the other filter's job
        ):
            blob = base64.b64encode(f"{cipher}:secretpw@h.example.com:443".encode()).decode()

            assert _xray_incompatible_reason(f"ss://{blob}") == expected, cipher

    def test_a_shadowsocksr_cipher_is_judged_the_same_way(self) -> None:
        """SSR configs get converted to plain Shadowsocks, so the same switch runs.

        This is most of the `ssr://` corpus: `aes-256-cfb` is what ssserver
        defaulted to, and xray has no SSR protocol or obfs layer either.
        """
        raw = b"h.example.com:443:origin:aes-256-cfb:plain:none"

        reason = _xray_incompatible_reason(f"ssr://{base64.b64encode(raw).decode()}")

        assert "aes-256-cfb" in reason

    def test_a_password_that_looks_like_a_cipher_is_left_alone(self) -> None:
        """The rule reads the scheme, not the word.

        Trojan passwords are free-form text in front of the host, and an
        unscoped check would refuse configs xray builds without complaint.
        """
        assert _xray_incompatible_reason("trojan://rc4-md5@h.example.com:443?security=tls") == ""

    def test_an_ss_url_whose_credentials_cannot_be_read_is_not_refused(self) -> None:
        """No verdict is not a verdict: this one has to fall through.

        Pinned because the rule is written as `if method and ...` and an
        unparseable payload would otherwise be refused for a cipher nobody read.
        """
        assert _xray_incompatible_reason("ss://!!!not-base64!!!@h.example.com:443") == ""


class TestTheRulesThatStay:
    """The refusals that are real — pinned so a hy2 fix cannot take them too.

    Each of these would parse into an outbound and then fail when xray loads the
    config, which in batch mode costs every other config sharing the process.
    """

    def test_a_malformed_uuid_is_refused(self) -> None:
        reason = _xray_incompatible_reason(VLESS_BAD_UUID)

        assert "UUID" in reason

    def test_a_flow_removed_from_xray_is_refused(self) -> None:
        assert "flow xray does not support" in _xray_incompatible_reason(VLESS_DEAD_FLOW)

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

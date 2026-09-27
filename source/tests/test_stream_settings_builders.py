"""The `streamSettings` blocks both builders emit, checked against xray's own keys.

Moved out of `test_protocol_parsers.py`, which had reached the repository's
module-size ceiling. Everything here is the same question from a different angle:
does the JSON that reaches xray use the key names `StreamConfig` actually reads,
resolve the transport aliases, and fall back where upstream refuses a value. The
parser-side URL shapes stay in the file this one came from.

Offline by construction: a URL or a vmess object goes in, a dict comes back, and
that dict is what is read. Nothing starts a process or opens a port.
"""

import base64
import json
from typing import Any

import pytest

pytestmark = pytest.mark.unit


class TestStreamSettingsUseXraysKeys:
    """Every key here has to be one `StreamConfig` reads.

    `infra/conf/transport_internet.go` (v26.3.27) defines the settings blocks as
    `wsSettings{path,host}`, `httpupgradeSettings{path,host}`, `xhttpSettings
    {path,host,mode}` and `realitySettings{serverName,fingerprint,publicKey,
    shortId}`. A key it does not have is dropped in silence, and a transport with
    no settings block is dialled over the wrong wire — both come back as a dead
    node rather than an error, which is the failure this project keeps mistaking
    for an unavailable server.
    """

    URL = (
        "vless://12345678-1234-1234-1234-123456789012@ws.example.com:443"
        "?security=tls&sni=ws.example.com&type={kind}&path=%2Fnode&host=cdn.example.com"
    )

    def _stream(self, kind: str) -> dict[str, Any]:
        from utils.protocol_parsers import parse_url_to_outbound

        out = parse_url_to_outbound(self.URL.format(kind=kind), "proxy")
        assert out is not None
        stream = out["streamSettings"]
        assert isinstance(stream, dict)
        return stream

    @pytest.mark.parametrize("kind", ["ws", "httpupgrade", "xhttp", "splithttp"])
    def test_the_typed_and_legacy_builders_produce_the_same_stream(self, kind: str):
        from utils.protocol_parsers import parse_vless_to_outbound
        from utils.vpn_config import parse_url

        typed = parse_url(self.URL.format(kind=kind))
        assert typed is not None
        typed_out = typed.to_xray_outbound()
        assert typed_out is not None
        legacy = parse_vless_to_outbound(self.URL.format(kind=kind), "proxy")
        assert legacy is not None

        assert typed_out["streamSettings"] == legacy["streamSettings"]

    def test_websocket_carries_host_rather_than_a_headers_map(self):
        stream = self._stream("ws")

        assert stream["wsSettings"] == {"path": "/node", "host": "cdn.example.com"}
        assert "headers" not in stream["wsSettings"]

    def test_httpupgrade_carries_its_own_settings_block(self):
        """`network: httpupgrade` with no settings tested the node against `/`."""
        stream = self._stream("httpupgrade")

        assert stream["httpupgradeSettings"] == {"path": "/node", "host": "cdn.example.com"}

    def test_xhttp_carries_its_own_settings_block_under_both_names(self):
        for kind in ("xhttp", "splithttp"):
            stream = self._stream(kind)

            assert stream["network"] == kind
            assert stream["xhttpSettings"] == {"path": "/node", "host": "cdn.example.com"}


class TestFingerprintField:
    """xray resolves `fingerprint` through utls and aborts the load when it cannot.

    `TLSConfig.Build()` errors `unknown "fingerprint"` for anything
    `GetFingerprint` does not know, and the Reality client refuses `unsafe` and
    `hellogolang` as well. An empty string is one of those unknowns, so the old
    `"fingerprint": fp` — `None` whenever the URL carried no `fp=` — made every
    such reality outbound a config-load failure.
    """

    def _reality(self, query: str) -> dict[str, Any]:
        from utils.protocol_parsers import parse_url_to_outbound

        out = parse_url_to_outbound(
            f"vless://12345678-1234-1234-1234-123456789012@r.example.com:443{query}", "proxy"
        )
        assert out is not None
        stream = out["streamSettings"]
        assert isinstance(stream, dict)
        return stream

    def test_a_reality_url_without_fp_still_names_one(self):
        from config.settings import TLS_FINGERPRINT

        stream = self._reality("?security=reality&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")

        assert stream["realitySettings"]["fingerprint"] == TLS_FINGERPRINT
        assert stream["realitySettings"]["fingerprint"] is not None

    def test_the_urls_own_fingerprint_is_kept(self):
        stream = self._reality(
            "?security=reality&fp=firefox&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        )

        assert stream["realitySettings"]["fingerprint"] == "firefox"

    def test_a_fingerprint_reality_forbids_falls_back_instead_of_failing_the_load(self):
        stream = self._reality(
            "?security=reality&fp=unsafe&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        )

        assert stream["realitySettings"]["fingerprint"] == "chrome"

    def test_fingerprint_does_not_belong_on_stream_settings(self):
        """`StreamConfig` has no such key; the value is read inside the settings."""
        stream = self._reality("?security=tls")

        assert "fingerprint" not in stream
        assert stream["tlsSettings"]["fingerprint"] == "chrome"


class TestTransportAliasesAndMode:
    """`ws`/`websocket` and `xhttp`/`splithttp` are one transport upstream.

    `TransportProtocol.Build()` resolves both spellings of each pair, so a builder
    that dispatches on one literal sends the other spelling out with no settings
    block: no path, no host, and a node that works in every other client comes back
    as a timeout.
    """

    def _streams(self, kind: str, extra: str = "") -> tuple[dict[str, Any], dict[str, Any]]:
        from utils.protocol_parsers import parse_url_to_outbound
        from utils.vpn_config import parse_url

        url = (
            "vless://12345678-1234-1234-1234-123456789012@ws.example.com:443"
            f"?security=tls&type={kind}&path=/node{extra}"
        )
        typed = parse_url(url)
        legacy = parse_url_to_outbound(url, "proxy")

        assert typed is not None and legacy is not None
        typed_out = typed.to_xray_outbound()
        assert typed_out is not None
        return typed_out["streamSettings"], legacy["streamSettings"]

    @pytest.mark.parametrize("kind", ["ws", "websocket"])
    def test_both_websocket_spellings_carry_their_settings(self, kind: str) -> None:
        typed, legacy = self._streams(kind)

        assert typed["wsSettings"] == {"path": "/node", "host": "ws.example.com"}
        assert typed == legacy

    @pytest.mark.parametrize("kind", ["xhttp", "splithttp"])
    def test_both_xhttp_spellings_carry_their_settings(self, kind: str) -> None:
        typed, legacy = self._streams(kind)

        assert typed["xhttpSettings"] == {"path": "/node", "host": "ws.example.com"}
        assert typed == legacy

    def test_the_xhttp_mode_survives_both_builders(self) -> None:
        typed, legacy = self._streams("xhttp", "&mode=stream-up")

        assert typed["xhttpSettings"]["mode"] == "stream-up"
        assert typed == legacy

    def test_a_mode_xray_does_not_implement_is_not_emitted(self) -> None:
        """`unsupported mode` is a load failure; leaving it out defaults to `auto`."""
        typed, legacy = self._streams("xhttp", "&mode=stream-two")

        assert "mode" not in typed["xhttpSettings"]
        assert typed == legacy


class TestVMessJSONUsesTheSharedBuilder:
    """The vmess fallback knew two transports and had no reality block at all.

    Every other spelling of `net` reached xray with no settings block, and
    `tls: "reality"` produced `security: reality` without `realitySettings`, which
    `StreamConfig.Build()` rejects. Both builders now go through the same function,
    so the vmess object cannot drift from the URL parsers again.
    """

    @staticmethod
    def _url(**fields: object) -> str:
        payload: dict[str, object] = {
            "add": "vm.example.com",
            "port": "443",
            "id": "12345678-1234-1234-1234-123456789012",
        }
        payload.update(fields)
        return "vmess://" + base64.b64encode(json.dumps(payload).encode()).decode()

    @pytest.mark.parametrize("net", ["httpupgrade", "xhttp", "splithttp", "websocket"])
    def test_every_transport_the_url_parsers_handle_gets_their_block(self, net: str) -> None:
        from utils.protocol_parsers import parse_vmess_to_outbound

        out = parse_vmess_to_outbound(
            self._url(net=net, path="/node", host="cdn.example.com"), "tag"
        )

        assert out is not None
        settings = out["streamSettings"]
        assert settings["network"] == net
        block = (
            settings.get("wsSettings")
            or settings.get("httpupgradeSettings")
            or settings.get("xhttpSettings")
        )
        assert block is not None, f"{net} produced no settings block"
        assert block["path"] == "/node"
        assert block["host"] == "cdn.example.com"

    def test_reality_without_a_public_key_builds_no_outbound(self) -> None:
        from utils.protocol_parsers import parse_vmess_to_outbound

        out = parse_vmess_to_outbound(self._url(tls="reality", sni="vm.example.com"), "tag")

        assert out is None

    def test_tls_falls_back_to_the_address_for_its_server_name(self) -> None:
        """The vmess object carries no `sni`, so the Host value is what xray must see."""
        from utils.protocol_parsers import parse_vmess_to_outbound

        out = parse_vmess_to_outbound(self._url(tls="tls", host="vm.example.com"), "tag")

        assert out is not None
        assert out["streamSettings"]["tlsSettings"]["serverName"] == "vm.example.com"

    def test_a_boolean_tls_field_loads(self) -> None:
        """Older clients write `"tls": true`, and xray matches `security` as a string.

        The boolean went into the outbound as `"security": true`, which
        `StreamConfig.Build()` answers with `Unknown security` — a config-load
        failure that in batch mode costs every other config in the chunk.
        """
        from utils.protocol_parsers import parse_vmess_to_outbound
        from utils.vpn_config import parse_url

        url = self._url(tls=True, host="vm.example.com", net="ws", path="/node")
        legacy = parse_vmess_to_outbound(url, "tag")
        typed_cfg = parse_url(url)

        assert legacy is not None
        assert legacy["streamSettings"]["security"] == "tls"
        assert typed_cfg is not None
        typed_out = typed_cfg.to_xray_outbound()
        assert typed_out is not None
        assert typed_out["streamSettings"] == legacy["streamSettings"]

    def test_vmess_reality_is_declined_rather_than_guessed(self) -> None:
        """The reality field names in this JSON are not agreed on between clients.

        Emitting `security: reality` without a `realitySettings` block is a load
        failure, and inventing the key would test a key the node may not use, so
        both builders return None and the config stays out of verification.
        """
        from utils.protocol_parsers import parse_vmess_to_outbound
        from utils.vpn_config import parse_url

        url = self._url(tls="reality", host="vm.example.com", sni="vm.example.com")

        assert parse_vmess_to_outbound(url, "tag") is None
        assert parse_url(url) is None


class TestSpellingCaseOfParameters:
    """xray folds some of these names and values, and silently accepts the rest.

    `TransportProtocol.Build()` is `switch strings.ToLower(string(p))` and
    `StreamConfig.Build()` is `switch strings.ToLower(c.Security)`
    (`transport_internet.go:999` and `:1763`, v26.3.27), so `type=WS` and `security=TLS`
    are the same config to xray. The builders compared the URL's spelling to lowercase
    literals instead, so a capitalized link dropped to the defaults -- `network: tcp,
    security: none` -- and was tested over plaintext against a node speaking TLS. That
    answer comes back as a dead server, and the security filter, which had folded the
    string it read, had already filed the same node as encrypted.

    Parameter *names* fold for the reason the compatibility filter already documents:
    YAML converters emit both `pbk` and `PBK`. Values that are data do not: a publicKey
    is base64 and a gRPC service name is a string the server chose.
    """

    VLESS_BASE = "vless://12345678-1234-1234-1234-123456789012@ws.example.com:443"
    PBK = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

    def _both(self, url: str) -> tuple[dict[str, Any], dict[str, Any]]:
        from utils.protocol_parsers import parse_url_to_outbound
        from utils.vpn_config import parse_url

        legacy = parse_url_to_outbound(url, "proxy")
        typed = parse_url(url)
        assert legacy is not None, f"legacy declined {url}"
        typed_out = typed.to_xray_outbound() if typed is not None else None
        assert typed_out is not None, f"typed declined {url}"
        return legacy["streamSettings"], typed_out["streamSettings"]

    def test_a_capitalized_security_and_transport_still_build_tls_over_ws(self):
        legacy, typed = self._both(f"{self.VLESS_BASE}?security=TLS&type=WS&sni=ws.example.com")

        assert legacy["security"] == "tls", legacy
        assert legacy["network"] == "ws", legacy
        assert legacy["wsSettings"]["path"] == "/"
        assert typed == legacy

    def test_capitalized_parameter_names_read_the_same_values(self):
        lower_legacy, _ = self._both(
            f"{self.VLESS_BASE}?security=tls&type=ws&path=%2Fnode"
            "&host=cdn.example.com&sni=ws.example.com&fp=chrome"
        )
        upper_legacy, upper_typed = self._both(
            f"{self.VLESS_BASE}?Security=tls&Type=ws&Path=%2Fnode"
            "&Host=cdn.example.com&SNI=ws.example.com&FP=chrome"
        )

        assert upper_legacy == lower_legacy, (upper_legacy, lower_legacy)
        assert upper_typed == lower_legacy

    def test_reality_under_any_capitalization_still_builds_reality_settings(self):
        for spelling in ("security=reality", "Security=REALITY", "SECURITY=Reality"):
            legacy, typed = self._both(
                f"{self.VLESS_BASE}?{spelling}&pbk={self.PBK}&sni=ws.example.com&type=tcp"
            )

            assert legacy["security"] == "reality", legacy
            assert legacy["realitySettings"]["publicKey"] == self.PBK
            assert typed == legacy

    def test_a_public_key_is_case_sensitive_data_and_stays_that_way(self):
        """Folding `pbk` would corrupt the key xray decodes as raw base64."""
        mixed = "aaCAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        legacy, typed = self._both(
            f"{self.VLESS_BASE}?security=reality&PBK={mixed}&sni=ws.example.com"
        )

        assert legacy["realitySettings"]["publicKey"] == mixed
        assert typed["realitySettings"]["publicKey"] == mixed

    def test_a_grpc_service_name_survives_both_the_name_and_its_own_case(self):
        legacy, typed = self._both(
            f"{self.VLESS_BASE}?security=tls&type=grpc&ServiceName=MyService"
        )

        assert legacy["grpcSettings"]["serviceName"] == "MyService"
        assert typed["grpcSettings"]["serviceName"] == "MyService"

    def test_the_fingerprint_is_folded_because_xray_folds_it(self):
        """`config.Fingerprint = strings.ToLower(c.Fingerprint)` (`:702`)."""
        legacy, typed = self._both(
            f"{self.VLESS_BASE}?security=tls&type=ws&sni=ws.example.com&fp=Chrome"
        )

        assert legacy["tlsSettings"]["fingerprint"] == "chrome"
        assert typed["tlsSettings"]["fingerprint"] == "chrome"

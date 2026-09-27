"""A node's remark must not change what any reader concludes about the node.

`vmess://`, `ssr://` and the encoded `ss://` forms carry their address inside base64,
and the lenient decoders used here discard `#` rather than raising on it -- so the
remark was folded into the payload before the padding was computed. Five modules then
disagreed about the same line: no host for the SNI whitelist, no outbound for the
verifier, no cipher for the allowlist, no `allowInsecure` for the security filter, a
raw-blob key for deduplication. Each reader keeps its own answer here, because the bug
was never in one of them.

Offline by construction: every case hands a URL string to a pure function.
"""

import base64
import json

import pytest

from utils.file_utils import _get_dedup_key, deduplicate_configs, extract_host_port
from utils.protocol_parsers import parse_url_to_outbound
from utils.security_filter import extract_ss_credentials, has_insecure_setting
from utils.url_payload import base64_payload
from utils.vpn_config import parse_url
from utils.xray_compat import filter_xray_compatible

pytestmark = pytest.mark.unit

_ID = "12345678-1234-1234-1234-123456789012"


def _vmess(**fields) -> str:
    obj = {
        "v": "2",
        "ps": "node",
        "add": "1.2.3.4",
        "port": "443",
        "id": _ID,
        "aid": "0",
        "net": "ws",
        "path": "/node",
        "host": "cdn.example.com",
        "tls": "tls",
    }
    obj.update(fields)
    payload = base64.b64encode(json.dumps(obj, sort_keys=True).encode()).decode()
    return "vmess://" + payload.rstrip("=")


_VMESS_SECURE = _vmess()
_VMESS_INSECURE = _vmess(tls="", allowInsecure="1")
_SSR = "ssr://" + base64.urlsafe_b64encode(
    b"5.6.7.8:443:auth_aes128_md5:aes-256-gcm:plain:cGFzc3dvcmQ="
).decode().rstrip("=")
_SS_BLOB = "ss://" + base64.b64encode(b"aes-256-gcm:pw@9.10.11.12:8388").decode().rstrip("=")
_SS_COMPAT = "ss://" + base64.b64encode(b"aes-256-gcm:pw").decode() + "@13.14.15.16:8388"
_VLESS = f"vless://{_ID}@edge.example.com:443?security=tls&type=ws&path=%2Fnode"
_TROJAN = "trojan://pw@sni.example.com:443?security=tls"

# A remark made of base64 alphabet text is the worst case: those characters survive a
# lenient decode and land inside the payload.
REMARKS = [
    "#Tokyo-1",
    "#%D0%9D%D0%BE%D0%B4%D0%B0",
    "#\u0423\u0441\u0442\u0440 \u041d\u043e\u0434\u0430",
    "#dGVzdA==",
    "#node?with=question",
    "#",
]


def _typed_outbound(url: str):
    """The typed path's outbound, not its dataclass.

    `VPNConfig` keeps the remark as the node's `name`, which is the one field a
    remark is supposed to change -- comparing the objects would fail for a parser
    that is behaving correctly.
    """
    cfg = parse_url(url)
    return None if cfg is None else cfg.to_xray_outbound("proxy")


READERS = [
    pytest.param(extract_host_port, id="host_port"),
    pytest.param(parse_url_to_outbound, id="legacy_outbound"),
    pytest.param(_typed_outbound, id="typed_outbound"),
    pytest.param(has_insecure_setting, id="security_verdict"),
    pytest.param(extract_ss_credentials, id="ss_credentials"),
    pytest.param(_get_dedup_key, id="dedup_key"),
]

BASE_URLS = [_VMESS_SECURE, _VMESS_INSECURE, _SSR, _SS_BLOB, _SS_COMPAT, _VLESS, _TROJAN]


def _call(reader, url):
    """Every reader has its own signature; the tag argument is all they need."""
    try:
        return reader(url, "proxy")
    except TypeError:
        return reader(url)


class TestRemarkChangesNothing:
    """One node, spelled with any remark, has to read the same every time."""

    @pytest.mark.parametrize("url", BASE_URLS)
    @pytest.mark.parametrize("remark", REMARKS)
    @pytest.mark.parametrize("reader", READERS)
    def test_a_remark_leaves_the_verdict_alone(self, reader, url, remark):
        bare = _call(reader, url)
        named = _call(reader, url + remark)

        assert named == bare, f"{getattr(reader, '__name__', reader)} disagrees once named"

    @pytest.mark.parametrize("url", BASE_URLS)
    def test_the_readers_do_read_the_bare_line(self, url):
        """The guard above would pass on a URL nobody can read at all.

        Six assertions of `None == None` prove nothing, so the same URL set is shown
        here to produce a real answer before it is used to claim stability.
        """
        assert extract_host_port(url) is not None
        assert parse_url_to_outbound(url, "proxy") is not None
        assert _get_dedup_key(url)[1] not in ("", None)


class TestTheCasesThatWereWrong:
    """Each of these used to answer for a node that could not be decoded.

    Not a restatement of the table above: these are the consequences measured on the
    published corpus, kept as named cases so a regression says which one came back.
    """

    def test_an_insecure_vmess_stays_insecure_when_it_is_named(self):
        assert has_insecure_setting(_VMESS_INSECURE) is True
        assert has_insecure_setting(_VMESS_INSECURE + "#\u0423\u0441\u0442\u0440") is True

    def test_a_named_vmess_still_reaches_the_verifier(self):
        assert parse_url_to_outbound(_VMESS_SECURE + "#Tokyo #2", "proxy") is not None
        assert parse_url(_VMESS_SECURE + "#Tokyo #2") is not None

    def test_a_named_ssr_still_reaches_the_verifier(self):
        assert extract_host_port(_SSR + "#\u041d\u043e\u0434\u0430 1") == ("5.6.7.8", 443)
        assert parse_url_to_outbound(_SSR + "#\u041d\u043e\u0434\u0430 1", "proxy") is not None

    def test_one_node_is_one_entry_whatever_it_is_called(self):
        spellings = [
            _VMESS_SECURE,
            _VMESS_SECURE + "#Tokyo",
            _VMESS_SECURE + "#\u041d\u043e\u0434\u0430",
        ]

        assert len(deduplicate_configs(spellings)) == 1

    def test_a_named_ss_blob_still_gives_up_its_host(self):
        assert extract_host_port(_SS_BLOB + "#\u041d\u043e\u0434\u0430") == ("9.10.11.12", 8388)

    def test_the_compat_filter_judges_the_config_not_its_name(self):
        for url in (_VLESS, _TROJAN, _SS_BLOB, _SSR):
            accepted, refused = filter_xray_compatible([url, url + "#\u041d\u043e\u0434\u0430"])
            assert len(accepted) == 2, f"{refused[0][1] if refused else ''}"


class TestBase64Payload:
    """The helper itself: whichever separator comes first ends the payload."""

    @pytest.mark.parametrize(
        "url",
        [
            "vmess://QUJD#name",
            "vmess://QUJD?name",
            "vmess://QUJD#name?more",
            "vmess://QUJD?name#more",
            "vmess://QUJD",
        ],
    )
    def test_the_payload_is_what_remains(self, url):
        assert base64_payload(url) == "QUJD"

    def test_a_remark_holding_a_separator_is_still_a_remark(self):
        assert base64_payload("ssr://QUJD#\u041d\u043e?de") == "QUJD"

    def test_the_scheme_is_not_part_of_the_answer(self):
        """Callers had their own prefix arithmetic; this retires it."""
        assert base64_payload(_VMESS_SECURE) == _VMESS_SECURE[len("vmess://") :]

    def test_a_url_with_no_separator_returns_its_whole_body(self):
        assert base64_payload(_SS_BLOB) == _SS_BLOB[len("ss://") :]

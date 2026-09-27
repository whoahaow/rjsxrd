"""The rules every reader of a VPN link has to agree on.

A share link is `scheme://payload[#remark][?params]`, and for `vmess://`, `ssr://`
and the encoded `ss://` forms the payload is base64. Base64 decoders here are the
lenient kind: `b64decode` and `urlsafe_b64decode` discard characters outside their
alphabet rather than raising, and neither `#` nor `?` is in that alphabet. So a link
that carries a node name -- which is what every client writes, because the remark is
the only human-readable part of the link -- has that name folded into the payload
before the padding is computed.

What that costs depends on the length of the leftover characters, which is why it
went unnoticed for so long: sometimes the decode still yields valid JSON and every
reader agrees, and sometimes the tail shifts the decode window and the result is
corrupted text. In the second case one node, read by five modules, gets five
different answers -- no host for the SNI whitelist, no outbound for the verifier, no
cipher for the allowlist, no `allowInsecure` for the security filter, and a dedup key
made from the raw blob instead of the server's address. The node is then published as
secure, never verified, and duplicated under each spelling of its name.

The query half of a link has its own rule, and it is xray's: which spellings of a
parameter name and value it resolves case-insensitively. Cut the tail before padding,
speak both alphabets, and fold only what upstream folds.
"""

import base64
import binascii
from urllib.parse import parse_qs

# The spellings a boolean URL parameter arrives in. Share links write the hysteria2
# `insecure` flag as `1` because that is what the spec shows, and as `true`, `yes` or
# `on` because that is what the panels that generate them say, and xray reads all of
# them through `strconv.ParseBool`-style parsing rather than against one literal.
TRUTHY_VALUES = frozenset({"1", "true", "yes", "on"})


def is_truthy(value: str | None) -> bool:
    """Whether a query parameter is present and says yes."""
    return value is not None and value.strip().lower() in TRUTHY_VALUES


def base64_payload(url: str) -> str:
    """The encoded payload of a URL, without its remark or parameters.

    Everything after `://` up to whichever separator comes first. Only the base64
    forms may be read this way: on a `vless://` or `trojan://` link the `?` introduces
    the parameters that *are* the configuration, and a caller that sliced those off
    would be handing xray a node with no transport, no SNI and no fingerprint.
    """
    body = url[url.index("://") + 3 :] if "://" in url else url
    cut = len(body)
    for separator in "#?":
        index = body.find(separator)
        if index != -1 and index < cut:
            cut = index
    return body[:cut]


def decode_base64_token(token: str) -> str | None:
    """One base64 token decoded, or None when it is not base64 text at all.

    The urlsafe alphabet is tried first, and the order is the whole point: the two
    alphabets are not symmetric. `urlsafe_b64decode` translates `-` and `_` and still
    accepts `+` and `/`, so it reads either spelling, while `b64decode` *discards*
    `-` and `_` as characters outside its alphabet -- a urlsafe token fed to it comes
    back with two bits of every affected byte missing, which is a corrupted decode
    that raises nothing. The second attempt is a fallback for a token the first
    rejects outright, not an alphabet sweep.

    Padding is recomputed because links are published with and without it. The decode
    drops bytes that are not UTF-8: the callers read fields by separator, so a lost
    byte costs them a field and yields a `None` verdict rather than a plausible wrong
    one.
    """
    padded = token + "=" * (-len(token) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(padded).decode("utf-8", errors="ignore")
        except (ValueError, TypeError, binascii.Error):
            continue
    return None


def query_parameters(query: str) -> dict[str, list[str]]:
    """A query string parsed with its parameter names folded to lowercase.

    Three readers look at these names and disagreed about case: the compatibility
    filter matched them with `re.IGNORECASE` from the start, on the documented reason
    that YAML converters emit both `pbk` and `PBK`, while both outbound builders
    indexed `parse_qs` output with literal lowercase keys. A URL spelled
    `?Security=tls&Type=ws&SNI=…` therefore certified as encrypted by one reader and
    built as `security: none, network: tcp` by the other two -- a node dialed over the
    wrong wire, which comes back as a dead server rather than as a parse error.

    Values are left exactly as they arrived. A publicKey and a shortId are base64 and
    hex, where case is data; the fields whose case xray itself folds are folded by
    `xray_stream_settings`, which cites the line that folds them.
    """
    folded: dict[str, list[str]] = {}
    for name, values in parse_qs(query).items():
        folded.setdefault(name.lower(), []).extend(values)
    return folded

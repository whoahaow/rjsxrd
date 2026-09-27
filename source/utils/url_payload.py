"""Two rules every reader of a base64 VPN link has to agree on.

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

Cut the tail before padding, and speak both alphabets. Those are the two rules.
"""

import base64
import binascii


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

    Both alphabets are tried -- standard (`+`, `/`) and urlsafe (`-`, `_`) -- because
    the two are mixed in the wild: a share link may carry either, and one reader that
    tries only the other silently corrupts the result rather than failing. Padding is
    recomputed, since links are published with and without it.

    Decoding is deliberately strict about *this* step and lenient about the next: an
    unpadded tail is repaired, but `errors="ignore"` means non-UTF-8 bytes are dropped.
    The callers read fields out of the result by separator, so a dropped byte yields a
    missing field rather than a wrong one, and a missing field is a `None` verdict.
    """
    padded = token + "=" * (-len(token) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(padded).decode("utf-8", errors="ignore")
        except (ValueError, TypeError, binascii.Error):
            continue
    return None

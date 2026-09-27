"""The one place that knows where a base64 VPN payload stops.

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

Cut the tail before padding. That is all this module does.
"""


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

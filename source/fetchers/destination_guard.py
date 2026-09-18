"""The destination guard's pure half: which answers a fetch refuses, and what it refused.

`fetchers/fetcher.py` owns the seam this decision reads through — `_resolved_addresses`,
which the suite replaces with a stub — and the order in which the answers are judged. This
module owns everything that needs no I/O: the classification of a resolved address, the
message a refusal is reported with, and the run's refusal figure.

The split is where the mode is: the classification is pure and holds no state, and the
module that spawns requests is the one place in the package where a page of decision logic
is hardest to find. A guard whose rule cannot be read without reading the fetch loop is a
guard nobody reads.

Why a refusal is counted at all. A refusal is a statement about the network the run is on —
the name resolved to an address this pipeline must not connect to — and never evidence that
the source is gone. `utils/url_stats.py` ages a URL toward removal from `URLS.txt` after
three consecutive failures, so a refusal that was recorded as one would delete a curated
source on a DNS blip, with the operator seeing the source vanish rather than the network
problem. It does not age the URL instead (that module recognizes
`utils.fetch_outcomes.DESTINATION_REFUSAL_PREFIX`), and the run names it here, every run,
until a human decides what it means.
"""

from __future__ import annotations

import ipaddress
import threading
from dataclasses import dataclass

from utils.fetch_outcomes import DESTINATION_REFUSAL_PREFIX
from utils.logger import log, warning

# The IPv6 prefixes that carry an *IPv4 address* inside them, with the bit layout each one
# carries it in. A wrapped address is judged by what it carries rather than by the prefix
# being listed as blocked: the point is the address the traffic reaches, and `64:ff9b::/96`
# is exactly where a real deployment puts public destinations, so refusing the whole prefix
# would be a false positive.
#
# `64:ff9b::/96` is the NAT64 well-known prefix (RFC 6052, RFC 8215) and `2002::/16` is 6to4
# (RFC 3056, whose `2002:V4ADDR::/48` form puts the address in the 32 bits after its 16-bit
# prefix). `::/96` is the IPv4-compatible form `::a.b.c.d`, deprecated by RFC 4291 §2.5.5.1
# and still parseable — which is why `::7f00:1` has to be read as loopback.
#
# Deliberately absent: `64:ff9b:1::/48`, the RFC 8215 local-use prefix. That RFC requires
# nodes not to assume the syntax of an address inside it — "must not ... make any
# assumptions regarding the syntax or properties of those addresses (e.g., the existence and
# location of embedded IPv4 addresses)" — and the plain rule above it already refuses the
# whole prefix, so an unwrap there could only make the guard more permissive, never less.
_RFC_6052 = "rfc6052"
_SIX_TO_FOUR = "six_to_four"

_TRANSLATION_PREFIXES: tuple[tuple[ipaddress.IPv6Network, int, str], ...] = (
    (ipaddress.IPv6Network("64:ff9b::/96"), 96, _RFC_6052),
    (ipaddress.IPv6Network("2002::/16"), 16, _SIX_TO_FOUR),
    (ipaddress.IPv6Network("::/96"), 96, _RFC_6052),
)


@dataclass(frozen=True)
class EmbeddedAddress:
    """An IPv4 address a translation prefix carries, and the prefix that carries it."""

    prefix: str
    address: ipaddress.IPv4Address


def _rfc6052_bits(value: int, prefix_length: int) -> int:
    """The IPv4 address RFC 6052 §2.2 placed at `prefix_length` inside a 128-bit address.

    The split is a function of the prefix length: for a /96 the address is simply the last
    32 bits, and for the shorter lengths the leading bits follow the prefix while the rest
    land after the reserved octet at bits 64-71. The six lengths the RFC allows are 32, 40,
    48, 56, 64 and 96, and the arithmetic covers all of them so that recognizing another
    translation prefix is a row in `_TRANSLATION_PREFIXES` rather than a new branch here —
    a prefix added by listing it would be the same defect one release later.
    """
    before = max(0, 64 - prefix_length)
    after = 32 - before
    high = (value >> 64) & ((1 << before) - 1) if before else 0
    low_start = 72 if before else max(prefix_length, 72)
    low = (value >> (128 - (low_start + after))) & ((1 << after) - 1) if after else 0
    return (high << after) | low


def embedded_ipv4(parsed: ipaddress.IPv4Address | ipaddress.IPv6Address) -> EmbeddedAddress | None:
    """The IPv4 address `parsed` carries, when it sits inside a translation prefix."""
    if not isinstance(parsed, ipaddress.IPv6Address):
        return None
    value = int(parsed)
    for network, prefix_length, layout in _TRANSLATION_PREFIXES:
        if parsed not in network:
            continue
        if layout == _SIX_TO_FOUR:
            carried = (value >> 80) & 0xFFFFFFFF
        else:
            carried = _rfc6052_bits(value, prefix_length)
        return EmbeddedAddress(prefix=str(network), address=ipaddress.IPv4Address(carried))
    return None


def _is_blocked_address(address: str) -> bool:
    """Whether a resolved address is one a fetch must never connect to.

    The rule is "globally routable, or refused": `ipaddress` already knows which answers
    are not — loopback, RFC 1918 and unique-local private space, link-local (which is
    where the cloud metadata endpoint `169.254.169.254` lives, the address that matters
    most because this pipeline runs on a VPS), unspecified `0.0.0.0/8`, carrier-grade NAT,
    reserved and documentation ranges. Multicast is spelled out because `is_global`
    reports it as global on this interpreter.

    An address inside a translation prefix is judged by the address it carries: the
    well-known prefix reports itself as global on this interpreter, so `64:ff9b::7f00:1`
    is a public-looking v6 address for 127.0.0.1 and the metadata endpoint encodes the same
    way. What the wrappers do is add to the refused set, never subtract from it — a prefix
    whose whole range already fails the check above stays refused, so no answer that was
    refused before this is admitted by it.

    An answer the parser cannot read is refused as well: it came from a resolver, and an
    address this module cannot classify is not one it can clear. The cost of the strict
    direction is a source that lives somewhere unroutable, which is not a source a
    subscription can be served from; the allowlist in `config/settings.py` is the explicit
    way around it.
    """
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return True
    if not parsed.is_global or parsed.is_multicast:
        return True
    embedded = embedded_ipv4(parsed)
    if embedded is None:
        return False
    return not embedded.address.is_global or embedded.address.is_multicast


@dataclass(frozen=True)
class DestinationRefusalStats:
    """A snapshot of one run's refusals, as the report states them."""

    refusals: int = 0
    destinations: tuple[tuple[str, str], ...] = ()

    @property
    def hosts_affected(self) -> int:
        """Distinct hosts behind those refusals.

        A host that was refused on every attempt of a run counts once: the number an
        operator needs is how much of the source list was left unfetched, not how many
        lookups it took.
        """
        return len({host for host, _ in self.destinations})


class _DestinationRefusalCounter:
    """Counts this run's refused destinations, thread-safely.

    The fetch pool runs these calls in dozens of threads and nothing else aggregates
    them — without this, a run in which half the sources were refused reports exactly
    like a clean one.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._refusals = 0
        self._destinations: set[tuple[str, str]] = set()

    def record(self, host: str, address: str) -> None:
        """Count one refusal, and remember the destination that caused it."""
        with self._lock:
            self._refusals += 1
            self._destinations.add((host, address))

    def reset(self) -> None:
        """Drop the run's counts — for a test, or a process that runs twice."""
        with self._lock:
            self._refusals = 0
            self._destinations.clear()

    def snapshot(self) -> DestinationRefusalStats:
        """A consistent copy of the counts, safe to report from."""
        with self._lock:
            return DestinationRefusalStats(
                refusals=self._refusals,
                destinations=tuple(sorted(self._destinations)),
            )


# One counter per process, which is one per run: every entry point imports this module
# once and runs the fetch stage once. Tests reset it per case.
DESTINATION_REFUSALS = _DestinationRefusalCounter()


def _embedded_note(address: str) -> str:
    """The address a translation prefix carries, named for the reader of a refusal.

    A refusal that reads only `64:ff9b::7f00:1` looks like a v6 address that happens to be
    unroutable. Naming what it carries is what tells the operator their source is being
    answered with loopback.
    """
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return ""
    embedded = embedded_ipv4(parsed)
    if embedded is None or (embedded.address.is_global and not embedded.address.is_multicast):
        return ""
    return f" (the {embedded.prefix} prefix carries {embedded.address})"


def refusal_reason(host: str, address: str) -> str:
    """The message a refused destination is reported with, and the run's record of it.

    Built from `DESTINATION_REFUSAL_PREFIX`, so the marker `utils/url_stats.py` recognizes
    is this module's own text rather than a second string that has to be kept in agreement
    with it.

    Counting here rather than at the call site is what makes the run's figure exact: the
    fetch path produces a refusal at two points — before the request is made, and after a
    redirect the client followed by itself — and both go through this function.
    """
    DESTINATION_REFUSALS.record(host, address)
    return (
        f"{DESTINATION_REFUSAL_PREFIX}{host}: it resolves to the "
        f"non-public address {address}{_embedded_note(address)}"
    )


def report_destination_refusals() -> DestinationRefusalStats:
    """Log the run's destination refusals and return the snapshot it logged.

    Deliberately distinct from the two other things a run's output says about a source:
    the URL health report's "dead" list (a fetch that failed three times running) and the
    TLS downgrade report (a request that went out without certificate verification). An
    operator scanning one run has to be able to tell "this source is dead" from "this
    source resolved somewhere private" from "this source was fetched insecurely" — three
    different responses, and only the first of them is about the source.
    """
    stats = DESTINATION_REFUSALS.snapshot()
    if stats.refusals == 0:
        log("[fetch-security] no destination was refused")
        return stats

    warning(
        f"[fetch-security] {stats.refusals} destination refusal(s) on "
        f"{stats.hosts_affected} host(s) — not dead sources: a refusal is about the "
        "resolved address, not a fetch that failed"
    )
    for host, address in stats.destinations:
        warning(f"[fetch-security]   refused {host}: non-public address {address}")
    return stats

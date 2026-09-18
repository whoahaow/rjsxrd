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


def _is_blocked_address(address: str) -> bool:
    """Whether a resolved address is one a fetch must never connect to.

    The rule is "globally routable, or refused": `ipaddress` already knows which answers
    are not — loopback, RFC 1918 and unique-local private space, link-local (which is
    where the cloud metadata endpoint `169.254.169.254` lives, the address that matters
    most because this pipeline runs on a VPS), unspecified `0.0.0.0/8`, carrier-grade NAT,
    reserved and documentation ranges. Multicast is spelled out because `is_global`
    reports it as global on this interpreter.

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
    return not parsed.is_global or parsed.is_multicast


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
    return f"{DESTINATION_REFUSAL_PREFIX}{host}: it resolves to the non-public address {address}"


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

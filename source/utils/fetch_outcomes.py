"""The vocabulary a fetch outcome shares between the fetch stage and the URL stats.

The rule this module exists for: only a failure that says something about the *source* may age
a URL toward removal from `URLS.txt`. An outcome that says something about *this run* instead —
a destination whose name resolved somewhere this pipeline must not connect to, a fetch the
operator's own safety policy curtailed, a call that asked for no attempt at all — is not
evidence about the source, and `utils/url_stats.py` counts it as nothing. Three of those used
to be indistinguishable from three dead fetches, and a curated source was deleted by a DNS
blip; the policy case deleted one because the operator had turned a safety setting *on*.

The producer marks each such outcome with a prefix from `NOT_SOURCE_EVIDENCE_PREFIXES` and the
consumer asks one question about the class (`is_source_evidence`), so a new member is a prefix
plus a marker at the site that produces it rather than a second special case in the stats.
`fetchers/destination_guard.py` builds its refusal from `DESTINATION_REFUSAL_PREFIX`, and the
fetch stage builds the outcomes that are its own through `run_condition()` below, so what the
stats recognize cannot drift from what the fetch stage produced. The module lives in `utils/`
because both sides need it and neither imports the other.

Why markers rather than a field on the fetch result. The text is what the history persists and
what a run's report prints, so a `FetchResult.refused` flag would be a second channel for a
fact the guard's own message already carries — and two channels can disagree. What holds the
two ends together is a test that pins each prefix at position 0
(`source/tests/test_fetch_posture.py::TestARefusalIsAnOutcomeOfItsOwn`): a substring test over
the same text is the defect the guard exists for, and a flag would have left that looseness
reachable through the history path anyway.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from utils.logger import log, warning

# The text every destination refusal's error begins with. Produced by
# `fetchers/destination_guard.py`, recognized by `utils/url_stats.py`; the test that pins
# the two sides together is in `source/tests/test_fetch_posture.py`.
DESTINATION_REFUSAL_PREFIX = "[fetch-security] refused "

# The text every other run-condition outcome begins with, built by `run_condition()` below —
# which is also what counts it. The refusal keeps a prefix of its own because its message, the
# report it appears in and the threat documentation were written around it, and because the
# guard produces it rather than the fetch stage.
RUN_CONDITION_PREFIX = "[fetch-run-condition] "

# The class: every prefix an error can begin with when the failure is not evidence about its
# source. A member is added here and marked at the site that produces it; `is_source_evidence`
# below is the one place the stats consult, so the class is covered rather than each member.
NOT_SOURCE_EVIDENCE_PREFIXES: tuple[str, ...] = (
    DESTINATION_REFUSAL_PREFIX,
    RUN_CONDITION_PREFIX,
)


def is_destination_refusal(error: str) -> bool:
    """Whether an error text is a refusal the destination guard produced.

    An empty string is not a refusal — it is the absence of a reason, which is what a
    successful fetch carries.
    """
    return error.startswith(DESTINATION_REFUSAL_PREFIX)


def is_source_evidence(error: str) -> bool:
    """Whether a failed fetch is evidence that its source is gone.

    The question `utils/url_stats.py` asks before it raises a URL's failure count, and it is
    asked about the class rather than about one member of it: an error beginning with any
    marker in `NOT_SOURCE_EVIDENCE_PREFIXES` describes the run — the network it is on, the
    rules it was started with — and never the source. Anything else, including an empty error,
    is a failure of the fetch and ages the URL exactly as it did before this existed.

    The comparison is on position 0, like the refusal's, and for the same reason: a transport
    error that merely quotes one of these markers is a failure of the fetch.

    The limit this accepts, stated rather than left as an argument: a text that *begins* with
    a marker is that class whoever wrote it. The fetch stage quotes what a failed attempt
    raised rather than authoring the text itself, so a quoted message that led with a marker
    would spare the source it came from. No raiser in this tree composes one — the client and
    the OS write their own messages — and that is the reason this is accepted rather than
    closed: closing it means marking every failure the fetch stage reports, which changes the
    text the history persists and the rule the default path states (a failure the fetch made
    carries no marker). What it can cost is bounded to the quiet direction: the URL is spared,
    never wrongly deleted. `source/tests/test_fetch_posture.py` holds the behaviour as a test,
    so a change to it has to move this record with it.
    """
    return not error.startswith(NOT_SOURCE_EVIDENCE_PREFIXES)


@dataclass(frozen=True)
class RunConditionStats:
    """A snapshot of one run's outcomes that say nothing about their source."""

    outcomes: int = 0
    conditions: tuple[tuple[str, str], ...] = ()

    @property
    def hosts_affected(self) -> int:
        """Distinct hosts behind those outcomes.

        A host curtailed on every attempt of a run counts once: the number an operator needs
        is how much of the source list was left unfetched, not how many fetches it took.
        """
        return len({host for host, _ in self.conditions})


class _RunConditionCounter:
    """Counts this run's run-condition outcomes, thread-safely.

    The fetch pool runs these calls in dozens of threads and nothing else aggregates them —
    without this, a run in which half the sources were curtailed by the operator's own safety
    policy reports exactly like a clean one.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._outcomes = 0
        self._conditions: set[tuple[str, str]] = set()

    def record(self, host: str, reason: str) -> None:
        """Count one outcome, and remember what curtailed it."""
        with self._lock:
            self._outcomes += 1
            self._conditions.add((host, reason))

    def reset(self) -> None:
        """Drop the run's counts — for a test, or a process that runs twice."""
        with self._lock:
            self._outcomes = 0
            self._conditions.clear()

    def snapshot(self) -> RunConditionStats:
        """A consistent copy of the counts, safe to report from."""
        with self._lock:
            return RunConditionStats(
                outcomes=self._outcomes,
                conditions=tuple(sorted(self._conditions)),
            )


# One counter per process, which is one per run: every entry point imports this module once and
# runs the fetch stage once. Tests reset it per case.
RUN_CONDITIONS = _RunConditionCounter()


def run_condition(host: str, reason: str) -> str:
    """The message a fetch reports when the run, and not the source, is the cause.

    Built from `RUN_CONDITION_PREFIX`, so the marker the stats recognize is this function's own
    text rather than a second string kept in agreement with it. Counting here rather than at
    each call site is what makes a run's figure exact: every site that produces one of these
    outcomes goes through this function, and a site that does not carries no marker — which is
    the inspectable difference between an outcome of this class and one that was forgotten.
    """
    RUN_CONDITIONS.record(host, reason)
    return f"{RUN_CONDITION_PREFIX}{reason}"


def report_run_conditions() -> RunConditionStats:
    """Log the run's run-condition outcomes and return the snapshot it logged.

    Deliberately distinct from the three other things a run's output says about a source: the
    URL health report's "dead" list (a fetch that failed three times running), the destination
    refusals (a name that resolved somewhere this pipeline must not connect to) and the TLS
    downgrade report (a request that went out without certificate verification). An operator
    scanning one run has to be able to tell "this source is dead" from "this run was not
    allowed to test it": only the first is about the source, and only the first justifies
    dropping a line from `URLS.txt`.
    """
    stats = RUN_CONDITIONS.snapshot()
    if stats.outcomes == 0:
        log("[fetch-security] no fetch was curtailed by this run's own rules")
        return stats

    warning(
        f"[fetch-security] {stats.outcomes} outcome(s) on {stats.hosts_affected} host(s) are "
        "not evidence about their source — not dead sources: this run's own rules curtailed "
        "the fetch"
    )
    for host, reason in stats.conditions:
        warning(f"[fetch-security]   {host}: {reason}")
    return stats

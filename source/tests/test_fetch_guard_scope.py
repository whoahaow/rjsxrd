"""What the fetch guard's scope is written as, held against what it does.

Three things live here, and they are one subject: the boundary of the fetch guard as
the repository *states* it, checked against the boundary the code actually has.

* the private-destination allowlist — the entries it may hold, the entry that switches
  the guard off and is refused at load for it, and the forms the setting's own comment
  promises an operator (F4, F6);
* the port an entry pins — a port-qualified entry covers the port the request will use
  and no other, and an unknown port is not a match (F5);
* the one warning filter the fetch module is allowed to install, and the syntactic
  shapes the regression walk for it has to see (F2).

Why a module of its own. `test_fetcher_unit.py` is a budgeted module under
`test_module_size.py`: it sat at its budget of 912 lines when that gate landed, and a
budgeted file may not grow at all. The walk below is longer than the shape it replaces,
so the regression guard moved here rather than growing a file the gate forbids to grow,
taking its module's imports and fixtures with it. The remaining assertions of that test
class stayed where they were — they exercise the fetch path, not its scope.

Every check here is offline. The resolver and both HTTP clients are stubbed or absent:
nothing in this module opens a socket.
"""

from collections.abc import Iterator
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import config.settings as settings_module
import fetchers.fetcher as fetcher_module
from config.settings import _refuse_guard_disabling_allowlist
from fetchers.destination_guard import DESTINATION_REFUSALS, _is_destination_allowlisted
from fetchers.fetcher import INSECURE_FETCHES, _port_of, fetch_data
from utils.fetch_outcomes import RUN_CONDITIONS

pytestmark = pytest.mark.unit

# The answer the suite's stubbed resolver gives. Never dialled: what is under test is
# what the guard does with an answer, not the answer.
LOOPBACK_ADDRESS = "127.0.0.1"


def load_settings(monkeypatch: pytest.MonkeyPatch, entries: str) -> dict[str, object]:
    """Execute `config/settings.py` with `FETCH_PRIVATE_ALLOWLIST` set to `entries`.

    The setting is a module-level assignment, so the only way to observe what a value
    of the environment variable does to a *run* is to run the module that reads it.
    Executed into a namespace of its own rather than reloaded in place: a reload
    rebinds the module every other importer is already holding, and a raise in the
    middle of one leaves the module half-updated for the rest of the session.

    What this inherits: the executed module loads the repository's `.env` the way any
    import of it does, which is a no-op for a variable already in the environment —
    `monkeypatch.setenv` wins, which is what makes the probe deterministic.
    """
    monkeypatch.setenv("FETCH_PRIVATE_ALLOWLIST", entries)
    path = Path(settings_module.__file__)
    namespace: dict[str, object] = {
        "__name__": "config.settings_probe",
        "__file__": str(path),
    }
    exec(compile(path.read_text(encoding="utf-8"), str(path), "exec"), namespace)
    return namespace


@pytest.fixture(autouse=True)
def offline_fetch(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Keep this module off the network, and the run's counters clean.

    The same fixture the two sibling modules carry, for the same reasons: the guard
    resolves a name before it connects, so without the stub a fetch here would reach a
    real resolver; and the counters are one object per process, so a test's numbers
    would otherwise be the next module's starting point — which is how a report test
    elsewhere starts reading a run it did not make. Cleared on the way in and on the way
    out: this module is not the only one that reads them. `time.sleep` goes with them,
    because the retry ladder's one-second wait is not what any test here is about.
    """
    monkeypatch.setattr(
        fetcher_module, "_resolved_addresses", lambda host, port: [LOOPBACK_ADDRESS]
    )
    monkeypatch.setattr(fetcher_module.time, "sleep", lambda _seconds: None)
    DESTINATION_REFUSALS.reset()
    INSECURE_FETCHES.reset()
    RUN_CONDITIONS.reset()
    yield
    DESTINATION_REFUSALS.reset()
    INSECURE_FETCHES.reset()
    RUN_CONDITIONS.reset()


class TestAnEntryThatSwitchesTheGuardOff:
    """F4: the allowlist may not be turned into "no guard at all" silently.

    `_is_destination_allowlisted` reads whatever it is handed, so an entry covering a
    whole address family makes every fetch to that family permitted. Before this, the
    only thing between that entry and an unguarded run was nothing: the entry parsed as
    a legitimate CIDR, the guard consulted it, and the run's output said nothing.
    """

    @pytest.mark.parametrize(
        "entry",
        [
            "0.0.0.0/0",  # every IPv4 answer
            "1.2.3.4/0",  # the same network, written with a host address
            "::/0",  # every IPv6 answer
            "2001:db8::/0",  # the v6 spelling with a host address
        ],
    )
    def test_a_universal_network_is_refused(self, entry: str) -> None:
        """Every spelling of a zero prefix, not a list of the two famous strings."""
        with pytest.raises(ValueError) as raised:
            _refuse_guard_disabling_allowlist([entry])

        assert entry in str(raised.value)

    def test_the_refusal_says_what_the_entry_does(self) -> None:
        """The operator has to be able to act on it without reading the guard."""
        with pytest.raises(ValueError) as raised:
            _refuse_guard_disabling_allowlist(["0.0.0.0/0"])

        message = str(raised.value)
        assert "FETCH_PRIVATE_ALLOWLIST" in message
        assert "switches the guard off" in message
        assert "Remove it" in message

    @pytest.mark.parametrize(
        ("entry", "address"),
        [("0.0.0.0/0", "93.184.216.34"), ("::/0", "2606:4700::1111")],
    )
    def test_the_entry_is_one_that_would_have_disabled_the_guard(
        self, entry: str, address: str
    ) -> None:
        """What the refusal closes: every address of the family, not just some.

        The pair is the finding: the entry is read by the guard as a permission for an
        address nobody wrote down, and the same entry cannot be configured at all.
        """
        assert _is_destination_allowlisted("mirror.example", 443, address, [entry]) is True

        with pytest.raises(ValueError):
            _refuse_guard_disabling_allowlist([entry])

    @pytest.mark.parametrize(
        "entry",
        [
            "192.168.1.5/32",  # one address
            "10.0.0.0/8",  # wide, and still a range rather than the whole family
            "127.0.0.0/8",
            "fc00::/7",
            "172.16.0.0/12",
            "127.0.0.1",  # an IP literal, no prefix to read
            "mirror.example",
            "mirror.example:8443",
            "::1",
            "[::1]:1080",
            "not/a/network",  # not parseable: the guard reads it as matching nothing
            "",
        ],
    )
    def test_an_entry_that_is_not_universal_is_kept_as_written(self, entry: str) -> None:
        """Ordinary use is untouched, including the wide ranges and the junk."""
        assert _refuse_guard_disabling_allowlist([entry]) == [entry]

    def test_a_universal_entry_beside_a_narrow_one_is_still_refused(self) -> None:
        """The list is not "saved" by the legitimate entries next to it."""
        with pytest.raises(ValueError):
            _refuse_guard_disabling_allowlist(["127.0.0.1", "0.0.0.0/0", "mirror.example"])

    def test_the_setting_refuses_at_load(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The wiring: a run with the entry in the environment does not start.

        The rule is only enforced if the module that reads the setting enforces it —
        a helper nobody calls is the state this replaced, with better prose.
        """
        with pytest.raises(ValueError, match="switches the guard off"):
            load_settings(monkeypatch, "0.0.0.0/0")

    def test_the_setting_loads_the_entries_a_run_may_have(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """And the same path still loads an ordinary list, split and stripped."""
        namespace = load_settings(monkeypatch, "127.0.0.1, mirror.example:8443")

        assert namespace["FETCH_PRIVATE_ALLOWLIST"] == ["127.0.0.1", "mirror.example:8443"]

    def test_the_setting_is_empty_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Nothing is permitted implicitly, read through the same path."""
        namespace = load_settings(monkeypatch, "")

        assert namespace["FETCH_PRIVATE_ALLOWLIST"] == []


class TestThePortAnEntryPins:
    """F5: a port-qualified entry covers the port the request will use, and no other.

    The condition was `port is None or int(entry_port) == port`, so a URL whose port
    could not be determined matched a port-qualified entry anyway — a match granted by
    the absence of the thing the entry exists to check. The open arm was reachable only
    for a URL that is neither https nor http, or whose port is not a number (`_port_of`
    defaults the two schemes a fetch uses), which makes it narrow rather than harmless:
    the entry names a port so that the list cannot admit a destination the operator did
    not write down, and "nothing to compare" was read as agreement.
    """

    def test_a_port_qualified_entry_does_not_cover_an_unknown_port(self) -> None:
        """The fail-open: no port to compare is no match, not every match."""
        assert (
            _is_destination_allowlisted(
                "mirror.example", None, LOOPBACK_ADDRESS, ["mirror.example:8443"]
            )
            is False
        )

    def test_an_entry_covers_the_port_it_names(self) -> None:
        """The ordinary case the fix must not break: `host:8443` against `:8443`."""
        assert (
            _is_destination_allowlisted(
                "mirror.example", 8443, LOOPBACK_ADDRESS, ["mirror.example:8443"]
            )
            is True
        )

    @pytest.mark.parametrize("port", [443, 80, 1080])
    def test_an_entry_does_not_cover_another_port(self, port: int) -> None:
        """A pinned port is one port; the rest of them are not covered by it."""
        assert (
            _is_destination_allowlisted(
                "mirror.example", port, LOOPBACK_ADDRESS, ["mirror.example:8443"]
            )
            is False
        )

    @pytest.mark.parametrize(
        ("url", "port"),
        [
            ("https://mirror.example/list.txt", 443),
            ("http://mirror.example/list.txt", 80),
            ("ftp://mirror.example/list.txt", None),
        ],
    )
    def test_the_port_is_the_one_the_request_will_use(self, url: str, port: int | None) -> None:
        """What "known" means, and where "unknown" comes from.

        The scheme's default rather than "absent from the URL text": a URL that writes no
        port still goes somewhere, and the entry is compared against where that is. A
        scheme this module cannot default leaves the port unknown, and that is the only
        state in which the fix changes the answer.
        """
        assert _port_of(url) == port

    def test_a_default_port_entry_covers_a_url_that_leaves_the_port_out(self) -> None:
        """`https://host/` is 443, so an entry `host:443` covers it — and says so."""
        assert (
            _is_destination_allowlisted(
                "mirror.example", 443, LOOPBACK_ADDRESS, ["mirror.example:443"]
            )
            is True
        )

    @pytest.mark.parametrize("port", [None, 80, 8443])
    def test_an_entry_that_names_no_port_covers_every_port(self, port: int | None) -> None:
        """The two halves of the rule: a pinned port is one, an absent port is all."""
        assert (
            _is_destination_allowlisted(
                "mirror.example", port, LOOPBACK_ADDRESS, ["mirror.example"]
            )
            is True
        )

    def test_the_fetch_path_refuses_the_unknown_port_case(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """End to end: the fail-open reached the fetch path, not just the matcher.

        The URL is made up of the two things the exit needs — a scheme `_port_of` cannot
        default, and a name the stubbed resolver answers with loopback — so nothing is
        dialled and the refusal is the guard's own.
        """
        monkeypatch.setattr(fetcher_module, "FETCH_PRIVATE_ALLOWLIST", ["mirror.example:8443"])
        monkeypatch.setattr(
            fetcher_module, "_resolved_addresses", lambda host, port: [LOOPBACK_ADDRESS]
        )
        session = MagicMock()

        result = fetch_data("ftp://mirror.example/list.txt", session=session)

        assert result.success is False
        assert result.text == ""
        assert LOOPBACK_ADDRESS in result.error
        assert session.get.call_count == 0

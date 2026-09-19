"""What the fetch guard's scope is written as, held against what it does.

Three things live here, and they are one subject: the boundary of the fetch guard as
the repository *states* it, checked against the boundary the code actually has.

* the private-destination allowlist — the entries it may hold, the entry that switches
  the guard off and is refused at load for it, and the forms the setting's own comment
  promises an operator (F4, F6);
* the port an entry pins — a port-qualified entry covers the port the request will use
  and no other, and an unknown port is not a match (F5);
* the one warning filter the fetch module is allowed to install, the shapes a
  regression walk for it has to see, and the shapes it still cannot (F2).

Why a module of its own. `test_fetcher_unit.py` is a budgeted module under
`test_module_size.py`: it sat at its budget of 912 lines when that gate landed, and a
budgeted file may not grow at all. The walk below is longer than the shape it replaces,
so the regression guard moved here rather than growing a file the gate forbids to grow.
The three assertions of that test class that exercise the fetch path rather than its
scope stayed where they were, and the moved guard's module now carries its own copy of
the offline fixture (the resolver stub and the run's counters, both process-wide).

Every check here is offline. The resolver and both HTTP clients are stubbed or absent:
nothing in this module opens a socket.
"""

import ast
import re
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


BACKTICKED = re.compile(r"`([^`]+)`")

# The entries the setting's own comment holds out to an operator, each with the
# destination it is supposed to name: the URL's host, the port the request will use, and
# the address the name resolved to. And the entries the same comment names as refused.
DOCUMENTED_ENTRIES: dict[str, tuple[str, int | None, str]] = {
    "127.0.0.1": ("mirror.example", 443, "127.0.0.1"),
    "192.168.1.5/32": ("mirror.example", 443, "192.168.1.5"),
    "[::1]": ("::1", 443, "::1"),
    "[::1]:1080": ("::1", 1080, "::1"),
}
DOCUMENTED_REFUSALS: frozenset[str] = frozenset({"0.0.0.0/0", "::/0"})


def documented_examples() -> set[str]:
    """The entry-shaped examples in the comment above `FETCH_PRIVATE_ALLOWLIST`.

    Read out of the module's own source instead of being restated here: the forms the
    comment promises are the forms the code has to accept, so the promise is the thing
    to read. "Entry-shaped" is a backticked token carrying a `.`, a `/` or a `[` — the
    characters an address, a CIDR or a bracketed v6 host cannot be written without. The
    placeholder forms (`host`, `host:port`) name a shape rather than a destination and
    are covered by the cases below instead; a token with none of the three is prose.
    """
    lines = Path(settings_module.__file__).read_text(encoding="utf-8").splitlines()
    start = next(index for index, line in enumerate(lines) if line.startswith("FETCH_PRIVATE"))
    comment: list[str] = []
    for line in reversed(lines[:start]):
        if not line.startswith("#"):
            break
        comment.append(line)

    return {
        token
        for token in BACKTICKED.findall("\n".join(reversed(comment)))
        if set(token) & set("./[")
    }


class TestTheFormAnEntryIsWrittenIn:
    """F6: the setting's comment and the matcher must name the same destinations.

    The comment documented `host` / `host:port`, and an operator who wrote a v6 address
    that way (`[::1]:8080`) got an entry that silently never matched: `rpartition(":")`
    left the host as `"[::1]"`, while `urlparse` hands the URL's host back unwrapped as
    `"::1"`. Nothing warned — the entry failed closed, which is why this is a
    correctness-of-documentation bug rather than a hole, and why an entry that silently
    does nothing is worse than one that errors.

    The brackets now come off, so the documented form is the form that works. The cases
    below are read out of that comment and matched against the implementation, the same
    two-artefacts-one-contract shape `test_fetch_posture.py` uses for the token hosts: a
    form promised in the comment with no case here fails the suite, rather than an
    operator discovering it.
    """

    def test_every_documented_example_is_answered_for(self) -> None:
        """A promised form the tests do not answer is a promise nobody checks."""
        assert documented_examples() == set(DOCUMENTED_ENTRIES) | DOCUMENTED_REFUSALS

    @pytest.mark.parametrize(
        ("entry", "host", "port", "address"),
        [(entry, *case) for entry, case in DOCUMENTED_ENTRIES.items()],
    )
    def test_a_documented_entry_covers_the_destination_it_names(
        self, entry: str, host: str, port: int | None, address: str
    ) -> None:
        """`[::1]:1080` was the dead one: the documented form now matches."""
        assert _is_destination_allowlisted(host, port, address, [entry]) is True

    @pytest.mark.parametrize("entry", sorted(DOCUMENTED_REFUSALS))
    def test_a_documented_refusal_is_refused(self, entry: str) -> None:
        """The comment names these as refused, and the load refuses them."""
        with pytest.raises(ValueError):
            _refuse_guard_disabling_allowlist([entry])

    def test_a_bracketed_address_without_a_port_covers_that_address(self) -> None:
        """`[::1]` and `::1` name the same destination, under either spelling."""
        assert _is_destination_allowlisted("mirror.example", 443, "::1", ["[::1]"]) is True
        assert _is_destination_allowlisted("mirror.example", 443, "::1", ["::1"]) is True

    @pytest.mark.parametrize("port", [443, 80, None])
    def test_a_bracketed_entry_with_a_port_covers_only_that_port(self, port: int | None) -> None:
        """The bracket changes how the host is written, not how the port is read."""
        assert _is_destination_allowlisted("mirror.example", port, "::1", ["[::1]:1080"]) is False

    def test_a_bare_v6_address_is_still_read_as_an_address(self) -> None:
        """`::1` is an address, not a host with port `1`."""
        assert _is_destination_allowlisted("mirror.example", 1, "::1", ["::1"]) is True
        assert _is_destination_allowlisted("mirror.example", 1, "2001:db8::1", ["::1"]) is False

    def test_a_bare_v6_address_with_a_port_is_not_expressible(self) -> None:
        """What the bracket is for, stated as a test: `::1:1080` is an address.

        Read as `0:0:0:0:0:0:1:1080`, so it covers a URL that resolves to that address
        and no URL with host `::1`, whatever its port. The bracketed form is the only way
        to write a qualified v6 entry, and the comment says so.
        """
        assert _is_destination_allowlisted("mirror.example", 1080, "::1:1080", ["::1:1080"]) is True
        assert _is_destination_allowlisted("::1", 1080, "::1", ["::1:1080"]) is False

    def test_a_bracketed_host_name_is_read_as_the_name_it_wraps(self) -> None:
        """The brackets are URL syntax for a host, not part of the host."""
        assert (
            _is_destination_allowlisted(
                "mirror.example", 443, LOOPBACK_ADDRESS, ["[mirror.example]"]
            )
            is True
        )


FETCH_SOURCE = Path(fetcher_module.__file__).read_text(encoding="utf-8")

# The two functions that install a filter. Both are read by name rather than by the
# `warnings.` prefix, so an alias cannot smuggle one past the walk.
FILTER_FUNCTIONS = ("filterwarnings", "simplefilter")

# `warnings.filterwarnings` at a module's top level silences that warning for the whole
# process, for the rest of the run, from every module — the defect this guards. Each
# entry below is that same defect written another way, all of them one line long.
INSTALLED_AT_IMPORT: dict[str, str] = {
    "the shape the walk was written for": 'warnings.filterwarnings("ignore")\n',
    "an aliased module": 'import warnings as _w\n_w.filterwarnings("ignore")\n',
    "an aliased from-import": 'from warnings import filterwarnings as _fw\n_fw("ignore")\n',
    "the other function": 'from warnings import simplefilter\nsimplefilter("ignore")\n',
    "inside a module-level if": 'if True:\n    warnings.filterwarnings("ignore")\n',
    "inside a module-level try": (
        'try:\n    warnings.filterwarnings("ignore")\nexcept Exception:\n    pass\n'
    ),
    "inside a module-level with": 'with open(__file__):\n    warnings.filterwarnings("ignore")\n',
    "inside a module-level for": 'for _ in (0,):\n    warnings.filterwarnings("ignore")\n',
    "inside a module-level class body": 'class _Probe:\n    warnings.filterwarnings("ignore")\n',
    "inside a def the module body calls": (
        'def _install():\n    warnings.filterwarnings("ignore")\n_install()\n'
    ),
    "inside a def another called def calls": (
        'def _inner():\n    warnings.filterwarnings("ignore")\n'
        "def _outer():\n    _inner()\n_outer()\n"
    ),
}

# The other half: the same call written in a place that does not run at import, so it is
# not the defect. The sanctioned site is one of these — a filter installed for the length
# of one call silences that call and nothing else.
NOT_INSTALLED_AT_IMPORT: dict[str, str] = {
    "a def nothing calls": 'def _never():\n    warnings.filterwarnings("ignore")\n',
    "a lambda": '_deferred = lambda: warnings.filterwarnings("ignore")\n',
    "a def only an uncalled def calls": (
        'def _runtime():\n    warnings.filterwarnings("ignore")\ndef _caller():\n    _runtime()\n'
    ),
}


def _nodes_reached_at_import(node: ast.AST) -> Iterator[ast.AST]:
    """Every node reached while `node` executes at import, stopping at function bodies.

    A function body runs when the function is called, not where it is written, so the
    walk stops there — the `def` statement itself is reached (it binds the name, and its
    decorators and defaults are evaluated) but its body is not, and the caller decides
    about that by entering the body of the functions the module actually calls.
    Everything else is reached: a module-level `if`, `try`, `with`, `for` or `while`
    body, and a `class` body, which executes when it is defined.
    """
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        yield node
        for decorator in node.decorator_list:
            yield from _nodes_reached_at_import(decorator)
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                yield from _nodes_reached_at_import(default)
        return
    if isinstance(node, ast.Lambda):
        return
    yield node
    for child in ast.iter_child_nodes(node):
        yield from _nodes_reached_at_import(child)


def _warnings_names(tree: ast.Module) -> tuple[set[str], set[str]]:
    """The local names bound to the `warnings` module and to its filter functions.

    Both spellings count, because both install the same filter and both are one line to
    write: `import warnings as _w` binds the module, `from warnings import filterwarnings
    as _fw` binds the function itself.
    """
    modules = {"warnings"}
    functions: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(
                alias.asname or alias.name for alias in node.names if alias.name == "warnings"
            )
        elif isinstance(node, ast.ImportFrom) and node.module == "warnings":
            functions.update(
                alias.asname or alias.name for alias in node.names if alias.name in FILTER_FUNCTIONS
            )
    return modules, functions


def _installs_a_filter(call: ast.Call, modules: set[str], functions: set[str]) -> str | None:
    """The name this call installs a filter through, or None when it is not one."""
    func = call.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        if func.value.id in modules and func.attr in FILTER_FUNCTIONS:
            return f"{func.value.id}.{func.attr}"
        return None
    if isinstance(func, ast.Name) and func.id in functions:
        return func.id
    return None


def installations_at_import(source: str) -> list[tuple[int, str]]:
    """`(line, name)` for every warnings filter this module installs at import.

    The walk reads shapes rather than text, because the defect is one line to write in
    more ways than the one it was originally guarded against: through an aliased module
    or an aliased from-import, from inside any module-level `if` / `try` / `with` / `for`
    / `class` body, or from inside a `def` that the module body calls — directly, or
    through another module-level function that calls it.

    A test cannot see the install by reading `warnings.filters` at run time: pytest wraps
    each test in its own warning context and restores the list, so the runtime answer is
    the same whether or not the module installed anything. The source is read instead.

    What this cannot catch, stated rather than left to be assumed: a name built at run
    time (`getattr(warnings, "filter" + "warnings")`), a filter installed by a helper in
    *another* module imported for its side effect, a function defined inside a function,
    and anything reached only after import. `test_what_the_walk_cannot_see` holds each of
    those as a case, so the boundary is measured rather than claimed.
    """
    tree = ast.parse(source)
    modules, functions = _warnings_names(tree)

    defined: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {
        node.name: node
        for node in _nodes_reached_at_import(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    calls = [node for node in _nodes_reached_at_import(tree) if isinstance(node, ast.Call)]
    scanned: set[str] = set()
    while True:
        # A module-level function the module body calls runs at import, so its body is
        # read too — transitively, because what it calls runs with it.
        called = {
            call.func.id
            for call in calls
            if isinstance(call.func, ast.Name)
            and call.func.id in defined
            and call.func.id not in scanned
        }
        if not called:
            break
        for name in called:
            scanned.add(name)
            calls.extend(
                node
                for statement in defined[name].body
                for node in _nodes_reached_at_import(statement)
                if isinstance(node, ast.Call)
            )

    installed: dict[tuple[int, str], None] = {}
    for call in calls:
        label = _installs_a_filter(call, modules, functions)
        if label is not None:
            installed[(call.lineno, label)] = None
    return sorted(installed)


class TestNoWarningFilterIsInstalledAtImport:
    """F2: the regression walk for the one warning the client must keep reporting.

    The ignore used to sit at the client module's top level, where it applied to every
    warning of that shape for the rest of the process. The walk that replaced it
    recognised exactly one syntactic shape, and measured against five other ways of
    writing the same line, all of which install the filter at import and left the suite
    green. This is that walk, widened to the class and moved here with its module: the
    module it reads is the one the defect was in.
    """

    def test_the_fetch_module_installs_nothing_at_import(self) -> None:
        """The guard itself, against the real source."""
        assert installations_at_import(FETCH_SOURCE) == []

    def test_the_sanctioned_call_is_in_the_file_and_is_not_an_import_time_one(self) -> None:
        """The one place that may use the attribute, and why the walk lets it pass.

        `_silence_client_tls_warning` calls `warnings.filterwarnings` inside a context
        manager for the single call that sets `verify=False`. It is identified by *that*
        — a filter that does not run at import — rather than by its line, so moving the
        function or rewriting the line around it cannot make the guard pass by accident.
        """
        assert "warnings.filterwarnings(" in FETCH_SOURCE
        assert "_silence_client_tls_warning" in FETCH_SOURCE
        assert installations_at_import(FETCH_SOURCE) == []

    @pytest.mark.parametrize("shape", list(INSTALLED_AT_IMPORT))
    def test_each_way_of_installing_it_at_import_is_seen(self, shape: str) -> None:
        """Every measured blind form, injected into the real module's source."""
        found = installations_at_import(INSTALLED_AT_IMPORT[shape] + FETCH_SOURCE)

        assert found, f"the walk did not see {shape!r}"

    @pytest.mark.parametrize("shape", list(NOT_INSTALLED_AT_IMPORT))
    def test_a_call_that_does_not_run_at_import_is_not_seen(self, shape: str) -> None:
        """The other direction: a deferred call is not the defect."""
        assert installations_at_import(NOT_INSTALLED_AT_IMPORT[shape] + FETCH_SOURCE) == []

    @pytest.mark.parametrize(
        ("shape", "source"),
        [
            (
                "a name built at run time",
                'import warnings\nbuild = getattr(warnings, "filter" + "warnings")\nbuild("ignore")\n',
            ),
            (
                "a helper in another module",
                "from _installer import install\ninstall()\n",
            ),
            (
                "a def defined inside a called def",
                "def _outer():\n    def _inner():\n        warnings.filterwarnings"
                '("ignore")\n    _inner()\n_outer()\n',
            ),
            (
                "a wildcard import",
                'from warnings import *\nfilterwarnings("ignore")\n',
            ),
        ],
    )
    def test_what_the_walk_cannot_see(self, shape: str, source: str) -> None:
        """The residual, as cases: each of these installs the filter and is missed.

        Held as tests so the boundary is a measurement rather than a claim — if one of
        them ever starts being caught, this fails and says so, and if someone assumes
        the walk is total, these are what they are assuming wrongly.
        """
        assert installations_at_import(source + FETCH_SOURCE) == [], shape

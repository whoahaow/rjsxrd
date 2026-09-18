"""The figures the docs state about this suite, re-derived from the suite.

Three cards in a row moved the same numbers and each time the documentation went
stale behind them: K09 corrected ``682/28`` to ``705/30`` by hand, K09b
re-measured to ``706``, and K05b then added 18 tests plus a new test module
without touching a doc. A figure corrected by hand is wrong again by the next
card, so the correction is paired with this guard: it collects the suite at run
time and fails when a documented figure disagrees with what was collected.

What it guards, and where each expectation comes from:

* the test total and the module count — the items pytest collected for this
  session, captured by the hook in ``conftest.py`` *before* `-m` deselects
  anything, so the answer does not depend on the selection the run uses;
* the `-m unit` / `-m integration` split — the markers on those same items;
* every row of the per-file table in ``testing.md`` and ``testing.en.md`` — one
  row per collected module, and the count in it;
* the ``test_*.py`` listing in both README trees — the same module set in both
  languages, so a new module cannot land in one and be forgotten in the other;
* how many lines state each figure — a README states the totals twice (the file
  tree and the prose sentence) and must keep stating them twice, so one site
  cannot be reworded while the other keeps the file looking guarded;
* the marker registry in ``pyproject.toml`` — a registered marker no test
  carries is a claim the suite does not make (``slow`` was one).

What it does NOT guard, so nobody assumes otherwise:

* the coverage percentages. Re-deriving those means a second instrumented run
  inside the suite; they stay a hand-measured figure, and a doc that states one
  names the command that produced it;
* the warning counts, for the same reason;
* the prose around the figures. This test reads numbers, not claims.

Run it with the whole suite: the guard answers about what was collected, so a
single-module invocation (`pytest tests/test_docs_figures.py`) answers about
that module. `pytest -q` and marker selections (`-m unit`, `-m integration`)
all see the whole collection — the snapshot is taken before deselection.

Every mismatch is reported in one failure message with ``path:line``, so the
next drift is corrected in a single pass instead of one review cycle per figure.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Sequence
from pathlib import Path

import pytest

from tests.support import COLLECTED_ITEMS

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = REPO_ROOT / "pyproject.toml"

# "724 теста, 31 файл" / "724 tests, 31 files" — the README tree annotation and
# the README prose sentence.
RU_TOTALS = re.compile(r"(?P<tests>\d+)\s+тест(?:ов|а)?\s*,\s*(?P<files>\d+)\s+файл(?:ов|а)?")
EN_TOTALS = re.compile(r"(?P<tests>\d+)\s+tests?\s*,\s*(?P<files>\d+)\s+files?")
# "724 теста в 31 файле" / "724 tests in 31 files" — the architecture and
# testing pages.
RU_FILES = re.compile(r"(?P<tests>\d+)\s+тест(?:ов|а)?\s+в\s+(?P<files>\d+)\s+файл(?:ах|е)")
EN_FILES = re.compile(r"(?P<tests>\d+)\s+tests?\s+in\s+(?P<files>\d+)\s+files?")
# A bare count: "724 теста" / "724 tests" (the development-environment page).
RU_BARE = re.compile(r"(?P<tests>\d+)\s+тест(?:ов|а)?\b")
EN_BARE = re.compile(r"(?P<tests>\d+)\s+tests?\b")
# The marker split: "694 и 30 тестов из 724" / "694 and 30 tests out of 724".
RU_SPLIT = re.compile(
    r"(?P<unit>\d+)\s+и\s+(?P<integration>\d+)\s+тест(?:ов|а)?\s+из\s+(?P<total>\d+)"
)
EN_SPLIT = re.compile(
    r"(?P<unit>\d+)\s+and\s+(?P<integration>\d+)\s+tests?\s+out of\s+(?P<total>\d+)"
)
# A row of the per-file table: "| `test_progress.py` | 6 | tqdm consolidation |".
TABLE_ROW = re.compile(r"^\|\s*`(test_[a-z0-9_]+\.py)`\s*\|\s*(?P<count>\d+)\s*\|")
# A test module inside a README's file tree: " │   ├─ test_progress.py".
TREE_ENTRY = re.compile(r"^[^\S\n]*[│][^\S\n]*[├└]─\s*(test_[a-z0-9_]+\.py)")
# The `tests/` node of that tree, and the next directory node that ends the
# subtree. `scripts/` lists `test_telegram_proxies.py` — an entry point that is
# not a test module — at the same indentation, so the listing has to be read
# per subtree instead of per line.
TREE_TESTS_DIR = re.compile(r"^[^\S\n]*(?:[│][^\S\n]*)?[├└]─\s*tests/")
TREE_DIRECTORY_ENTRY = re.compile(r"^[^\S\n]*(?:[│][^\S\n]*)?[├└]─\s*[\w.-]+/")

# Every site that states "N tests in M files" (or the bare test count), with the
# number of lines it must match. The count is part of the contract: both READMEs
# state the totals twice — the file-tree annotation and the prose sentence — so a
# check that only asked "did anything match?" would let one of the two be reworded
# while the file still looked guarded.
COUNT_SITES: tuple[tuple[str, re.Pattern[str], int], ...] = (
    ("README.md", RU_TOTALS, 2),
    ("README.en.md", EN_TOTALS, 2),
    ("docs/development/architecture.md", RU_FILES, 1),
    ("docs/development/architecture.en.md", EN_FILES, 1),
    ("docs/development/development-environment.md", RU_BARE, 1),
    ("docs/development/development-environment.en.md", EN_BARE, 1),
    ("docs/development/testing.md", RU_FILES, 1),
    ("docs/development/testing.en.md", EN_FILES, 1),
)

# Every site that states the `-m unit` / `-m integration` split, with how many
# lines it must match — the same contract, for the same reason.
SPLIT_SITES: tuple[tuple[str, re.Pattern[str], int], ...] = (
    ("docs/development/testing.md", RU_SPLIT, 1),
    ("docs/development/testing.en.md", EN_SPLIT, 1),
)

# Every per-file table, in both languages.
TABLE_SITES: tuple[str, ...] = (
    "docs/development/testing.md",
    "docs/development/testing.en.md",
)

# The two file trees that list the test modules.
TREE_SITES: tuple[str, ...] = ("README.md", "README.en.md")


def collected(request: pytest.FixtureRequest) -> list[pytest.Item]:
    """The whole collected suite, before `-m` narrowed it.

    The snapshot is written by the `pytest_collection_modifyitems` hook in
    `tests/conftest.py`. Without it, reading the stash raises a bare
    ``KeyError: <_pytest.stash.StashKey object at 0x…>`` — loud, but naming no
    file, cause or remedy — so the missing case reports the hook that did not run
    instead. The failure stays hard: every figure below is derived from this
    collection, and answering from anything else would defeat the guard.
    """
    if COLLECTED_ITEMS not in request.config.stash:
        raise AssertionError(
            "the collection snapshot is missing: the `pytest_collection_modifyitems` "
            "hook in `tests/conftest.py` did not run, so this guard cannot see the "
            "suite it checks the documented figures against. Check that conftest.py is "
            "collected and that the hook still writes the stash (it runs `tryfirst`), "
            "then re-run the suite."
        )
    return request.config.stash[COLLECTED_ITEMS]


def module_counts(items: Sequence[pytest.Item]) -> dict[str, int]:
    """Collected tests per test module, keyed by file name."""
    counts: dict[str, int] = {}
    for item in items:
        name = Path(item.nodeid.split("::", 1)[0]).name
        counts[name] = counts.get(name, 0) + 1
    return counts


def marker_counts(items: Sequence[pytest.Item]) -> dict[str, int]:
    """Collected tests per marker name, over every marker each test carries."""
    counts: dict[str, int] = {}
    for item in items:
        for marker in item.iter_markers():
            counts[marker.name] = counts.get(marker.name, 0) + 1
    return counts


def find(path: str, pattern: re.Pattern[str]) -> list[tuple[int, re.Match[str]]]:
    """Every match of `pattern` in the repo-relative file, with its line number.

    Markdown emphasis is stripped before matching: `testing.md` states the
    figures in bold, and a pattern describes the figure, not its formatting.
    """
    lines = (REPO_ROOT / path).read_text(encoding="utf-8").splitlines()
    found: list[tuple[int, re.Match[str]]] = []
    for number, raw in enumerate(lines, start=1):
        match = pattern.search(raw.replace("**", ""))
        if match:
            found.append((number, match))
    return found


def tree_modules(path: str) -> set[str] | None:
    """The test modules listed in a README's `tests/` subtree, or None.

    None means the subtree was not found — a reworded tree would otherwise read
    as "every module is missing", which points at the wrong thing.
    """
    lines = (REPO_ROOT / path).read_text(encoding="utf-8").splitlines()
    start = next((number for number, line in enumerate(lines) if TREE_TESTS_DIR.search(line)), None)
    if start is None:
        return None
    listed: set[str] = set()
    for line in lines[start + 1 :]:
        if TREE_DIRECTORY_ENTRY.search(line):
            break
        entry = TREE_ENTRY.search(line)
        if entry:
            listed.add(entry.group(1))
    return listed


def report(problems: Sequence[str], headline: str) -> None:
    """Fail with every problem at once, so one pass fixes the whole drift."""
    assert not problems, "\n".join((headline, *(f"  {problem}" for problem in problems)))


def site_count_problem(
    path: str,
    pattern: re.Pattern[str],
    expected: int,
    found: int,
    registry: str,
) -> str:
    """Why a figure's site count disagrees, and what the fix is in that direction.

    The count is a contract in both directions and the remedies are opposite:
    fewer matches than expected means the sentence this pattern describes was
    reworded or lost, and more means a site was legitimately added whose registry
    row has not moved with it. A message that only names the first direction
    sends the reader of the too-many case looking for a lost sentence that was
    never lost, so this states which case fired and what to change.
    """
    if found < expected:
        remedy = (
            "the sentence this pattern describes was reworded or lost — restore it, or "
            "extend the guard if the wording genuinely changed"
        )
    else:
        remedy = f"a site was added — bump this entry's expected count in {registry}"
    return f"{path}: expected {expected} sites for {pattern.pattern!r}, found {found} — {remedy}"


class TestDocumentedSuiteSize:
    """The totals the docs state, against the totals the suite has."""

    def test_documented_suite_size_matches_the_collection(
        self, request: pytest.FixtureRequest
    ) -> None:
        """Every "N tests in M files" site matches the collected suite."""
        items = collected(request)
        total = len(items)
        files = len(module_counts(items))
        problems: list[str] = []

        for path, pattern, expected in COUNT_SITES:
            found = find(path, pattern)
            if len(found) != expected:
                problems.append(
                    site_count_problem(path, pattern, expected, len(found), "COUNT_SITES")
                )
            for number, match in found:
                documented = int(match.group("tests"))
                if documented != total:
                    problems.append(
                        f"{path}:{number}: docs say {documented} tests, the suite collects {total}"
                    )
                documented_files = match.groupdict().get("files")
                if documented_files is not None and int(documented_files) != files:
                    problems.append(
                        f"{path}:{number}: docs say {documented_files} files, the suite has "
                        f"{files} test modules"
                    )

        report(problems, "the documented suite size disagrees with the collected suite:")


class TestDocumentedMarkers:
    """The marker figures, and the marker registry behind them."""

    def test_documented_marker_split_matches_the_collection(
        self, request: pytest.FixtureRequest
    ) -> None:
        """The documented `-m unit` / `-m integration` split is what the markers say."""
        items = collected(request)
        counts = marker_counts(items)
        unit = counts.get("unit", 0)
        integration = counts.get("integration", 0)
        total = len(items)
        problems: list[str] = []

        for path, pattern, expected in SPLIT_SITES:
            found = find(path, pattern)
            if len(found) != expected:
                problems.append(
                    site_count_problem(path, pattern, expected, len(found), "SPLIT_SITES")
                )
            for number, match in found:
                documented = (
                    int(match.group("unit")),
                    int(match.group("integration")),
                    int(match.group("total")),
                )
                if documented != (unit, integration, total):
                    problems.append(
                        f"{path}:{number}: docs say {documented[0]} unit and "
                        f"{documented[1]} integration out of {documented[2]}, the markers say "
                        f"{unit} unit and {integration} integration out of {total}"
                    )

        report(problems, "the documented marker split disagrees with the collected markers:")

    def test_every_registered_marker_is_used(self, request: pytest.FixtureRequest) -> None:
        """A registered marker no test carries is a claim the suite does not make.

        The other direction is already a hard failure: pytest runs with
        ``--strict-markers``, so an unregistered marker cannot be attached to a
        test in the first place.
        """
        settings = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
        entries: list[str] = settings["tool"]["pytest"]["ini_options"]["markers"]
        registered = {entry.split(":", 1)[0].strip() for entry in entries}
        used = set(marker_counts(collected(request)))

        unused = sorted(registered - used)
        report(
            [f"pyproject.toml registers {name!r}, which no test carries" for name in unused],
            "the marker registry claims markers the suite does not use:",
        )


class TestDocumentedTables:
    """The per-file figures, in the table and in the file trees."""

    def test_per_file_table_matches_each_collected_module(
        self, request: pytest.FixtureRequest
    ) -> None:
        """Each table row states the count that module actually collects.

        This is the row the last three cards drifted on: a new module, or 18 new
        tests in an existing one, and no change to the doc.
        """
        modules = module_counts(collected(request))
        problems: list[str] = []

        for path in TABLE_SITES:
            rows: dict[str, int] = {}
            for _, match in find(path, TABLE_ROW):
                rows[match.group(1)] = int(match.group("count"))
            for name, count in sorted(modules.items()):
                if name not in rows:
                    problems.append(f"{path}: no row for {name}, which collects {count} tests")
                elif rows[name] != count:
                    problems.append(
                        f"{path}: {name} is listed with {rows[name]} tests, it collects {count}"
                    )
            problems.extend(
                f"{path}: {name} has a row but collects no tests"
                for name in sorted(set(rows) - set(modules))
            )

        report(problems, "the per-file tables disagree with the collected suite:")

    def test_readme_trees_list_every_test_module(self, request: pytest.FixtureRequest) -> None:
        """Both README trees list exactly the modules the suite collects."""
        modules = set(module_counts(collected(request)))
        problems: list[str] = []

        for path in TREE_SITES:
            listed = tree_modules(path)
            if listed is None:
                problems.append(
                    f"{path}: no `tests/` entry in the file tree — unreadable, not empty"
                )
                continue
            problems.extend(
                f"{path}: the file tree is missing {name}" for name in sorted(modules - listed)
            )
            problems.extend(
                f"{path}: the file tree lists {name}, which collects no tests"
                for name in sorted(listed - modules)
            )

        report(problems, "the README file trees disagree with the collected suite:")

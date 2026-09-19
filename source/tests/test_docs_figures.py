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
  carries is a claim the suite does not make (``slow`` was one);
* the auto-commit churn figures in ``modules.md`` / ``modules.en.md`` — that the
  sentence still names the commit it was measured at, that the three figures add
  up, that both shares follow from them, that the commands printed below it
  reproduce the same three figures at the same commit, and that both languages
  state the same measurement. Those figures moved ``6872/172`` → ``6894/194``
  across two cards with nothing checking them, this sprint's own work included;
* the coverage rows in ``testing.md`` / ``testing.en.md`` — that the table still
  names the commit it was measured at, that both languages name the same one and
  state the same three rows, that each row's percentage follows from the counters
  beside it within the band branch mode allows, and that the two rows measuring
  the same tree (``--cov=.``, which the coverage config scopes to the code rather
  than to the suite) agree about it with the offline floor the lower of the two.
  Those rows went stale three times by hand before they were anchored.

What it does NOT guard, so nobody assumes otherwise:

* the coverage figures against a run. Their anchor, the arithmetic behind each
  row, the relations between the rows and the agreement between the two languages
  are held; the numbers themselves are not re-derived, because that means a second
  instrumented run inside the suite. A row whose four figures moved together and
  stayed inside the band its counters allow would pass here, and only a
  re-measurement would say otherwise. Nor is the anchor checked against ``git``,
  for the reason the churn bullet below gives: nothing here runs it, so a coverage
  anchor naming a commit that does not exist passes as well;
* the warning counts, for the same reason;
* the prose around the figures. This test reads numbers, not claims;
* the churn figures against ``git``. The anchor makes them a historical
  measurement rather than a claim about HEAD, but nothing here runs ``git``, so
  an edit that moved all three numbers together under a valid-looking anchor,
  and an anchor naming a commit that does not exist, would both pass. Checking
  them means a ``git`` subprocess and a full-depth clone — the CI checkout sets
  no ``fetch-depth``, so it is shallow and cannot answer there.

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
# The churn measurement: "на ветке `main` в коммите `71972831`: 6894 коммита, из
# них 6700 (≈ 97,2 %)…" / "on branch `main` at commit `71972831`: 6894 commits,
# 6700 of them (≈ 97.2 %)…". The anchor, the three figures and both shares are
# captured together because they are one claim: an edit to any of them without
# the others is what this catches.
RU_CHURN = re.compile(
    r"на ветке `main` в коммите `(?P<sha>[0-9a-f]{7,40})`: (?P<total>\d+) коммит\w*, "
    r"из них (?P<auto>\d+) \(≈ (?P<share>\d+,\d+) %\) начинаются с `auto: update`, "
    r"а остальные (?P<other>\d+) \(≈ (?P<other_share>\d+,\d+) %\)"
)
EN_CHURN = re.compile(
    r"on branch `main` at commit `(?P<sha>[0-9a-f]{7,40})`: (?P<total>\d+) commits, "
    r"(?P<auto>\d+) of them \(≈ (?P<share>\d+\.\d+) %\) start with `auto: update`, "
    r"and the remaining (?P<other>\d+) \(≈ (?P<other_share>\d+\.\d+) %\)"
)
# One line of the reproduction block: the commit it measures, and the figure the
# command printed at it — "git rev-list --count 71972831   # 6894".
CHURN_COMMAND = re.compile(
    r"^git (?:rev-list|log)\b[^#]*?(?P<sha>[0-9a-f]{7,40})[^#]*#\s*(?P<value>\d+)\s*$"
)
# The sentence that anchors the coverage table to the commit it was measured at. One site per
# language, because an anchor is a claim about a commit and two languages disagreeing about it
# is the drift this holds up.
RU_COVERAGE_ANCHOR = re.compile(r"замер на ветке `main` в коммите `(?P<sha>[0-9a-f]{7,40})`")
EN_COVERAGE_ANCHOR = re.compile(
    r"a measurement on branch `main` at commit `(?P<sha>[0-9a-f]{7,40})`"
)
# A row of the coverage table: "| `pytest --cov=.` — the full run, as in CI | the code under
# `source/` | **<percent> %** (<statements> statements, <missed> missed, <branches> branches) |".
# The shape of a row, not a figure copied from the page: the values the pattern is matched
# against are the measurement's own, stated in `testing.md` / `testing.en.md` and re-measured
# with the tree. Emphasis is stripped by `find` before matching, so the percentage is read
# without its asterisks. The counters are captured with the words around them in either
# language — the unit nouns differ, the shape does not.
COVERAGE_ROW = re.compile(
    r"^\|\s*`(?P<command>[^`]+)`[^|]*\|[^|]*\|\s*"
    r"(?P<percent>\d+(?:[.,]\d+)?)\s*%\s*"
    r"\((?P<statements>\d+)\s+\w+,\s*(?P<missed>\d+)\s+[^,]+,\s*(?P<branches>\d+)\s+[^)]+\)"
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

# The churn measurement, one site per language. The count is a contract here for
# the same reason it is above: a reworded sentence that no longer matches has to
# fail loudly rather than leaving the page looking guarded by nothing.
CHURN_SITES: tuple[tuple[str, re.Pattern[str], int], ...] = (
    ("docs/development/modules.md", RU_CHURN, 1),
    ("docs/development/modules.en.md", EN_CHURN, 1),
)

# The coverage table's anchor, one site per language. The count is a contract here for the same
# reason it is above: a reworded sentence that no longer matches has to fail loudly rather than
# leaving the page looking guarded by nothing.
COVERAGE_ANCHOR_SITES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("docs/development/testing.md", RU_COVERAGE_ANCHOR),
    ("docs/development/testing.en.md", EN_COVERAGE_ANCHOR),
)

# The two tables that state the measured coverage, and how many rows each of them must state.
COVERAGE_TABLE_SITES: tuple[str, ...] = (
    "docs/development/testing.md",
    "docs/development/testing.en.md",
)
COVERAGE_ROWS = 3

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


def find_joined(path: str, pattern: re.Pattern[str]) -> list[tuple[int, re.Match[str]]]:
    """Matches of a pattern that may span a line break, with its starting line.

    `find` answers per line, which is right for a figure stated on one line and
    wrong for the churn sentence: its anchor, three figures and two shares sit
    on different lines of the source, so a pattern that described the wrapping
    instead of the sentence would go red on a re-wrap. Emphasis is stripped as
    in `find`, the lines are joined with a single space, and each match is
    mapped back to the line it starts on so a failure still carries
    ``path:line``.
    """
    offsets: list[int] = []
    parts: list[str] = []
    cursor = 0
    for line in (REPO_ROOT / path).read_text(encoding="utf-8").splitlines():
        offsets.append(cursor)
        part = line.replace("**", "")
        parts.append(part)
        cursor += len(part) + 1
    joined = " ".join(parts)

    found: list[tuple[int, re.Match[str]]] = []
    for match in pattern.finditer(joined):
        start = max(index for index, offset in enumerate(offsets) if offset <= match.start())
        found.append((start + 1, match))
    return found


def fenced_block(path: str, after: int) -> list[tuple[int, str]]:
    """The first fenced block starting below line `after`, as (line, text).

    Reading the block rather than the rest of the page keeps a `git` command
    elsewhere in the file from being mistaken for a re-measurement site — or,
    worse, from silently satisfying the expected number of them.
    """
    block: list[tuple[int, str]] = []
    opened = False
    for number, raw in enumerate(
        (REPO_ROOT / path).read_text(encoding="utf-8").splitlines()[after:], start=after + 1
    ):
        if raw.startswith("```"):
            if opened:
                return block
            opened = True
            continue
        if opened:
            block.append((number, raw))
    return block


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


def reproduction_problems(
    path: str, anchor_line: int, anchor: str, stated: tuple[int, int, int]
) -> list[str]:
    """The commands in the churn page's reproduction block, against the sentence.

    The block prints each figure a second time, in the comment of the command
    that produced it, so a figure edited without its measurement becomes a
    disagreement between two statements on the same page — which is what this
    returns. The values are compared as a set: which command prints which half
    is the page's business, that all three were printed at the anchor is not.
    """
    problems: list[str] = []
    values: list[int] = []
    for line, text in fenced_block(path, anchor_line):
        command = CHURN_COMMAND.search(text)
        if not command:
            continue
        values.append(int(command.group("value")))
        if command.group("sha") != anchor:
            problems.append(
                f"{path}:{line}: this command measures {command.group('sha')}, the "
                f"measurement above it is anchored to {anchor}"
            )
    if len(values) != len(stated):
        problems.append(
            f"{path}: the reproduction block prints {len(values)} figures, expected "
            f"{len(stated)} — the total and its two halves"
        )
    elif sorted(values) != sorted(stated):
        problems.append(
            f"{path}: the reproduction commands print {sorted(values)}, the sentence "
            f"states {sorted(stated)}"
        )
    return problems


class TestDocumentedChurn:
    """The churn figures, against the commit they say they were measured at.

    These are the figures that drifted unobserved: ``6872`` → ``6894`` and
    ``172`` → ``194`` across the two cards before this one, this sprint's own
    work included, because they were stated for HEAD and nothing checked them.
    They name a commit now, which makes them a historical measurement, and this
    class holds the anchor and the arithmetic in place.
    """

    def test_the_churn_figures_are_anchored_and_add_up(self) -> None:
        """Each figure is stated twice; the check compares both statements.

        Once in the sentence, once in the comment of the command that printed it.
        The anchor has to be one commit across both languages, the total has to
        be its two halves, both shares have to follow from those figures, and the
        commands have to print the three numbers the sentence states.
        """
        problems: list[str] = []
        anchors: dict[str, str] = {}
        measurements: dict[str, tuple[int, int, int]] = {}

        for path, pattern, expected in CHURN_SITES:
            found = find_joined(path, pattern)
            if len(found) != expected:
                problems.append(
                    site_count_problem(path, pattern, expected, len(found), "CHURN_SITES")
                )
                continue

            number, match = found[0]
            anchor = match.group("sha")
            total = int(match.group("total"))
            auto = int(match.group("auto"))
            other = int(match.group("other"))
            anchors[path] = anchor
            measurements[path] = (total, auto, other)

            if total != auto + other:
                problems.append(
                    f"{path}:{number}: the figures do not add up — {total} total, "
                    f"{auto} auto and {other} other, and {auto} + {other} = {auto + other}"
                )
            for label, value, stated_share in (
                ("auto", auto, match.group("share")),
                ("other", other, match.group("other_share")),
            ):
                share = round(value / total * 100, 1) if total else 0.0
                if abs(float(stated_share.replace(",", ".")) - share) > 0.05:
                    problems.append(
                        f"{path}:{number}: the {label} share is stated as {stated_share} %, "
                        f"and {value} of {total} is {share} %"
                    )

            problems.extend(reproduction_problems(path, number, anchor, measurements[path]))

        if len(measurements) == len(CHURN_SITES):
            if len(set(anchors.values())) != 1:
                problems.append(
                    "the two languages anchor the churn measurement to different commits: "
                    + ", ".join(f"{path} names {sha}" for path, sha in sorted(anchors.items()))
                )
            if len(set(measurements.values())) != 1:
                problems.append(
                    "the two languages state different churn figures: "
                    + ", ".join(
                        f"{path} states {figures}" for path, figures in sorted(measurements.items())
                    )
                )

        report(problems, "the documented churn measurement disagrees with itself:")


def coverage_row_problems(
    path: str,
    line: int,
    command: str,
    statements: int,
    missed: int,
    branches: int,
    percent: float,
) -> list[str]:
    """Whether a row's percentage can follow from the counters stated beside it.

    Branch mode, so the percentage is covered statements plus covered branches over statements
    plus branches — and the table states how many branches there are, never how many of them were
    taken. The answer is a band rather than an equality: the covered branches lie somewhere
    between none of them and all of them, and what is checked is that the stated figure sits
    inside it. That band is the limit of this guard, and the module docstring states it: a row
    whose four figures moved together and stayed inside the band passes here, and only a
    re-measurement would say otherwise.
    """
    problems: list[str] = []
    if missed > statements:
        problems.append(
            f"{path}:{line}: {command} is stated with {missed} missed of {statements} statements — "
            "more missed than there are"
        )

    total = statements + branches
    if total <= 0:
        problems.append(f"{path}:{line}: {command} is stated with no statements and no branches")
        return problems

    low = (statements - missed) / total * 100
    high = (statements - missed + branches) / total * 100
    if not low - 0.5 <= percent <= high + 0.5:
        problems.append(
            f"{path}:{line}: {command} states {percent:g} %, and {statements} statements with "
            f"{missed} missed and {branches} branches can only give between {low:.1f} % and "
            f"{high:.1f} %"
        )
    return problems


def coverage_scope_problems(
    path: str,
    rows: Sequence[tuple[int, re.Match[str]]],
    stated: Sequence[tuple[int, int, int, float]],
) -> list[str]:
    """The relations between the rows that measure the same tree.

    Two of the three rows cover what ``--cov=.`` reports, so they have to agree about the tree
    they measured — the same statements and the same branches — and the one that deselects the 15
    network tests can only be the worse of the two: dropping tests cannot execute more code. Both
    of those rows are scoped by the coverage config, which measures the code rather than the
    suite, so "the same tree" is the code under ``source/``. The two-package row is deliberately
    not compared with them, and the page says why — two packages and a tree have different
    denominators.
    """
    whole_tree = [
        (row.group("command"), figures)
        for (_, row), figures in zip(rows, stated, strict=True)
        if "--cov=." in row.group("command")
    ]
    if len(whole_tree) != 2:
        return [
            f"{path}: {len(whole_tree)} rows measure the same tree (`--cov=.`), expected 2 — "
            "the relations here are between exactly those two"
        ]

    full = next((entry for entry in whole_tree if "not integration" not in entry[0]), None)
    offline = next((entry for entry in whole_tree if "not integration" in entry[0]), None)
    if full is None or offline is None:
        return [
            f"{path}: the rows measuring the same tree are not one full run and one offline "
            "floor — the floor is the command that deselects the integration marker"
        ]

    full_statements, full_missed, full_branches, full_percent = full[1]
    floor_statements, floor_missed, floor_branches, floor_percent = offline[1]
    problems: list[str] = []
    if (full_statements, full_branches) != (floor_statements, floor_branches):
        problems.append(
            f"{path}: the full run and the offline floor measure the same tree, so they must state "
            f"the same statements and the same branches — {full[0]} states {full_statements} "
            f"statements and {full_branches} branches, {offline[0]} states {floor_statements} and "
            f"{floor_branches}"
        )
    if floor_missed < full_missed:
        problems.append(
            f"{path}: the offline floor skips the 15 network tests and reports {floor_missed} "
            f"missed, fewer than the full run's {full_missed} — deselecting tests cannot cover more"
        )
    if floor_percent > full_percent:
        problems.append(
            f"{path}: the offline floor is stated at {floor_percent:g} %, above the full run's "
            f"{full_percent:g} % — the same direction the missed counts run in"
        )
    return problems


class TestDocumentedCoverage:
    """The coverage figures, against the commit they say they were measured at.

    These rows went stale three times with nothing checking them: two cards re-measured them by
    hand, each a few commits late, and the third time the modules this sprint added moved them
    again. They name a commit now, which makes them a historical measurement rather than a claim
    about HEAD, and this class holds the anchor, the arithmetic and both languages in place.

    Every branch here was shown failing on a scratch copy before this landed: a percentage
    outside the band its own counters allow, a row disagreeing with the other row that measures
    the same tree, an anchor that differs between the two languages, a table stated differently
    in the two languages, counters that are all zero, and an offline floor that beats the full
    run on either the missed count or the percentage.
    """

    def test_the_coverage_rows_are_anchored_and_add_up(self) -> None:
        """Each row is measured once and stated twice, and the two statements have to agree.

        One commit across both languages; every row's percentage inside the band its own counters
        allow; the two rows measuring the same tree agreeing about it, with the offline floor the
        worse of the two; and the same three rows in both languages. Every mismatch is reported in
        one failure with ``path:line``, so the next drift is corrected in one pass.
        """
        problems: list[str] = []
        anchors: dict[str, str] = {}
        measurements: dict[str, list[tuple[int, int, int, float]]] = {}

        for path, anchor_pattern in COVERAGE_ANCHOR_SITES:
            found = find(path, anchor_pattern)
            if len(found) != 1:
                problems.append(
                    site_count_problem(path, anchor_pattern, 1, len(found), "COVERAGE_ANCHOR_SITES")
                )
                continue
            anchors[path] = found[0][1].group("sha")

        for path in COVERAGE_TABLE_SITES:
            rows = find(path, COVERAGE_ROW)
            if len(rows) != COVERAGE_ROWS:
                problems.append(
                    f"{path}: {len(rows)} coverage rows, expected {COVERAGE_ROWS} — a row that was "
                    "reworded has to fail here rather than leave the table looking guarded"
                )
                continue

            stated = [
                (
                    int(row.group("statements")),
                    int(row.group("missed")),
                    int(row.group("branches")),
                    float(row.group("percent").replace(",", ".")),
                )
                for _, row in rows
            ]
            measurements[path] = stated

            for (line, row), figures in zip(rows, stated, strict=True):
                problems.extend(
                    coverage_row_problems(
                        path,
                        line,
                        row.group("command"),
                        figures[0],
                        figures[1],
                        figures[2],
                        figures[3],
                    )
                )
            problems.extend(coverage_scope_problems(path, rows, stated))

        if len(anchors) == len(COVERAGE_ANCHOR_SITES) and len(measurements) == len(
            COVERAGE_TABLE_SITES
        ):
            if len(set(anchors.values())) != 1:
                problems.append(
                    "the two languages anchor the coverage measurement to different commits: "
                    + ", ".join(f"{path} names {sha}" for path, sha in sorted(anchors.items()))
                )
            if len({tuple(sorted(rows)) for rows in measurements.values()}) != 1:
                problems.append(
                    "the two languages state different coverage rows: "
                    + ", ".join(
                        f"{path} states {rows}" for path, rows in sorted(measurements.items())
                    )
                )

        report(problems, "the documented coverage measurement disagrees with itself:")

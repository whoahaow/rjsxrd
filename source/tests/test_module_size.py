"""The size gate: a ceiling every module obeys, and a debt list that may only shrink.

This repository's size problem was first named at four modules -- ``xray_tester``,
``xray_batch``, ``config_processor`` and ``protocol_parsers`` -- and measuring the whole
tree showed it is wider than that list: three of the largest test modules are
above the ceiling set below, and the largest file in the repository is one of them. A gate
covering only those four would repeat the defect a named list always carries, a
rule applied where someone happened to look and not where nobody did. So this gate walks
every ``.py`` file under ``source/`` -- tests included, subdirectories included -- and
holds two components whose holes are complementary:

* **the ceiling** (``CEILING``). No module may be longer than this. It needs no list and
  cannot be gamed by failing to maintain one: a 3000-line module added tomorrow, in a
  subdirectory nobody has heard of, is caught by the walk alone.
* **the budget** (``BUDGETS``). The files that were already over the ceiling on the day
  this gate landed, each with the size it was measured at. Acknowledged debt, not
  permission: a budgeted file may not grow at all, and its budget may only be lowered.

Why both components. The ceiling alone would let today's oversized files stay oversized
forever -- ``len(path) <= CEILING`` is true of a file that never moves, and a gate that
merely records a size is a stale figure with a test around it. The list alone would be
gameable by not maintaining it: a file nobody registered is covered by nothing. Each
component closes the other's hole, which is why neither is optional.

Why the ceiling is 800. Four modules had already been judged too large, and the
smallest of the four (``source/utils/protocol_parsers.py``, 803 lines) is the top of that
band, so 800 is the round number at or below it: the gate's line is the line the
repository has already drawn rather than a second opinion that contradicts it. A ceiling
of 1000 is the tempting alternative and the weaker one -- three of those four modules
would sit *under* it, and the gate would be declaring that files the repository called too
large are fine, while the debt list could no longer state that those four are
what is above the line.

Why the ratchet. A budget nobody lowers quietly becomes a licence: in two years the file
is twice the size it should be and still reads as "within budget". So a budgeted file
that drops more than ``RATCHET_SLACK`` below its budget fails the gate and asks for the
budget to be lowered -- one edit, in the same commit as the reduction. That edit *is* the
mechanism, and its cost is the trade this gate accepts: a legitimate large reduction pays
one extra edit, because the alternative is a budget that never tightens. The slack is a
share rather than a fixed number of lines because it has to scale with the file: a fixed
slack punishes a 2038-line file and coddles an 803-line one. Ten percent of the smallest
budget here is 80 lines -- more than an ordinary refactor moves, less than any split, so
routine work does not trip it and a real reduction dies on it.

Two of those branches overlap for a budget whose slack threshold falls below the ceiling: the
only way to be more than the slack below an 884-line budget is to be under the 800-line
ceiling as well, so there the entry-removal branch is the one that fires. That is the tighter
of the two -- the file's limit drops from the budget to the ceiling -- so no pressure is lost
to the overlap, and the ordering is stated here so nobody later reads it as a defect.

The debt list is closed. It holds the files that were over the ceiling at the moment this
gate landed; a file that crosses the ceiling afterwards -- one added tomorrow, or an
existing one that grew -- is a file to split, and adding it to ``BUDGETS`` is how a size
gate gets silenced rather than satisfied. Widening the ceiling itself is a deliberate
change to this module, made on its own and argued in its commit message, not a side effect
of whatever needed the room.

The budgets are measured sizes, not comfortable roundings above them, and they live here
as data rather than being derived from git: the CI checkout passes no ``fetch-depth``, so
it is shallow and has no history to walk.

Every branch below was shown failing on a scratch copy before this module landed: a file
one line over the ceiling, a budgeted file one line over its budget, a budgeted file
shrunk well below its budget, and an oversized new file in a new subdirectory -- the last
one being what proves the walk covers the tree rather than a list of directories. A guard
whose branches have not been shown failing is a guard nobody has tested.

Sizes are counted in Python (``splitlines()``), never with ``wc -l``: the two disagree
about a file whose last line carries no newline, and the answer has to be the same on
Windows and on the Linux runner.

The policy this implements is written for a reader in ``docs/development/testing.md`` and
``docs/development/testing.en.md``, under "Module size" / "Размер модулей" -- a failure
message points there.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = REPO_ROOT / "source"

# The ceiling, in lines, for every `.py` file under `source/` that is not in BUDGETS.
# Chosen at the top of the band already judged too large: see the module
# docstring. The comment above each check below says which component it is and why the
# component exists.
CEILING = 800

# Component 2: the files that were over the ceiling on the day this gate landed, with the
# size each was measured at then. Acknowledged debt, not permission -- a file listed here
# may not grow at all, and its budget may never be raised. Four of these are the modules
# named above; the other three are test modules that first list never reached,
# the largest of them the largest file in the repository. Not one of them has been split:
# this gate makes the debt visible and forbids it growing, and shrinking them is separate
# work.
BUDGETS: dict[str, int] = {
    "source/tests/test_config_processor.py": 2038,
    "source/utils/xray_tester.py": 1203,
    "source/utils/xray_batch.py": 952,
    "source/tests/test_fetcher_unit.py": 912,
    "source/processors/config_processor.py": 884,
    "source/tests/test_pipeline_e2e.py": 827,
    "source/utils/protocol_parsers.py": 803,
}

# How far a budgeted file may fall below its budget before the budget counts as stale and
# the gate asks for it to be lowered. A share, so it scales with the file; see the module
# docstring for the trade it accepts.
RATCHET_SLACK = 0.10

# The walk has to be shown reaching the tree, or a wrong root makes every check below pass
# by measuring nothing. Two files rather than one on purpose: `source/main.py` proves the
# top level is seen, and a nested test module proves the recursion and the inclusion of
# `source/tests/` -- a walk that listed one directory, or that skipped tests, fails here
# instead of passing quietly with a smaller tree.
WALK_ANCHORS = ("source/main.py", "source/tests/test_docs_figures.py")


def module_sizes() -> dict[str, int]:
    """Every ``.py`` file under ``source/``, repo-relative, counted in lines.

    Discovered by walking the tree, not from a list of directories: a file added tomorrow
    in a new subdirectory is covered without an edit here. The count is ``splitlines()``
    in Python so the answer does not depend on the platform or on a trailing newline.
    """
    return {
        path.relative_to(REPO_ROOT).as_posix(): len(path.read_text(encoding="utf-8").splitlines())
        for path in sorted(SOURCE_ROOT.rglob("*.py"))
    }


def report(problems: Sequence[str], headline: str) -> None:
    """Fail with every problem at once, so one pass fixes the whole drift."""
    assert not problems, "\n".join((headline, *(f"  {problem}" for problem in problems)))


def ceiling_problem(path: str, lines: int) -> str:
    """What to do about a module that crossed the ceiling without being on the debt list.

    The remedy is the split and only the split: registering the file would silence the
    component that catches exactly this, so the message says so instead of leaving the
    reader to reach for the list.
    """
    return (
        f"{path}: {lines} lines, {lines - CEILING} over the {CEILING}-line ceiling, and it is not "
        f"acknowledged debt. Split it -- move a coherent part into a module of its own so this file "
        f"comes back to {CEILING} lines or fewer. Adding it to BUDGETS in "
        f"source/tests/test_module_size.py is not the remedy: that list holds the files that were "
        f"already over the ceiling when the gate landed, and a new entry there is how a size gate is "
        f"silenced rather than satisfied. The policy is in docs/development/testing.md, "
        '"Module size".'
    )


def budget_problem(path: str, lines: int, budget: int) -> str:
    """What to do about a budgeted module that grew.

    The budget may not be raised -- that is the whole point of the entry -- so the two
    honest responses are named: bring the file back, or split it and lower the budget.
    """
    return (
        f"{path}: {lines} lines, {lines - budget} over its budget of {budget}. That budget is the "
        f"size this file was measured at when the gate landed; it is acknowledged debt and a "
        f"one-way ratchet, so it cannot be raised. Bring the file back to {budget} lines or fewer, "
        f"or split it and lower the budget to what is left in the same commit. "
        f'The policy is in docs/development/testing.md, "Module size".'
    )


def stale_budget_problem(path: str, lines: int, budget: int) -> str:
    """What to do about a budget the file has outgrown downwards.

    Without this branch nobody ever tightens a budget and the entry becomes a licence, so
    the message names the single edit that keeps the ratchet honest and states what it
    costs.
    """
    slack = int(budget * RATCHET_SLACK)
    return (
        f"{path}: {lines} lines against a budget of {budget} -- {budget - lines} lines below it, "
        f"more than the {slack}-line ({RATCHET_SLACK:.0%}) slack this gate allows. Set the budget "
        f"to {lines} in BUDGETS (source/tests/test_module_size.py), in the same commit as the "
        f"reduction. That edit is the ratchet: a budget nobody lowers stops describing the file and "
        f'starts protecting it. The policy is in docs/development/testing.md, "Module size".'
    )


def covered_by_the_ceiling_problem(path: str, lines: int, budget: int) -> str:
    """What to do about an entry for a file that is no longer over the ceiling.

    Left in place, the entry is worse than useless: the file's limit becomes its budget,
    which sits above the ceiling, so the file could grow back past the ceiling every other
    module obeys.
    """
    return (
        f"{path}: BUDGETS lists it at {budget} lines, but the file is down to {lines} -- at or below "
        f"the {CEILING}-line ceiling, so the entry is stale. Delete it: while it stands, this file's "
        f"limit is its budget rather than the ceiling, and it could grow back past a line every other "
        f'module obeys. The policy is in docs/development/testing.md, "Module size".'
    )


def missing_file_problem(path: str, budget: int) -> str:
    """What to do about an entry that names no file -- a budget checking nothing."""
    return (
        f"{path}: BUDGETS lists it at {budget} lines, and no such file exists under source/. Remove "
        f"the entry, or fix the path if the file moved -- an entry that names nothing measures "
        f"nothing."
    )


class TestTheWalkIsReal:
    """The walk, against the two files it must always see."""

    def test_the_walk_reaches_every_part_of_the_tree(self) -> None:
        """The measured tree contains the anchors, so the checks below are not vacuous.

        A wrong ``SOURCE_ROOT``, or a walk that stopped at the top level, or one that
        skipped the test modules, would leave every assertion below passing over a smaller
        tree than the one the policy is about. Nothing else in this module would notice.
        """
        sizes = module_sizes()
        problems = [
            f"{anchor}: not among the {len(sizes)} modules the walk measured -- the walk is not "
            f"reaching the tree this gate is about, so every check in this module is answering about "
            f"a smaller one. Fix the walk before reading any other failure here."
            for anchor in WALK_ANCHORS
            if anchor not in sizes
        ]

        report(problems, "the walk over source/ did not see the files it must:")


class TestTheCeiling:
    """Component 1: the ceiling, which needs no list to catch a new module."""

    def test_a_module_that_is_not_debt_stays_under_the_ceiling(self) -> None:
        """No module outside the debt list is longer than the ceiling.

        This is the half that cannot be defeated by forgetting to register something, which
        is why it exists beside the budgets: a 3000-line module added tomorrow is caught by
        the walk itself.
        """
        sizes = module_sizes()
        problems = [
            ceiling_problem(path, lines)
            for path, lines in sorted(sizes.items())
            if path not in BUDGETS and lines > CEILING
        ]

        report(
            problems,
            f"a module is over the {CEILING}-line ceiling and is not acknowledged debt:",
        )


class TestTheBudgets:
    """Component 2: the debt list, which may only shrink."""

    def test_a_budgeted_module_stays_within_its_budget(self) -> None:
        """No file on the debt list is longer than the budget recorded for it.

        The entries are acknowledged debt, not permission: a listed file is at the size it
        was when the gate landed and may not grow, which is what makes the list a debt and
        not an exemption.
        """
        sizes = module_sizes()
        problems = [
            budget_problem(path, lines, BUDGETS[path])
            for path, lines in sorted(sizes.items())
            if path in BUDGETS and lines > BUDGETS[path]
        ]

        report(problems, "a budgeted module grew past the budget recorded for it:")

    def test_a_budget_that_no_longer_describes_its_file_is_reported(self) -> None:
        """Every entry still describes a real file that is still over the ceiling.

        Three ways an entry goes stale, and all three are failures: the file shrank well
        below its budget (the ratchet asks for the budget to be lowered), the file shrank
        to the ceiling or under it (the entry must go -- while it stands the file's limit is
        above the ceiling), or the file is gone (the entry measures nothing).
        """
        sizes = module_sizes()
        problems: list[str] = []

        for path, budget in sorted(BUDGETS.items()):
            if path not in sizes:
                problems.append(missing_file_problem(path, budget))
            elif sizes[path] <= CEILING:
                problems.append(covered_by_the_ceiling_problem(path, sizes[path], budget))
            elif sizes[path] < budget - int(budget * RATCHET_SLACK):
                problems.append(stale_budget_problem(path, sizes[path], budget))

        report(problems, "a budget in the debt list no longer describes its file:")

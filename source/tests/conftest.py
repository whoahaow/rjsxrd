"""Pytest configuration and fixtures."""

import os
import sys

import pytest

# Add source directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture
def temp_file(tmp_path):
    """An existing, empty file — for code paths that read from disk."""
    file_path = tmp_path / "test_file.txt"
    file_path.write_text("", encoding="utf-8")
    return file_path


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Park the full collection for the docs guard, before `-m` deselects.

    ``tests/test_docs_figures.py`` checks the figures the documentation states
    about this suite against the suite itself, so it has to see all of it: a
    guard that answered ``699 tests`` under ``-m unit`` and ``729`` under
    ``pytest -q`` would have to hard-code which selection it trusts, which is
    the second copy of the problem it exists to fix.

    The snapshot is full because this pytest runs the ``conftest`` hook before
    its own mark plugin's, and that plugin deselects by truncating the list in
    place: dropping ``tryfirst`` and running
    ``pytest -q -m unit -k docs_figures`` still passes, so this hook still sees
    all 729. The ordering is defensive rather than load-bearing at this
    version — ``tryfirst`` states it instead of leaving it incidental. Were a
    future pytest to reverse it, the snapshot would be the selection and the
    guard would fail loudly against the documented total rather than pass on a
    filtered count, exactly as it fails with five ``KeyError`` failures when
    the stash is never written.
    """
    from tests.support import COLLECTED_ITEMS

    config.stash[COLLECTED_ITEMS] = list(items)

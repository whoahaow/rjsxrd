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
    the second copy of the problem it exists to fix. ``tryfirst`` is what makes
    the snapshot full — pytest's own ``-m`` implementation also handles
    ``pytest_collection_modifyitems``, and it truncates the list in place.
    """
    from tests.support import COLLECTED_ITEMS

    config.stash[COLLECTED_ITEMS] = list(items)

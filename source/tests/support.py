"""Shared helpers for the test suite."""

import subprocess
from unittest.mock import MagicMock

import pytest

# Where the collection hook in `conftest.py` parks the whole collected suite,
# before `-m` deselects anything. `tests/test_docs_figures.py` reads it: it
# checks the figures the docs state about the suite, so it has to see the whole
# suite and not the selection the run happens to use.
COLLECTED_ITEMS: pytest.StashKey[list[pytest.Item]] = pytest.StashKey()


def make_result(returncode=0, stdout="", stderr=""):
    """Build a subprocess.CompletedProcess-like mock with real-ish attributes."""
    result = MagicMock(spec=subprocess.CompletedProcess)
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result

"""Shared helpers for the test suite."""

import subprocess
from unittest.mock import MagicMock


def make_result(returncode=0, stdout="", stderr=""):
    """Build a subprocess.CompletedProcess-like mock with real-ish attributes."""
    result = MagicMock(spec=subprocess.CompletedProcess)
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result

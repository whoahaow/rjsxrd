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

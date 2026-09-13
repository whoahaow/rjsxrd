"""Tests for the pipeline-and-upload entry point in main.py."""

from unittest.mock import MagicMock, patch

import pytest

import main

FILE_PAIRS = [("local.txt", "remote/path.txt")]


pytestmark = pytest.mark.unit


def _run_pipeline(use_git: bool, dry_run: bool = False) -> bool:
    return main._run_pipeline_and_upload(
        output_dir="out",
        skip_xray=True,
        tcp_ping=False,
        verbose=False,
        flag_overrides=None,
        dry_run=dry_run,
        use_git=use_git,
    )


class TestUploadPathGuards:
    """Both upload paths must guard their handler with a real error.

    The invariant used to be checked with `assert`, which disappears under
    `python -O` — after which the next line dereferenced None and failed with an
    unrelated AttributeError. The guard has to raise either way and name what is
    missing.
    """

    def test_git_path_without_updater_raises(self):
        """A missing GitUpdater is reported as such, not dereferenced."""
        with (
            patch.object(main, "process_all_configs", return_value=FILE_PAIRS),
            patch.object(main, "log"),
            patch("utils.git_updater.GitUpdater", return_value=None),
            pytest.raises(RuntimeError, match="GitUpdater"),
        ):
            _run_pipeline(use_git=True)

    def test_upload_path_without_handler_raises(self):
        """A missing GitHubHandler is reported as such, not dereferenced."""
        with (
            patch.object(main, "process_all_configs", return_value=FILE_PAIRS),
            patch.object(main, "log"),
            patch.object(main, "GitHubHandler", return_value=None),
            pytest.raises(RuntimeError, match="GitHubHandler"),
        ):
            _run_pipeline(use_git=False)

    def test_git_path_still_commits_on_the_normal_route(self):
        """With the updater present the git branch commits and reports success."""
        updater = MagicMock()
        updater.commit_and_push_files.return_value = True

        with (
            patch.object(main, "process_all_configs", return_value=FILE_PAIRS),
            patch.object(main, "log"),
            patch("utils.git_updater.GitUpdater", return_value=updater),
        ):
            assert _run_pipeline(use_git=True) is True

        updater.commit_and_push_files.assert_called_once_with(FILE_PAIRS)

    def test_upload_path_still_uploads_on_the_normal_route(self):
        """With the handler present the API branch uploads and reports success."""
        handler = MagicMock()
        handler.upload_multiple_files.return_value = 0

        with (
            patch.object(main, "process_all_configs", return_value=FILE_PAIRS),
            patch.object(main, "log"),
            patch.object(main, "GitHubHandler", return_value=handler),
        ):
            assert _run_pipeline(use_git=False) is True

        handler.upload_multiple_files.assert_called_once_with(FILE_PAIRS)

    def test_dry_run_never_touches_the_upload_paths(self):
        """A dry run returns before either guard is reached."""
        with (
            patch.object(main, "process_all_configs", return_value=FILE_PAIRS),
            patch.object(main, "log"),
        ):
            assert _run_pipeline(use_git=True, dry_run=True) is True

"""Tests for the pipeline-and-upload entry point in main.py."""

import sys
import types
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


def _deferred_handler(**handler_kwargs):
    """Stand in for ``utils.github_handler`` in ``sys.modules``.

    ``_run_pipeline_and_upload`` imports the handler at call time, so the fake
    is only reachable through the import system. That is what makes these tests
    prove the import is deferred rather than bound at module level, and why
    they run on a machine that has no PyGithub installed.
    """
    module = types.ModuleType("utils.github_handler")
    module.GitHubHandler = MagicMock(**handler_kwargs)
    return patch.dict(sys.modules, {"utils.github_handler": module})


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
            _deferred_handler(return_value=None),
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
            _deferred_handler(return_value=handler),
        ):
            assert _run_pipeline(use_git=False) is True

        handler.upload_multiple_files.assert_called_once_with(FILE_PAIRS)

    def test_a_missing_sdk_fails_at_upload_time_not_at_import_time(self):
        """With PyGithub absent, the failure lands on the upload, one step later.

        Before the import moved into the upload branch, an environment without
        PyGithub could not import this module at all; ``sys.modules`` holding
        ``None`` is how the import system reports a module it cannot provide.
        """
        with (
            patch.object(main, "process_all_configs", return_value=FILE_PAIRS),
            patch.object(main, "log"),
            patch.dict(sys.modules, {"utils.github_handler": None}),
            pytest.raises(ImportError),
        ):
            _run_pipeline(use_git=False)

    def test_dry_run_never_touches_the_upload_paths(self):
        """A dry run returns before either guard is reached."""
        with (
            patch.object(main, "process_all_configs", return_value=FILE_PAIRS),
            patch.object(main, "log"),
        ):
            assert _run_pipeline(use_git=True, dry_run=True) is True


class TestAutoRemoveDeadUrlsArgs:
    """CLI argument parsing for auto-removing dead URLs and failure threshold."""

    def test_enable_auto_remove_dead_urls_flag(self):
        with patch.object(sys, "argv", ["main.py", "--enable-auto-remove-dead-urls"]):
            args = main._parse_args()
            assert args.auto_remove_dead_urls is True

    def test_disable_auto_remove_dead_urls_flag(self):
        with patch.object(sys, "argv", ["main.py", "--disable-auto-remove-dead-urls"]):
            args = main._parse_args()
            assert args.auto_remove_dead_urls is False

    def test_dead_url_threshold_flag(self):
        with patch.object(sys, "argv", ["main.py", "--dead-url-threshold", "5"]):
            args = main._parse_args()
            assert args.dead_url_threshold == 5


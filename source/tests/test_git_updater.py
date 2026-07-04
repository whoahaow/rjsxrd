"""Tests for utils/git_updater using mocked subprocess.

Covers: init, configure, pull, stage, commit, push, full workflow,
retry on push conflict, and error handling.
"""

import os
import subprocess
from unittest.mock import patch, MagicMock
import pytest

from utils.git_updater import GitUpdater


# ── Helpers ───────────────────────────────────────────────────────────

def _make_result(returncode=0, stdout="", stderr=""):
    """Build a subprocess.CompletedProcess-like mock with real-ish attrs."""
    r = MagicMock(spec=subprocess.CompletedProcess)
    r.stdout = stdout
    r.stderr = stderr
    r.returncode = returncode
    return r


# ── Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture
def mock_subprocess_run():
    """Mock subprocess.run to return success by default."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = _make_result(0)
        yield mock_run


@pytest.fixture
def updater(tmp_path):
    """GitUpdater bound to a temp directory."""
    return GitUpdater(repo_dir=str(tmp_path), output_prefix="githubmirror/")


# ── Init ──────────────────────────────────────────────────────────────

class TestInit:
    def test_default_repo_dir_resolves(self):
        """Default repo_dir resolves to two levels up from utils/."""
        u = GitUpdater()
        expected = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        assert u.repo_dir == expected

    def test_custom_repo_dir(self, tmp_path):
        u = GitUpdater(repo_dir=str(tmp_path))
        assert u.repo_dir == str(tmp_path)

    def test_output_prefix_strips_trailing_slash(self):
        u = GitUpdater(output_prefix="githubmirror/")
        assert u.output_prefix == "githubmirror"

    def test_output_prefix_no_slash(self):
        u = GitUpdater(output_prefix="githubmirror")
        assert u.output_prefix == "githubmirror"


# ── _run_git ──────────────────────────────────────────────────────────

class TestRunGit:
    def test_runs_command(self, mock_subprocess_run, updater):
        updater._run_git("status")
        mock_subprocess_run.assert_called_once()
        args = mock_subprocess_run.call_args[0][0]
        assert args == ["git", "status"]

    def test_uses_repo_dir_as_cwd(self, mock_subprocess_run, updater):
        updater._run_git("log")
        assert mock_subprocess_run.call_args[1]["cwd"] == updater.repo_dir

    def test_timeout_raises(self, mock_subprocess_run, updater):
        mock_subprocess_run.side_effect = subprocess.TimeoutExpired("git", 60)
        with pytest.raises(subprocess.TimeoutExpired):
            updater._run_git("status")

    def test_nonzero_exit_raises(self, mock_subprocess_run, updater):
        mock_subprocess_run.side_effect = subprocess.CalledProcessError(
            128, ["git", "status"], stderr="fatal: not a git repository"
        )
        with pytest.raises(subprocess.CalledProcessError):
            updater._run_git("status")


# ── configure_git ─────────────────────────────────────────────────────

class TestConfigureGit:
    def test_sets_user_name_and_email(self, mock_subprocess_run, updater):
        updater.configure_git()
        calls = mock_subprocess_run.call_args_list
        assert len(calls) == 2
        assert calls[0].args[0] == ["git", "config", "user.name", "GitHub Actions"]
        assert calls[1].args[0] == ["git", "config", "user.email", "actions@github.com"]


# ── pull ──────────────────────────────────────────────────────────────

class TestPull:
    def test_pull_detects_branch(self, mock_subprocess_run, updater):
        mock_subprocess_run.return_value = _make_result(0, stdout="main\n")

        updater.pull()

        calls = mock_subprocess_run.call_args_list
        assert calls[0].args[0] == ["git", "rev-parse", "--abbrev-ref", "HEAD"]
        assert calls[2].args[0] == ["git", "pull", "--rebase", "origin", "main"]

    def test_pull_with_explicit_branch(self, mock_subprocess_run, updater):
        updater.pull(branch="staging")

        calls = mock_subprocess_run.call_args_list
        # Should skip rev-parse since branch is given
        assert calls[0].args[0] == ["git", "stash", "push", "-m", "Auto-stash before pull"]
        assert calls[1].args[0] == ["git", "pull", "--rebase", "origin", "staging"]

    def test_pull_resets_on_unstaged_changes(self, mock_subprocess_run, updater):
        """When pull fails with unstaged changes, falls back to reset+clean."""
        mock_subprocess_run.side_effect = [
            _make_result(0, stdout="main\n"),    # rev-parse
            _make_result(0),                      # stash push
            subprocess.CalledProcessError(        # pull --rebase (fails)
                1, ["git", "pull", "--rebase", "origin", "main"],
                stderr="Cannot pull with rebase: You have unstaged changes."
            ),
            _make_result(0),                      # reset --hard
            _make_result(0),                      # clean -fd
            _make_result(0),                      # pull --rebase (retry)
        ]

        updater.pull()
        calls = mock_subprocess_run.call_args_list
        assert calls[3].args[0] == ["git", "reset", "--hard", "HEAD"]
        assert calls[4].args[0] == ["git", "clean", "-fd"]
        assert calls[5].args[0] == ["git", "pull", "--rebase", "origin", "main"]


# ── stage_files ───────────────────────────────────────────────────────

class TestStageFiles:
    def test_stages_config_and_source(self, mock_subprocess_run, updater):
        file_pairs = [("local.txt", "githubmirror/remote.txt")]
        updater.stage_files(file_pairs)
        calls = mock_subprocess_run.call_args_list
        assert len(calls) == 3
        assert calls[0].args[0] == ["git", "add", "-A", "githubmirror"]
        assert calls[1].args[0] == ["git", "add", "source/config/URLS.txt"]
        assert calls[2].args[0] == ["git", "add", "source/config/servers.txt"]


# ── has_changes ───────────────────────────────────────────────────────

class TestHasChanges:
    def test_returns_true_when_diff_cached_nonzero(self, mock_subprocess_run, updater):
        mock_subprocess_run.return_value = _make_result(1)
        assert updater.has_changes() is True

    def test_returns_false_when_clean(self, mock_subprocess_run, updater):
        mock_subprocess_run.return_value = _make_result(0)
        assert updater.has_changes() is False

    def test_returns_false_on_error(self, mock_subprocess_run, updater):
        mock_subprocess_run.side_effect = subprocess.TimeoutExpired("git", 60)
        assert updater.has_changes() is False


# ── commit ────────────────────────────────────────────────────────────

class TestCommit:
    def test_commits_with_message(self, mock_subprocess_run, updater):
        # First has_changes call returns True (non-zero)
        mock_subprocess_run.return_value = _make_result(1)

        result = updater.commit("auto: update configs")
        assert result is True

        calls = mock_subprocess_run.call_args_list
        assert calls[1].args[0] == ["git", "commit", "-m", "auto: update configs"]

    def test_returns_false_when_no_changes(self, mock_subprocess_run, updater):
        mock_subprocess_run.return_value = _make_result(0)

        result = updater.commit("auto: update configs")
        assert result is False
        # Only has_changes called, no commit
        assert len(mock_subprocess_run.call_args_list) == 1

    def test_uses_default_message(self, mock_subprocess_run, updater):
        # has_changes returns True
        mock_subprocess_run.return_value = _make_result(1)

        updater.commit()
        assert mock_subprocess_run.call_args_list[1].args[0][3] == "auto: update configs"


# ── push ──────────────────────────────────────────────────────────────

class TestPush:
    def test_push_detects_branch(self, mock_subprocess_run, updater):
        mock_subprocess_run.return_value = _make_result(0, stdout="main\n")

        updater.push()

        calls = mock_subprocess_run.call_args_list
        assert calls[0].args[0] == ["git", "rev-parse", "--abbrev-ref", "HEAD"]
        assert calls[1].args[0] == ["git", "push", "origin", "main"]

    def test_push_with_explicit_branch(self, mock_subprocess_run, updater):
        updater.push(branch="staging")
        assert mock_subprocess_run.call_args_list[0].args[0] == ["git", "push", "origin", "staging"]

    def test_force_push(self, mock_subprocess_run, updater):
        mock_subprocess_run.return_value = _make_result(0, stdout="main\n")
        updater.push(force=True)
        assert mock_subprocess_run.call_args_list[1].args[0] == ["git", "push", "-f", "origin", "main"]


# ── commit_and_push_files (full workflow) ─────────────────────────────

class TestCommitAndPushFiles:
    def test_full_successful_workflow(self, mock_subprocess_run, updater):
        """Happy path: config git, stage, commit, push — all succeed."""
        def side_effect(cmd, *args, **kwargs):
            if cmd == ["git", "diff", "--cached", "--quiet"]:
                return _make_result(1)  # has changes
            if cmd == ["git", "rev-parse", "--abbrev-ref", "HEAD"]:
                return _make_result(0, stdout="main\n")
            return _make_result(0)

        mock_subprocess_run.side_effect = side_effect

        result = updater.commit_and_push_files([("local.txt", "githubmirror/remote.txt")])
        assert result is True

    def test_skips_commit_when_no_changes(self, mock_subprocess_run, updater):
        """No changes detected — return True without committing."""
        mock_subprocess_run.return_value = _make_result(0)

        result = updater.commit_and_push_files([("local.txt", "githubmirror/remote.txt")])
        assert result is True

        commit_calls = [
            c for c in mock_subprocess_run.call_args_list
            if c.args[0][:2] == ["git", "commit"]
        ]
        assert len(commit_calls) == 0

    def test_retries_on_push_failure(self, mock_subprocess_run, updater):
        """Push fails first time, pull+retry succeeds."""
        push_count = [0]

        def side_effect(cmd, *args, **kwargs):
            if cmd == ["git", "diff", "--cached", "--quiet"]:
                return _make_result(1)  # has changes
            if cmd == ["git", "rev-parse", "--abbrev-ref", "HEAD"]:
                return _make_result(0, stdout="main\n")
            if len(cmd) > 1 and cmd[0] == "git" and cmd[1] == "push":
                push_count[0] += 1
                if push_count[0] == 1:
                    raise subprocess.CalledProcessError(
                        1, cmd, stderr="! [rejected] non-fast-forward"
                    )
                return _make_result(0)
            return _make_result(0)

        mock_subprocess_run.side_effect = side_effect

        result = updater.commit_and_push_files([("local.txt", "githubmirror/remote.txt")])
        assert result is True

        pull_calls = [
            c for c in mock_subprocess_run.call_args_list
            if c.args[0][:3] == ["git", "pull", "--rebase"]
        ]
        assert len(pull_calls) == 2  # initial pull + retry pull after failed push

    def test_fails_after_max_retries(self, mock_subprocess_run, updater):
        """All push attempts fail."""
        def side_effect(cmd, *args, **kwargs):
            if cmd == ["git", "diff", "--cached", "--quiet"]:
                return _make_result(1)
            if cmd == ["git", "rev-parse", "--abbrev-ref", "HEAD"]:
                return _make_result(0, stdout="main\n")
            if len(cmd) > 1 and cmd[0] == "git" and cmd[1] == "push":
                raise subprocess.CalledProcessError(
                    1, cmd, stderr="! [rejected] non-fast-forward"
                )
            return _make_result(0)

        mock_subprocess_run.side_effect = side_effect

        result = updater.commit_and_push_files(
            [("local.txt", "githubmirror/remote.txt")],
            max_retries=2,
        )
        assert result is False

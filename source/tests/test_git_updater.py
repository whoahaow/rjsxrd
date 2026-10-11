"""Tests for utils/git_updater using mocked subprocess.

Covers: init, configure, pull, stage, commit, push, full workflow,
retry on push conflict, and error handling.
"""

import os
import subprocess
from unittest.mock import patch

import pytest

from tests.support import make_result
from utils.git_updater import GitUpdater

pytestmark = pytest.mark.unit

# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def mock_subprocess_run():
    """Mock subprocess.run to return success by default."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = make_result(0)
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
        assert len(calls) == 3
        assert calls[0].args[0] == ["git", "config", "user.name", "GitHub Actions"]
        assert calls[1].args[0] == ["git", "config", "user.email", "actions@github.com"]
        assert calls[2].args[0] == ["git", "remote", "get-url", "origin"]


# ── ensure_authenticated_remote & sanitization ────────────────────────


class TestEnsureAuthenticatedRemote:
    def test_updates_origin_when_token_in_env(self, mock_subprocess_run, updater, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_secrettoken123")
        mock_subprocess_run.side_effect = [
            make_result(0, stdout="https://github.com/whoahaow/rjsxrd.git\n"),
            make_result(0),
        ]

        updater.ensure_authenticated_remote()

        calls = mock_subprocess_run.call_args_list
        assert calls[0].args[0] == ["git", "remote", "get-url", "origin"]
        assert calls[1].args[0] == [
            "git",
            "remote",
            "set-url",
            "origin",
            "https://x-access-token:ghp_secrettoken123@github.com/whoahaow/rjsxrd.git",
        ]

    def test_replaces_old_token_when_regenerated_in_env(self, mock_subprocess_run, updater, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "github_pat_newtoken456")
        mock_subprocess_run.side_effect = [
            make_result(0, stdout="https://github_pat_oldtoken123@github.com/whoahaow/rjsxrd.git\n"),
            make_result(0),
        ]

        updater.ensure_authenticated_remote()

        calls = mock_subprocess_run.call_args_list
        assert calls[1].args[0] == [
            "git",
            "remote",
            "set-url",
            "origin",
            "https://x-access-token:github_pat_newtoken456@github.com/whoahaow/rjsxrd.git",
        ]

    def test_fixes_bare_token_without_token_in_env(self, mock_subprocess_run, updater, monkeypatch):
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("MY_TOKEN", raising=False)
        mock_subprocess_run.side_effect = [
            make_result(0, stdout="https://github_pat_mysecrettoken@github.com/whoahaow/rjsxrd.git\n"),
            make_result(0),
        ]

        updater.ensure_authenticated_remote()

        calls = mock_subprocess_run.call_args_list
        assert calls[1].args[0] == [
            "git",
            "remote",
            "set-url",
            "origin",
            "https://x-access-token:github_pat_mysecrettoken@github.com/whoahaow/rjsxrd.git",
        ]

    def test_ignores_ssh_url(self, mock_subprocess_run, updater, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_secrettoken123")
        mock_subprocess_run.return_value = make_result(0, stdout="git@github.com:whoahaow/rjsxrd.git\n")

        updater.ensure_authenticated_remote()

        calls = mock_subprocess_run.call_args_list
        assert len(calls) == 1
        assert calls[0].args[0] == ["git", "remote", "get-url", "origin"]

    def test_does_nothing_if_origin_already_matches_token(self, mock_subprocess_run, updater, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_secrettoken123")
        mock_subprocess_run.return_value = make_result(
            0, stdout="https://x-access-token:ghp_secrettoken123@github.com/whoahaow/rjsxrd.git\n"
        )

        updater.ensure_authenticated_remote()

        calls = mock_subprocess_run.call_args_list
        assert len(calls) == 1

    def test_handles_remote_error_gracefully(self, mock_subprocess_run, updater):
        mock_subprocess_run.side_effect = subprocess.CalledProcessError(
            1, ["git", "remote"], stderr="fatal: not a git repo"
        )

        # Must not raise
        updater.ensure_authenticated_remote()


class TestSanitizeGitMessage:
    def test_masks_token_in_https_url(self):
        from utils.git_updater import _sanitize_git_message

        msg = "fatal: could not read Password for 'https://x-access-token:ghp_secret@github.com/repo': No such device"
        sanitized = _sanitize_git_message(msg)
        assert "ghp_secret" not in sanitized
        assert "https://***@github.com/repo" in sanitized

    def test_masks_bare_token_in_https_url(self):
        from utils.git_updater import _sanitize_git_message

        cmd = "git push https://github_pat_123456@github.com/whoahaow/rjsxrd.git main"
        sanitized = _sanitize_git_message(cmd)
        assert "github_pat_123456" not in sanitized
        assert "https://***@github.com" in sanitized


# ── pull ──────────────────────────────────────────────────────────────


class TestPull:
    def test_pull_detects_branch(self, mock_subprocess_run, updater):
        mock_subprocess_run.return_value = make_result(0, stdout="main\n")

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
            make_result(0, stdout="main\n"),  # rev-parse
            make_result(0),  # stash push
            subprocess.CalledProcessError(  # pull --rebase (fails)
                1,
                ["git", "pull", "--rebase", "origin", "main"],
                stderr="Cannot pull with rebase: You have unstaged changes.",
            ),
            make_result(0),  # reset --hard
            make_result(0),  # clean -fd
            make_result(0),  # pull --rebase (retry)
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
        mock_subprocess_run.return_value = make_result(1)
        assert updater.has_changes() is True

    def test_returns_false_when_clean(self, mock_subprocess_run, updater):
        mock_subprocess_run.return_value = make_result(0)
        assert updater.has_changes() is False

    def test_returns_false_on_error(self, mock_subprocess_run, updater):
        mock_subprocess_run.side_effect = subprocess.TimeoutExpired("git", 60)
        assert updater.has_changes() is False


# ── commit ────────────────────────────────────────────────────────────


class TestCommit:
    def test_commits_with_message(self, mock_subprocess_run, updater):
        # First has_changes call returns True (non-zero)
        mock_subprocess_run.return_value = make_result(1)

        result = updater.commit("auto: update configs")
        assert result is True

        calls = mock_subprocess_run.call_args_list
        assert calls[1].args[0] == ["git", "commit", "-m", "auto: update configs"]

    def test_returns_false_when_no_changes(self, mock_subprocess_run, updater):
        mock_subprocess_run.return_value = make_result(0)

        result = updater.commit("auto: update configs")
        assert result is False
        # Only has_changes called, no commit
        assert len(mock_subprocess_run.call_args_list) == 1

    def test_uses_default_message(self, mock_subprocess_run, updater):
        # has_changes returns True
        mock_subprocess_run.return_value = make_result(1)

        updater.commit()
        assert mock_subprocess_run.call_args_list[1].args[0][3] == "auto: update configs"


# ── push ──────────────────────────────────────────────────────────────


class TestPush:
    def test_push_detects_branch(self, mock_subprocess_run, updater):
        mock_subprocess_run.return_value = make_result(0, stdout="main\n")

        updater.push()

        calls = mock_subprocess_run.call_args_list
        assert calls[0].args[0] == ["git", "rev-parse", "--abbrev-ref", "HEAD"]
        assert calls[1].args[0] == ["git", "push", "origin", "main"]

    def test_push_with_explicit_branch(self, mock_subprocess_run, updater):
        updater.push(branch="staging")
        assert mock_subprocess_run.call_args_list[0].args[0] == ["git", "push", "origin", "staging"]

    def test_force_push(self, mock_subprocess_run, updater):
        mock_subprocess_run.return_value = make_result(0, stdout="main\n")
        updater.push(force=True)
        assert mock_subprocess_run.call_args_list[1].args[0] == [
            "git",
            "push",
            "-f",
            "origin",
            "main",
        ]


# ── commit_and_push_single (progressive push) ─────────────────────────


class TestCommitAndPushSingle:
    def test_progressive_commit_and_push_happy_path(self, mock_subprocess_run, updater):
        mock_subprocess_run.return_value = make_result(0, stdout="main\n")

        updater.commit_and_push_single("githubmirror/bypass/bypass-1.txt", "auto: update bypass-1.txt")

        calls = mock_subprocess_run.call_args_list
        assert calls[0].args[0] == ["git", "add", "githubmirror/bypass/bypass-1.txt"]
        assert calls[1].args[0] == ["git", "commit", "--allow-empty", "-m", "auto: update bypass-1.txt"]
        assert calls[2].args[0] == ["git", "rev-parse", "--abbrev-ref", "HEAD"]
        assert calls[3].args[0] == ["git", "push", "origin", "main"]

    def test_progressive_push_retries_and_pulls_on_failure(self, mock_subprocess_run, updater):
        push_count = [0]

        def side_effect(cmd, *args, **kwargs):
            if cmd == ["git", "rev-parse", "--abbrev-ref", "HEAD"]:
                return make_result(0, stdout="main\n")
            if len(cmd) > 1 and cmd[0] == "git" and cmd[1] == "push":
                push_count[0] += 1
                if push_count[0] == 1:
                    raise subprocess.CalledProcessError(1, cmd, stderr="! [rejected] (fetch first)")
                return make_result(0)
            return make_result(0)

        mock_subprocess_run.side_effect = side_effect

        updater.commit_and_push_single("githubmirror/bypass/bypass-1.txt", "auto: update bypass-1.txt", max_retries=2)

        assert push_count[0] == 2
        pull_calls = [
            c
            for c in mock_subprocess_run.call_args_list
            if c.args[0][:3] == ["git", "pull", "--rebase"]
        ]
        assert len(pull_calls) == 1

    def test_progressive_push_raises_when_retries_exhausted(self, mock_subprocess_run, updater):
        def side_effect(cmd, *args, **kwargs):
            if cmd == ["git", "rev-parse", "--abbrev-ref", "HEAD"]:
                return make_result(0, stdout="main\n")
            if len(cmd) > 1 and cmd[0] == "git" and cmd[1] == "push":
                raise subprocess.CalledProcessError(1, cmd, stderr="! [rejected] (fetch first)")
            return make_result(0)

        mock_subprocess_run.side_effect = side_effect

        with pytest.raises(subprocess.CalledProcessError):
            updater.commit_and_push_single("githubmirror/bypass/bypass-1.txt", "auto: update bypass-1.txt", max_retries=2)


# ── commit_and_push_files (full workflow) ─────────────────────────────


class TestCommitAndPushFiles:
    def test_full_successful_workflow(self, mock_subprocess_run, updater):
        """Happy path: config git, stage, commit, push — all succeed."""

        def side_effect(cmd, *args, **kwargs):
            if cmd == ["git", "diff", "--cached", "--quiet"]:
                return make_result(1)  # has changes
            if cmd == ["git", "rev-parse", "--abbrev-ref", "HEAD"]:
                return make_result(0, stdout="main\n")
            return make_result(0)

        mock_subprocess_run.side_effect = side_effect

        result = updater.commit_and_push_files([("local.txt", "githubmirror/remote.txt")])
        assert result is True

    def test_skips_commit_when_no_changes(self, mock_subprocess_run, updater):
        """No changes detected — return True without committing."""
        mock_subprocess_run.return_value = make_result(0)

        result = updater.commit_and_push_files([("local.txt", "githubmirror/remote.txt")])
        assert result is True

        commit_calls = [
            c for c in mock_subprocess_run.call_args_list if c.args[0][:2] == ["git", "commit"]
        ]
        assert len(commit_calls) == 0

    def test_retries_on_push_failure(self, mock_subprocess_run, updater, monkeypatch):
        """Push fails first time, pull+retry succeeds."""
        monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
        push_count = [0]

        def side_effect(cmd, *args, **kwargs):
            if cmd == ["git", "diff", "--cached", "--quiet"]:
                return make_result(1)  # has changes
            if cmd == ["git", "rev-parse", "--abbrev-ref", "HEAD"]:
                return make_result(0, stdout="main\n")
            if len(cmd) > 1 and cmd[0] == "git" and cmd[1] == "push":
                push_count[0] += 1
                if push_count[0] == 1:
                    raise subprocess.CalledProcessError(
                        1, cmd, stderr="! [rejected] non-fast-forward"
                    )
                return make_result(0)
            return make_result(0)

        mock_subprocess_run.side_effect = side_effect

        result = updater.commit_and_push_files([("local.txt", "githubmirror/remote.txt")])
        assert result is True

        pull_calls = [
            c
            for c in mock_subprocess_run.call_args_list
            if c.args[0][:3] == ["git", "pull", "--rebase"]
        ]
        assert len(pull_calls) == 2  # initial pull + retry pull after failed push
        assert push_count[0] == 2

    def test_fails_after_max_retries(self, mock_subprocess_run, updater):
        """All push attempts fail."""

        def side_effect(cmd, *args, **kwargs):
            if cmd == ["git", "diff", "--cached", "--quiet"]:
                return make_result(1)
            if cmd == ["git", "rev-parse", "--abbrev-ref", "HEAD"]:
                return make_result(0, stdout="main\n")
            if len(cmd) > 1 and cmd[0] == "git" and cmd[1] == "push":
                raise subprocess.CalledProcessError(1, cmd, stderr="! [rejected] non-fast-forward")
            return make_result(0)

        mock_subprocess_run.side_effect = side_effect

        result = updater.commit_and_push_files(
            [("local.txt", "githubmirror/remote.txt")],
            max_retries=2,
        )
        assert result is False

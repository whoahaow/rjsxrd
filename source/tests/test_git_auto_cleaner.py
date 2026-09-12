"""Tests for utils/git_auto_cleaner using mocked subprocess.

Covers: is_auto_message (only ^auto: update ), squash_auto_commits edge cases.
"""

import subprocess
from unittest.mock import MagicMock, patch

from utils.git_auto_cleaner import is_auto_message, squash_auto_commits

# ── Helpers ───────────────────────────────────────────────────────────


def _make_result(returncode=0, stdout="", stderr=""):
    r = MagicMock(spec=subprocess.CompletedProcess)
    r.stdout = stdout
    r.stderr = stderr
    r.returncode = returncode
    return r


def _build_git_log_side_effect(messages: list):
    """Build side_effect for subprocess.run that returns git log messages.

    Each call with 'git log -1 --format=%s <target>' returns the next
    message from the list. First call = HEAD, second = HEAD~1, etc.
    After the list is exhausted, returns non-zero (simulating end of history).

    'git rev-parse --verify' returns a fake SHA.
    'git reset --soft' returns success.
    All other commands return success with empty stdout (safe default).
    """
    log_index = [0]

    def side_effect(cmd, *args, **kwargs):
        if isinstance(cmd, list) and cmd[:4] == ["git", "log", "-1", "--format=%s"]:
            i = log_index[0]
            log_index[0] += 1
            if i < len(messages):
                return _make_result(0, stdout=messages[i] + "\n")
            return _make_result(128, stderr="fatal: ambiguous argument")
        if isinstance(cmd, list) and cmd[:3] == ["git", "rev-parse", "--verify"]:
            return _make_result(0, stdout="deadbeef1234567890\n")
        if isinstance(cmd, list) and cmd[:3] == ["git", "reset", "--soft"]:
            return _make_result(0)
        return _make_result(0)

    return side_effect


# ── is_auto_message ──────────────────────────────────────────────────


class TestIsAutoMessage:
    def test_auto_update_matches(self):
        assert is_auto_message("auto: update bypass-all.txt: 17:21 | 27.06.2026") is True

    def test_auto_add_does_not_match(self):
        """auto: add is intentionally excluded — only auto: update is matched."""
        assert is_auto_message("auto: add bypass-4.txt: 03:24 | 26.06.2026") is False

    def test_update_bypass_does_not_match(self):
        """Old format Update bypass-* is intentionally excluded."""
        assert is_auto_message("Update bypass-1.txt: 20:35 | 25.06.2026") is False

    def test_first_commit_bypass_does_not_match(self):
        assert is_auto_message("First commit bypass-5.txt: 23:32 | 25.06.2026") is False

    def test_update_configs_does_not_match(self):
        assert is_auto_message("update configs") is False

    def test_fix_commit_does_not_match(self):
        assert is_auto_message("fix: correct rate_limiting_resettime") is False

    def test_feat_commit_does_not_match(self):
        assert is_auto_message("feat: progressive upload") is False

    def test_chore_commit_does_not_match(self):
        assert is_auto_message("chore: reduce xray concurrency") is False

    def test_merge_commit_does_not_match(self):
        assert is_auto_message("Merge remote-tracking branch 'origin/main'") is False

    def test_merge_pull_does_not_match(self):
        assert is_auto_message("merge: pull remote auto commits") is False

    def test_empty_string_does_not_match(self):
        assert is_auto_message("") is False

    def test_auto_in_body_not_prefix(self):
        assert is_auto_message("chore: auto-commit configs") is False

    def test_reinit_does_not_match(self):
        assert is_auto_message("reinit") is False


# ── squash_auto_commits ───────────────────────────────────────────────


class TestSquashAutoCommits:
    def test_no_auto_commits_at_tip(self):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = _build_git_log_side_effect(
                [
                    "fix: correct rate_limiting_resettime",
                ]
            )
            result = squash_auto_commits(repo_dir="/fake/path")
            assert result == 0

    def test_single_auto_commit_at_tip(self):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = _build_git_log_side_effect(
                [
                    "auto: update bypass-all.txt: 17:21 | 27.06.2026",
                    "fix: correct rate_limiting_resettime",
                ]
            )
            result = squash_auto_commits(repo_dir="/fake/path")
            assert result == 0  # < 2 threshold

    def test_two_auto_commits_squashed(self):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = _build_git_log_side_effect(
                [
                    "auto: update bypass-all.txt: 17:21 | 27.06.2026",
                    "auto: update bypass-all.txt: 16:00 | 27.06.2026",
                    "fix: correct rate_limiting_resettime",
                ]
            )
            result = squash_auto_commits(repo_dir="/fake/path")
            assert result == 2
            reset_calls = [
                c for c in mock_run.call_args_list if c.args[0][:3] == ["git", "reset", "--soft"]
            ]
            assert len(reset_calls) == 1

    def test_five_auto_commits_squashed(self):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = _build_git_log_side_effect(
                [
                    "auto: update bypass-1.txt: 10:05 | 27.06.2026",
                    "auto: update bypass-2.txt: 10:07 | 27.06.2026",
                    "auto: update bypass-3.txt: 10:09 | 27.06.2026",
                    "auto: update bypass-4.txt: 10:11 | 27.06.2026",
                    "auto: update bypass-5.txt: 10:15 | 27.06.2026",
                    "fix: something meaningful",
                ]
            )
            result = squash_auto_commits(repo_dir="/fake/path")
            assert result == 5

    def test_old_format_stops_walk(self):
        """Old format 'Update bypass-' does NOT match, so walk stops at it."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = _build_git_log_side_effect(
                [
                    "auto: update bypass-all.txt: 12:17 | 27.06.2026",
                    "Update bypass-1.txt: 20:35 | 25.06.2026",
                    "feat: real feature",
                ]
            )
            result = squash_auto_commits(repo_dir="/fake/path")
            assert result == 0  # only 1 auto:update commit, threshold < 2

    def test_merge_commit_stops_walk(self):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = _build_git_log_side_effect(
                [
                    "auto: update bypass-all.txt: 17:21 | 27.06.2026",
                    "merge: pull remote auto commits",
                ]
            )
            result = squash_auto_commits(repo_dir="/fake/path")
            assert result == 0

    def test_auto_after_merge_chain_still_squashes(self):
        """Auto commits at tip after a merge -> squash them (they're contiguous)."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = _build_git_log_side_effect(
                [
                    "auto: update bypass-1.txt: 08:05 | 27.06.2026",
                    "auto: update bypass-2.txt: 08:07 | 27.06.2026",
                    "auto: update bypass-3.txt: 08:09 | 27.06.2026",
                    "merge: pull remote auto commits",
                ]
            )
            result = squash_auto_commits(repo_dir="/fake/path")
            assert result == 3

    def test_handles_rev_parse_failure(self):
        with patch("subprocess.run") as mock_run:
            messages = [
                "auto: update bypass-all.txt: 17:21 | 27.06.2026",
                "auto: update bypass-all.txt: 16:00 | 27.06.2026",
                "auto: update bypass-all.txt: 15:00 | 27.06.2026",
                "reinit",
            ]

            def side_effect(cmd, *args, **kwargs):
                if isinstance(cmd, list) and cmd[:4] == ["git", "log", "-1", "--format=%s"]:
                    depth = cmd[4].count("~")
                    if depth < len(messages):
                        return _make_result(0, stdout=messages[depth] + "\n")
                    return _make_result(128, stderr="fatal: ambiguous argument")
                if isinstance(cmd, list) and cmd[:3] == ["git", "rev-parse", "--verify"]:
                    return _make_result(128, stderr="fatal: Needed a single revision")
                return _make_result(0)

            mock_run.side_effect = side_effect
            result = squash_auto_commits(repo_dir="/fake/path")
            assert result == 0  # rev-parse failed

    def test_reset_soft_called_with_correct_target(self):
        with patch("subprocess.run") as mock_run:
            messages = [
                "auto: update bypass-1.txt: 08:05 | 27.06.2026",
                "auto: update bypass-2.txt: 08:07 | 27.06.2026",
                "auto: update bypass-3.txt: 08:09 | 27.06.2026",
                "fix: real commit that should stay",
            ]

            def side_effect(cmd, *args, **kwargs):
                if isinstance(cmd, list) and cmd[:4] == ["git", "log", "-1", "--format=%s"]:
                    depth = cmd[4].count("~")
                    if depth < len(messages):
                        return _make_result(0, stdout=messages[depth] + "\n")
                    return _make_result(128, stderr="fatal: ambiguous argument")
                if isinstance(cmd, list) and cmd[:3] == ["git", "rev-parse", "--verify"]:
                    assert cmd[3] == "HEAD~1~1~1"  # 3 auto commits back
                    return _make_result(0, stdout="abc123def\n")
                if isinstance(cmd, list) and cmd[:3] == ["git", "reset", "--soft"]:
                    assert cmd[3] == "abc123def"
                    return _make_result(0)
                return _make_result(0)

            mock_run.side_effect = side_effect
            result = squash_auto_commits(repo_dir="/fake/path")
            assert result == 3

    def test_git_log_failure_at_tip(self):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = _build_git_log_side_effect([])
            result = squash_auto_commits(repo_dir="/fake/path")
            assert result == 0

    def test_auto_add_does_not_count_as_auto(self):
        """auto: add is excluded, so walk stops and nothing is squashed."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = _build_git_log_side_effect(
                [
                    "auto: update bypass-all.txt: 17:21 | 27.06.2026",
                    "auto: add bypass-4.txt: 03:24 | 26.06.2026",
                ]
            )
            result = squash_auto_commits(repo_dir="/fake/path")
            assert result == 0  # only 1 auto:update, threshold < 2

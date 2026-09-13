"""Tests for utils/github_handler using FakeGitHubClient.

Covers: file creation, update, no-change skip, rate limit handling,
conflict resolution, missing file handling, and batch upload.
"""

import time
from unittest.mock import MagicMock, patch

import pytest

from utils.github_handler import (
    GitHubHandler,
    _GitHubClient,
)

pytestmark = pytest.mark.unit


class FakeGitHubClient(_GitHubClient):
    """In-memory fake for GitHub API operations.

    Simulates a flat file tree with SHA tracking, rate limiting, and 409
    conflicts on stale SHA updates.
    """

    def __init__(self):
        self.files = {}  # path -> {"content": str, "sha": str}
        self._sha_counter = 0
        self._remaining = 5000
        self._limit = 5000
        self._reset_time = time.time() + 3600
        self._fail_on_create = False
        self._fail_on_update = False
        self._fail_on_get = False
        self._conflict_on_update = False

    def get_repo(self, repo_name: str):
        return MagicMock(name=repo_name)

    def get_rate_limiting(self):
        return self._remaining, self._limit

    def get_rate_limiting_reset(self):
        return self._reset_time

    def set_rate_remaining(self, remaining: int):
        self._remaining = remaining

    def get_contents(self, repo, remote_path: str):
        if self._fail_on_get:
            raise OSError("Simulated get failure")
        entry = self.files.get(remote_path)
        if entry is None:
            return None, None
        return entry["content"].encode("utf-8"), entry["sha"]

    def create_file(self, repo, remote_path: str, message: str, content: str):
        if self._fail_on_create:
            raise RuntimeError("Simulated create failure")
        if remote_path in self.files:
            raise RuntimeError(f"File already exists: {remote_path}")
        self._sha_counter += 1
        self.files[remote_path] = {
            "content": content,
            "sha": f"sha-{self._sha_counter}",
        }
        return True

    def update_file(self, repo, remote_path: str, message: str, content: str, sha: str):
        if self._fail_on_update:
            raise RuntimeError("Simulated update failure")
        if self._conflict_on_update:
            raise RuntimeError("409 conflict - stale SHA")
        entry = self.files.get(remote_path)
        if entry is None:
            raise RuntimeError(f"File not found: {remote_path}")
        if entry["sha"] != sha:
            # Simulate 409 Conflict
            from github import GithubException

            exc = GithubException(409, {"message": "SHA mismatch"}, None)
            raise exc
        self._sha_counter += 1
        entry["content"] = content
        entry["sha"] = f"sha-{self._sha_counter}"
        return True


class TestGitHubHandlerInit:
    """Handler initializes cleanly with a fake client."""

    def test_accepts_custom_client(self):
        fake = FakeGitHubClient()
        handler = GitHubHandler(client=fake)
        assert handler._client is fake
        assert handler.repo is not None

    def test_defaults_to_pygithub_client(self):
        handler = GitHubHandler()
        assert isinstance(handler._client, _GitHubClient)

    def test_handles_repo_not_found(self):
        fake = FakeGitHubClient()
        # Simulate get_repo returning None
        with patch.object(fake, "get_repo", return_value=None):
            handler = GitHubHandler(client=fake)
            assert handler.repo is None


class TestUploadFile:
    """Upload a single file with various scenarios."""

    def test_creates_new_file(self, tmp_path):
        fake = FakeGitHubClient()
        handler = GitHubHandler(client=fake)
        local_path = tmp_path / "test.txt"
        local_path.write_text("hello world")

        result = handler.upload_file(str(local_path), "test.txt")

        assert result is True
        assert fake.files["test.txt"]["content"] == "hello world"

    def test_updates_existing_file(self, tmp_path):
        fake = FakeGitHubClient()
        fake.files["test.txt"] = {"content": "old", "sha": "sha-1"}
        handler = GitHubHandler(client=fake)
        local_path = tmp_path / "test.txt"
        local_path.write_text("new content")

        result = handler.upload_file(str(local_path), "test.txt")

        assert result is True
        assert fake.files["test.txt"]["content"] == "new content"

    def test_skips_if_content_unchanged(self, tmp_path):
        fake = FakeGitHubClient()
        content = "same content"
        fake.files["test.txt"] = {"content": content, "sha": "sha-1"}
        handler = GitHubHandler(client=fake)
        local_path = tmp_path / "test.txt"
        local_path.write_text(content)

        result = handler.upload_file(str(local_path), "test.txt")

        assert result is True
        # SHA should NOT have changed (no update was made)
        assert fake.files["test.txt"]["sha"] == "sha-1"

    def test_returns_false_if_file_missing(self):
        fake = FakeGitHubClient()
        handler = GitHubHandler(client=fake)

        result = handler.upload_file("/nonexistent/file.txt", "remote.txt")

        assert result is False

    def test_returns_false_if_repo_none(self, tmp_path):
        fake = FakeGitHubClient()
        handler = GitHubHandler(client=fake)
        handler.repo = None
        local_path = tmp_path / "test.txt"
        local_path.write_text("data")

        result = handler.upload_file(str(local_path), "test.txt")

        assert result is False

    def test_retries_on_409_conflict(self, tmp_path):
        fake = FakeGitHubClient()
        fake.files["test.txt"] = {"content": "base", "sha": "sha-1"}
        handler = GitHubHandler(client=fake)
        local_path = tmp_path / "test.txt"
        local_path.write_text("new data")

        # First update fails with 409 (simulate by swapping SHA on first attempt)
        original_update = fake.update_file

        call_count = [0]

        def flaky_update(repo, path, msg, content, sha):
            call_count[0] += 1
            if call_count[0] == 1:
                # First call: simulate stale SHA by passing wrong one to the fake
                fake.files[path]["sha"] = "sha-different"
            return original_update(repo, path, msg, content, sha)

        fake.update_file = flaky_update

        # Re-read so fake has correct sha
        fake.files["test.txt"] = {"content": "base", "sha": "sha-1"}
        result = handler.upload_file(str(local_path), "test.txt")

        # Should eventually succeed (the 409 triggers a re-read + retry)
        assert result is True

    def test_rate_limit_wait_and_retry(self, tmp_path):
        fake = FakeGitHubClient()
        # Start with 0 remaining, reset after first check
        fake.set_rate_remaining(0)
        fake._reset_time = time.time() - 1  # past, so wait_seconds = 0
        handler = GitHubHandler(client=fake)
        local_path = tmp_path / "test.txt"
        local_path.write_text("data")

        call_count = [0]

        def reset_on_second_check():
            call_count[0] += 1
            if call_count[0] >= 2:
                return 5000, 5000
            return 0, 5000

        fake.get_rate_limiting = reset_on_second_check

        result = handler.upload_file(str(local_path), "test.txt")

        assert result is True

    def test_still_rate_limited_after_wait(self, tmp_path):
        fake = FakeGitHubClient()
        # Remaining is 0, reset is in the past but remaining never recovers
        fake.set_rate_remaining(0)
        fake._reset_time = time.time() - 1  # past, so wait_seconds = 0
        handler = GitHubHandler(client=fake)
        local_path = tmp_path / "test.txt"
        local_path.write_text("data")

        result = handler.upload_file(str(local_path), "test.txt")

        # Still rate limited (remaining stays 0 after re-check), should skip
        assert result is False


class TestUploadMultipleFiles:
    """Batch upload behavior."""

    def test_uploads_all_files(self, tmp_path):
        fake = FakeGitHubClient()
        handler = GitHubHandler(client=fake)

        files = []
        for i in range(3):
            local = tmp_path / f"file{i}.txt"
            local.write_text(f"content {i}")
            files.append((str(local), f"remote{i}.txt"))

        failures = handler.upload_multiple_files(files)

        assert failures == 0
        assert fake.files["remote0.txt"]["content"] == "content 0"
        assert fake.files["remote1.txt"]["content"] == "content 1"
        assert fake.files["remote2.txt"]["content"] == "content 2"

    def test_skips_on_dry_run(self, tmp_path):
        fake = FakeGitHubClient()
        handler = GitHubHandler(client=fake)

        files = [(str(tmp_path / "test.txt"), "remote.txt")]
        tmp_path.joinpath("test.txt").write_text("data")

        failures = handler.upload_multiple_files(files, dry_run=True)

        assert failures == 0
        assert "remote.txt" not in fake.files

    def test_counts_failures(self, tmp_path):
        fake = FakeGitHubClient()
        fake._fail_on_update = True
        handler = GitHubHandler(client=fake)

        files = [(str(tmp_path / "test.txt"), "remote.txt")]
        tmp_path.joinpath("test.txt").write_text("data")
        fake.files["remote.txt"] = {"content": "old", "sha": "sha-1"}

        failures = handler.upload_multiple_files(files)

        assert failures > 0


class TestRateLimitStatus:
    """Rate limit checking."""

    def test_returns_has_capacity_when_ok(self):
        fake = FakeGitHubClient()
        handler = GitHubHandler(client=fake)

        status = handler._check_rate_limit(required_requests=1)

        assert status.has_capacity is True
        assert status.seconds_to_wait == 0

    def test_returns_no_capacity_when_exhausted(self):
        fake = FakeGitHubClient()
        fake.set_rate_remaining(0)
        handler = GitHubHandler(client=fake)

        status = handler._check_rate_limit(required_requests=1)

        assert status.has_capacity is False
        assert status.seconds_to_wait > 0

    def test_proceeds_on_rate_check_failure(self):
        fake = FakeGitHubClient()
        handler = GitHubHandler(client=fake)

        with patch.object(fake, "get_rate_limiting", side_effect=OSError("no net")):
            status = handler._check_rate_limit(required_requests=1)

        assert status.has_capacity is True  # proceed on error
        assert status.seconds_to_wait == 0


class TestFileHelpers:
    """Static helper methods."""

    def test_file_exists_returns_true(self, tmp_path):
        p = tmp_path / "exists.txt"
        p.write_text("data")
        assert GitHubHandler._file_exists(str(p)) is True

    def test_file_exists_returns_false(self):
        assert GitHubHandler._file_exists("/nonexistent/thing.txt") is False

    def test_get_basename(self):
        assert GitHubHandler._get_basename("path/to/file.txt") == "file.txt"

    def test_get_timestamp_returns_string(self):
        ts = GitHubHandler._get_timestamp()
        assert isinstance(ts, str)
        assert len(ts) > 5

    def test_add_to_updated_files_is_noop(self):
        # Should not raise
        GitHubHandler._add_to_updated_files("anything.txt")

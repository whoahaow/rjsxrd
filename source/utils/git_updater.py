"""Git-based file updater for GitHub Actions."""

import os
import re
import subprocess
from datetime import datetime, timedelta, timezone

from utils.git_auto_cleaner import squash_auto_commits
from utils.logger import log


def _sanitize_git_message(text: str) -> str:
    """Mask credentials/tokens in git commands and error outputs."""
    return re.sub(
        r"(https?://)([^:\s@]+)(:[^@\s]+)?(@github\.com)",
        r"\1***\4",
        text,
    )


class GitUpdater:
    """Handles git commit and push operations for GitHub Actions."""

    def __init__(self, repo_dir: str | None = None, output_prefix: str = "githubmirror/") -> None:
        if repo_dir is None:
            self.repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        else:
            self.repo_dir = repo_dir

        self.output_prefix = output_prefix.rstrip("/")
        log(f"GitUpdater initialized for: {self.repo_dir}")

    def _run_git(self, *args, check: bool = True, timeout: int = 60) -> subprocess.CompletedProcess:
        """Run git command with timeout."""
        cmd = ["git"] + list(args)
        log(f"Running: {_sanitize_git_message(' '.join(cmd))}")

        try:
            result = subprocess.run(
                cmd, cwd=self.repo_dir, capture_output=True, text=True, check=check, timeout=timeout
            )

            if result.stdout:
                log(f"Git output: {_sanitize_git_message(result.stdout.strip())}")
            if result.stderr:
                log(f"Git stderr: {_sanitize_git_message(result.stderr.strip())}")

            return result
        except subprocess.TimeoutExpired:
            log(f"Git command timed out: {_sanitize_git_message(' '.join(cmd))}")
            raise
        except subprocess.CalledProcessError as e:
            err_msg = _sanitize_git_message(e.stderr or "")
            log(f"Git command failed: {err_msg}")
            raise

    def configure_git(self) -> None:
        """Configure git user and authenticated remote for commits."""
        log("Configuring git user...")
        self._run_git("config", "user.name", "GitHub Actions")
        self._run_git("config", "user.email", "actions@github.com")
        log("Git user configured")
        self.ensure_authenticated_remote()

    def ensure_authenticated_remote(self) -> None:
        """Ensure git origin URL uses authenticated https URL with token when available.

        In headless/daemon environments (e.g. systemd timer on VPS), pushing to
        an HTTPS remote without credentials or with a bare token (e.g. https://<TOKEN>@github.com)
        fails because git prompts for password on stdin and crashes with:
        'fatal: could not read Password ... No such device or address'.

        GitHub Personal Access Tokens (PAT) must be formatted as:
        https://x-access-token:<TOKEN>@github.com/owner/repo.git

        This method:
        1. If GITHUB_TOKEN or MY_TOKEN is set in environment, updates https origin to use
           https://x-access-token:<TOKEN>@github.com/owner/repo.git
        2. If no token in env, but origin currently has a bare token without password
           (https://github_pat_... or https://ghp_...), fixes it to use x-access-token prefix.
        """
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("MY_TOKEN")
        try:
            res = self._run_git("remote", "get-url", "origin", check=False)
            if res.returncode != 0 or not res.stdout.strip():
                return
            origin_url = res.stdout.strip()

            # Ignore SSH urls (e.g. git@github.com:...)
            if not origin_url.startswith("http://") and not origin_url.startswith("https://"):
                return

            # Extract repository owner/name: github.com[:/](owner/repo)
            match = re.search(r"github\.com[:/](.+?)(?:\.git)?$", origin_url)
            if not match:
                return
            repo_path = match.group(1).lstrip("/")

            if token:
                expected_url = f"https://x-access-token:{token}@github.com/{repo_path}.git"
                if origin_url != expected_url:
                    self._run_git("remote", "set-url", "origin", expected_url)
                    log("Configured git origin with token authentication")
                return

            # If no token in env, check if origin itself has a bare token
            bare_token_match = re.search(
                r"^https://((?:github_pat_|ghp_|gho_|ghu_|ghs_)[^:@]+)@github\.com/(.+?)(?:\.git)?$",
                origin_url,
            )
            if bare_token_match:
                extracted_token = bare_token_match.group(1)
                fixed_url = f"https://x-access-token:{extracted_token}@github.com/{repo_path}.git"
                self._run_git("remote", "set-url", "origin", fixed_url)
                log("Fixed bare-token origin URL to use x-access-token prefix")
        except Exception as e:
            log(f"Warning: could not verify or update git remote origin: {e}")

    def pull(self, branch: str | None = None) -> None:
        """Pull latest changes from remote with rebase."""
        if branch is None:
            result = self._run_git("rev-parse", "--abbrev-ref", "HEAD")
            branch = result.stdout.strip()

        log(f"Pulling from origin/{branch}...")
        try:
            # First stash any local changes (can happen with temp files)
            stash_res = self._run_git("stash", "push", "-m", "Auto-stash before pull", check=False)
            stashed = "Saved working directory" in (stash_res.stdout or "")

            # Now pull with rebase
            self._run_git("pull", "--rebase", "origin", branch)
            log("Pull successful")

            # Pop stash if it was created
            if stashed:
                self._run_git("stash", "pop", check=False)
        except subprocess.CalledProcessError as e:
            err_msg = (e.stderr or "").lower()
            if "cannot pull with rebase" in err_msg or "unstaged changes" in err_msg:
                # Force reset to clean state
                log("Warning: Had unstaged changes, resetting to clean state...")
                self._run_git("reset", "--hard", "HEAD", check=False)
                self._run_git("clean", "-fd", check=False)
                # Try pull again
                self._run_git("pull", "--rebase", "origin", branch)
                log("Pull successful after reset")
            else:
                # Rebase conflict or other failure — likely caused by force-push
                # squashing auto commits on remote. Since this machine only ever
                # creates auto commits, it's safe to reset to remote state.
                log(
                    f"Pull/rebase failed ({e.stderr.strip()[-200:]}) — "
                    f"resetting to origin/{branch} (safe — only auto commits lost)"
                )
                self._run_git("fetch", "origin", check=False)
                self._run_git("reset", "--hard", f"origin/{branch}", check=False)
                log(f"Reset to origin/{branch}")

    def stage_files(self, file_pairs: list[tuple[str, str]]) -> None:
        """Stage generated config files and updated source configs."""
        log("Staging generated files...")

        # Stage generated config files in githubmirror/
        self._run_git("add", "-A", self.output_prefix, check=False)

        # Stage source config files that may have been cleaned (dead URLs, dead servers)
        # These changes need to reach the repo so cleanup doesn't repeat every run.
        self._run_git("add", "source/config/URLS.txt", check=False)
        self._run_git("add", "source/config/servers.txt", check=False)

        log("Staging complete")

    def stage_file(self, local_path: str) -> None:
        """Stage a single file for progressive upload during verification.

        Args:
            local_path: Path relative to repo root (e.g. 'githubmirror/bypass/bypass-1.txt').
        """
        self._run_git("add", local_path, check=False)

    def has_changes(self) -> bool:
        """Check if there are staged changes."""
        try:
            result = self._run_git("diff", "--cached", "--quiet", check=False)
            return result.returncode != 0
        except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
            return False

    def commit(self, message: str = "auto: update configs") -> bool:
        """Commit staged changes."""
        if not self.has_changes():
            log("No changes to commit")
            return False

        log(f"Committing: {message}")
        self._run_git("commit", "-m", message)
        return True

    def push(
        self, branch: str | None = None, force: bool = False, force_lease: bool = False
    ) -> None:
        """Push commits to remote."""
        if branch is None:
            result = self._run_git("rev-parse", "--abbrev-ref", "HEAD")
            branch = result.stdout.strip()

        log(f"Pushing to origin/{branch}...")

        if force_lease:
            self._run_git("push", "--force-with-lease", "origin", branch)
        elif force:
            self._run_git("push", "-f", "origin", branch)
        else:
            self._run_git("push", "origin", branch)

        log("Push successful")

    def commit_and_push_single(
        self, local_path: str, message: str, max_retries: int = 3
    ) -> None:
        """Commit and push a single file progressively during pipeline.

        Used by upload_fn in git mode so files appear on GitHub live,
        before the final commit-and-push squashes them.

        Args:
            local_path: Path relative to repo root.
            message: Commit message (e.g. 'auto: update bypass-1.txt').
            max_retries: Number of retries on push rejection.
        """
        self._run_git("add", local_path, check=False)
        self._run_git("commit", "--allow-empty", "-m", message)

        for attempt in range(max_retries):
            try:
                self.push()
                return
            except subprocess.CalledProcessError as e:
                if attempt < max_retries - 1:
                    log(
                        f"Progressive push failed (attempt {attempt + 1}/{max_retries}), pulling latest changes..."
                    )
                    self.pull()
                else:
                    log(f"Progressive push failed after {max_retries} attempts: {e}")
                    raise

    def commit_and_push_files(
        self,
        file_pairs: list[tuple[str, str]],
        commit_message: str = "auto: update configs",
        max_retries: int = 3,
    ) -> bool:
        """Complete workflow with retry logic for push conflicts."""

        # Append timestamp to match github_handler.py format
        ts = datetime.now(timezone(timedelta(hours=3))).strftime("%H:%M | %d.%m.%Y")
        full_message = f"{commit_message}: {ts}"
        log("Starting git commit and push workflow...")

        try:
            self.configure_git()

            # Squash contiguous auto commits at tip before staging new files.
            # This prevents auto-generated commits from accumulating in history.
            # Only commits matching AUTO_PATTERNS are affected — real commits
            # (fix:, feat:, chore:, merge:) are never touched.
            squashed = squash_auto_commits(self.repo_dir)
            if squashed:
                log(
                    f"[auto-clean] squashed {squashed} old auto commits, "
                    f"next commit will replace them"
                )

            # Pull latest from remote before running.
            # In GitHub Actions the checkout action already has fresh code,
            # but on VPS (systemd timer) the repo can drift behind if other
            # machines push. Pull --rebase keeps history linear.
            if not os.environ.get("GITHUB_ACTIONS"):
                try:
                    self.pull()
                except Exception:
                    log("Warning: pull failed, continuing with local state")

            self.stage_files(file_pairs)

            if not self.has_changes():
                log("No changes detected, skipping commit")
                return True

            if not self.commit(full_message):
                log("Commit failed or no changes")
                return False

            # Retry loop for push conflicts
            for attempt in range(max_retries):
                try:
                    # force_lease needed because squash_auto_commits rewrote
                    # local history (removed progressive auto commits that
                    # were already pushed). --force-with-lease is safe when
                    # only one machine pushes.
                    self.push(force_lease=True)
                    log("Git workflow completed successfully")
                    return True
                except subprocess.CalledProcessError as e:
                    if attempt < max_retries - 1:
                        log(
                            f"Push failed (attempt {attempt + 1}/{max_retries}), pulling latest changes..."
                        )
                        # Reconcile with remote before retry — pull --rebase handles
                        # divergent histories that a plain sleep can't fix
                        self.pull()
                    else:
                        log(f"Push failed after {max_retries} attempts: {e.stderr}")
                        return False

            return False

        except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
            log(f"Git workflow failed with error: {e}")
            return False

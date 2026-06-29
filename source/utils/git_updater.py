"""Git-based file updater for GitHub Actions."""

import os
import subprocess
import time
from typing import List, Tuple, Optional
from utils.logger import log
from datetime import datetime, timezone, timedelta
from utils.git_auto_cleaner import squash_auto_commits


class GitUpdater:
    """Handles git commit and push operations for GitHub Actions."""
    
    def __init__(self, repo_dir: str = None, output_prefix: str = "githubmirror/") -> None:
        if repo_dir is None:
            self.repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        else:
            self.repo_dir = repo_dir
        
        self.output_prefix = output_prefix.rstrip("/")
        log(f"GitUpdater initialized for: {self.repo_dir}")
    
    def _run_git(self, *args, check: bool = True, timeout: int = 60) -> subprocess.CompletedProcess:
        """Run git command with timeout."""
        cmd = ["git"] + list(args)
        log(f"Running: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                cwd=self.repo_dir,
                capture_output=True,
                text=True,
                check=check,
                timeout=timeout
            )
            
            if result.stdout:
                log(f"Git output: {result.stdout.strip()}")
            if result.stderr:
                log(f"Git stderr: {result.stderr.strip()}")
            
            return result
        except subprocess.TimeoutExpired:
            log(f"Git command timed out: {' '.join(cmd)}")
            raise
        except subprocess.CalledProcessError as e:
            log(f"Git command failed: {e.stderr}")
            raise
    
    def configure_git(self) -> None:
        """Configure git user for commits."""
        log("Configuring git user...")
        self._run_git("config", "user.name", "GitHub Actions")
        self._run_git("config", "user.email", "actions@github.com")
        log("Git user configured")
    
    def pull(self, branch: Optional[str] = None) -> None:
        """Pull latest changes from remote with rebase."""
        if branch is None:
            result = self._run_git("rev-parse", "--abbrev-ref", "HEAD")
            branch = result.stdout.strip()
        
        log(f"Pulling from origin/{branch}...")
        try:
            # First stash any local changes (can happen with temp files)
            self._run_git("stash", "push", "-m", "Auto-stash before pull", check=False)
            
            # Now pull with rebase
            self._run_git("pull", "--rebase", "origin", branch)
            log("Pull successful")
            
            # Pop stash if it was created
            self._run_git("stash", "pop", check=False)
        except subprocess.CalledProcessError as e:
            if e.stderr and ("cannot pull with rebase" in e.stderr.lower() or "unstaged changes" in e.stderr.lower()):
                # Force reset to clean state
                log("Warning: Had unstaged changes, resetting to clean state...")
                self._run_git("reset", "--hard", "HEAD", check=False)
                self._run_git("clean", "-fd", check=False)
                # Try pull again
                self._run_git("pull", "--rebase", "origin", branch)
                log("Pull successful after reset")
            else:
                raise
    
    def stage_files(self, file_pairs: List[Tuple[str, str]]) -> None:
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
    
    def push(self, branch: Optional[str] = None, force: bool = False, force_lease: bool = False) -> None:
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

    def commit_and_push_single(self, local_path: str, message: str) -> None:
        """Commit and push a single file progressively during pipeline.

        Used by upload_fn in git mode so files appear on GitHub live,
        before the final commit-and-push squashes them.

        Args:
            local_path: Path relative to repo root.
            message: Commit message (e.g. 'auto: update bypass-1.txt').
        """
        self._run_git("add", local_path, check=False)
        self._run_git("commit", "--allow-empty", "-m", message)
        self.push()

    def commit_and_push_files(self, file_pairs: List[Tuple[str, str]], 
                               commit_message: str = "auto: update configs",
                               max_retries: int = 3) -> bool:
        """Complete workflow with retry logic for push conflicts."""

        # Append timestamp to match github_handler.py format
        ts = datetime.now(timezone(timedelta(hours=3))).strftime("%H:%M | %d.%m.%Y")
        full_message = "{0}: {1}".format(commit_message, ts)
        log("Starting git commit and push workflow...")
        
        try:
            self.configure_git()

            # Squash contiguous auto commits at tip before staging new files.
            # This prevents auto-generated commits from accumulating in history.
            # Only commits matching AUTO_PATTERNS are affected — real commits
            # (fix:, feat:, chore:, merge:) are never touched.
            squashed = squash_auto_commits(self.repo_dir)
            if squashed:
                log(f"[auto-clean] squashed {squashed} old auto commits, "
                    f"next commit will replace them")

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
            
            # Retry loop for push conflicts
            for attempt in range(max_retries):
                if self.commit(full_message):
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
                            log(f"Push failed (attempt {attempt + 1}/{max_retries}), pulling latest changes...")
                            # Reconcile with remote before retry — pull --rebase handles
                            # divergent histories that a plain sleep can't fix
                            self.pull()
                        else:
                            log(f"Push failed after {max_retries} attempts: {e.stderr}")
                            return False
                else:
                    log("Commit failed or no changes")
                    return False
            
            return False
            
        except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
            log(f"Git workflow failed with error: {e}")
            return False

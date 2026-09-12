"""Auto-cleanup of auto-generated commits from git history.

Call squash_auto_commits() before staging files and creating a new
auto-commit. It squashes contiguous auto commits at the tip of HEAD
into the index via git reset --soft, so the next commit replaces
N auto commits with a single one.

Only commits matching AUTO_PATTERNS are affected. Real commits
(fix:, feat:, chore:, merge:, etc.) are never touched.
"""

import re
import subprocess
from re import Pattern

# Pattern matching auto-generated commits to remove.
# Only 'auto: update' prefix — old formats (Update bypass-, update configs, etc.)
# are intentionally excluded. They're historical and irrelevant for ongoing cleanup.
AUTO_PATTERNS: list[Pattern] = [
    re.compile(r'^auto: update '),
]

# Safety limit — don't walk more than this many commits
_MAX_WALK = 500


def is_auto_message(msg: str) -> bool:
    """Check if a commit message matches any auto-generated pattern.

    Args:
        msg: Full commit message (first line / subject).

    Returns:
        True if the message matches an auto pattern, False otherwise.
    """
    return any(p.match(msg) for p in AUTO_PATTERNS)


def _run_git(repo_dir: str, *args: str, check: bool = False) -> subprocess.CompletedProcess:
    """Run a git command and return the result.

    Args:
        repo_dir: Repository working directory.
        *args: Git command arguments.
        check: If True, raises on non-zero exit.

    Returns:
        subprocess.CompletedProcess with stdout, stderr, returncode.
    """
    cmd = ['git'] + list(args)
    try:
        return subprocess.run(
            cmd, cwd=repo_dir, capture_output=True, text=True,
            timeout=30, check=check,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, returncode=124, stdout='', stderr='timeout')
    except subprocess.CalledProcessError as e:
        return subprocess.CompletedProcess(cmd, returncode=e.returncode, stdout=e.stdout or '', stderr=e.stderr or '')


def _walk_auto_commits(repo_dir: str) -> tuple:
    """Walk back from HEAD counting contiguous auto commits.

    Stops at the first non-auto commit, at root (no parent), or after
    _MAX_WALK iterations.

    Returns:
        Tuple of (count: int, target_revision: str).
        count = number of contiguous auto commits starting from HEAD.
        target_revision = e.g. 'HEAD~3' (the first non-auto commit).
        If count is 0, target_revision is 'HEAD'.
    """
    count = 0
    target = 'HEAD'

    for _ in range(_MAX_WALK):
        result = _run_git(repo_dir, 'log', '-1', '--format=%s', target)
        if result.returncode != 0:
            break
        msg = result.stdout.strip()
        if not msg or not is_auto_message(msg):
            break
        count += 1
        target = f'{target}~1'

    return count, target


def squash_auto_commits(repo_dir: str = '.') -> int:
    """Squash contiguous auto commits at the tip of HEAD into the index.

    Uses ``git reset --soft <last-non-auto-commit>`` to preserve the
    working tree and index exactly as they are, while moving HEAD back
    to the last real (non-auto) commit. The index retains all changes
    from the squashed commits, so the caller can stage additional files
    and commit normally — resulting in a single commit that replaces
    N auto commits.

    Only squashes when there are 2+ contiguous auto commits at the tip.
    A single auto commit at the tip is left alone (harmless).

    Args:
        repo_dir: Path to the git repository (default: '.').

    Returns:
        Number of commits squashed (0 if nothing was done).
    """
    count, target = _walk_auto_commits(repo_dir)

    if count < 2:
        return 0

    # Resolve the target revision to a stable SHA
    result = _run_git(repo_dir, 'rev-parse', '--verify', target)
    if result.returncode != 0 or not result.stdout.strip():
        return 0

    target_sha = result.stdout.strip()

    # Soft reset: move HEAD back, keep index and working tree
    result = _run_git(repo_dir, 'reset', '--soft', target_sha, check=True)

    return count

> **Language:** [Русский](history-notes.md) · [English](history-notes.en.md)

# Repository history: the line a restart replaced

On 27 June 2026 the current `main` history started over — the `reinit` commit is
its root. Before that the repository carried a different history: 541 commits
from 9 December 2025 to 9 January 2026. The two histories share no commit at all:
`git merge-base main refs/original/refs/heads/main` returns nothing, so today's
`main` neither descends from that line nor merges with it.

That history was kept alive by the ref `refs/original/refs/heads/main` — the
name `git filter-branch` leaves behind when it rewrites a branch. The ref was
not a branch, a tag or a remote-tracking ref: nothing referenced it, and its
only effect was to keep the line's objects away from the garbage collector.
Below is what it held, why it was removed, and how to find it again if it is
ever needed.

This record was written before the ref was removed.

## Measurement

Everything was measured on 18 September 2026 on branch `main` at commit
`7323be3b`.

| | |
| --- | --- |
| Ref | `refs/original/refs/heads/main` |
| Tip | `b8ba07e076791017e46b93fb4f5863a3f98d9c99` — `update urls`, 2026-01-09 19:34 +03:00 |
| First commit | `c8b144d84751b85790cf6609b16287d78be5bdc7` — `init`, 2025-12-09 18:08 +03:00 |
| Commits in the line | 541 |
| Unique to the line | 541 (shared with `main` — 0) |
| Objects in the line | 4938, of which 4767 are unreachable from `main` |
| Packed size of those 4767 objects | 231.96 MiB |
| Tip contents | 232 files: 167 `.png`, 41 `.txt`, 14 `.py`, 7 `.md`, 1 workflow, 1 LICENSE, 1 `.gitignore` |

How to reproduce:

```bash
git rev-list --count refs/original/refs/heads/main                      # 541
git rev-list --count ^main refs/original/refs/heads/main                # 541 unique
git merge-base main refs/original/refs/heads/main                       # nothing (exit code 1)
git count-objects -vH                                                   # .git sizes
```

## What the line held

- 459 of the 541 commits are the scheduled URL-list updates
  (`Обновление N.txt: <time> | <date>`). It is the same update machinery as
  today; only the commit labels differ.
- 14 files under `source/` — the previous generation of the code, at the same
  paths as in the current tree: `config/settings.py`, `main.py`,
  `processors/config_processor.py`, `utils/file_utils.py`,
  `utils/github_handler.py`, `utils/logger.py`,
  `fetchers/{fetcher,daily_repo_fetcher,yaml_converter}.py` and the package
  `__init__.py` files. No blob in the line equals the blob `main` has at the
  same path: these are earlier versions, not copies.
- 7 documentation files in the old flat layout — `docs/overview.md`,
  `docs/technical.md`, `docs/installation.md`, `docs/index.md`,
  `docs/development.md`, `docs/faq.md`. None of them exists in the current tree:
  the documentation moved into `docs/user/`, `docs/operation/` and
  `docs/development/`, and was rewritten.
- The `githubmirror/` layout of that era (`default/`, `split-by-protocols/`,
  `bypass-unsecure/`) — a different layout is published now.
- 34 paths in total that the current tree does not have (`git ls-tree -r
  --name-only` over the line against `git ls-files` on `main`).

## Checks run before removing it

Before touching the ref, everything that could have depended on it was checked:

- **Branches.** `git for-each-ref` lists three refs: `refs/heads/main`,
  `refs/original/refs/heads/main` and `refs/remotes/origin/main`. No branch
  leads into the line.
- **Worktrees.** `git worktree list` — one worktree, on branch `main`.
- **Tags.** `git tag -l` is empty.
- **Remote refs.** `git ls-remote origin` returns `HEAD`, `refs/heads/main` and
  four `refs/pull/*` bookkeeping refs. No remote ref points at the line.
- **Reflogs.** Only `HEAD`, `refs/heads/main` and `refs/remotes/origin/main`
  have logs, and no entry references a commit of the line (`grep <sha>
  .git/logs/...` finds neither the tip nor any of its ancestors).
- **Merging.** `git merge-base` returns no common commit.

## How to recover the contents

The public `origin` still serves the line's objects: the public GitHub API
endpoint `GET /repos/{owner}/{repo}/commits/{sha}` answers `200` for its commits
№1 through №539 — sampled on 18 September 2026 at positions 1, 100, 200, 300,
400, 500, 505, 510, 515, 520, 525, 530, 535, 536, 537, 538 and 539. The last two
commits of the line (№540 and the tip, №541) are no longer served: their SHAs
return `422` — they carry edits that were never pushed before the restart. So
the remote holds the line's history minus its last two commits, and it reads it
back by SHA for as long as GitHub keeps those objects.

Any commit of the line can be checked the same way:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  https://api.github.com/repos/<owner>/<repo>/commits/<sha>      # 200 — the commit is still there
```

## See also

- [Modules](modules.en.md) — `git_updater.py` and `git_auto_cleaner.py`: how the
  repository is updated, and why its history reads as a run of `auto: update ...`.
- [Testing](testing.en.md) — the run commands that were verified after the removal.
- [Architecture](architecture.en.md) — the current pipeline the previous code
  generation from this line belongs to.

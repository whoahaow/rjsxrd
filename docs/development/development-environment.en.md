> **Language:** [Русский](development-environment.md) · [English](development-environment.en.md)

# Development environment

How to set up the repository for code work and run the checks. There is exactly one installer — `uv`: bare `pip` commands are not used in the docs, in CI, or in the VPS cron.

## Requirements

- [uv](https://docs.astral.sh/uv/) — uv downloads and versions the Python interpreter itself, no system Python needed
- Git

## Creating the environment

```bash
uv venv --python 3.12 .venv
```

## Installing the dependencies

There are two files: `source/requirements.txt` — the runtime dependencies (installed by the VPS and GitHub Actions), `source/requirements-dev.txt` — the linters and the test toolchain; it pulls in the runtime file on its first line.

```bash
uv pip install --python .venv/Scripts/python.exe -r source/requirements-dev.txt
```

The interpreter path depends on the OS: `.venv/Scripts/python.exe` — Windows, `.venv/bin/python` — Linux and macOS.

## Checks before committing

```bash
# tests — from the source/ directory
cd source && ../.venv/Scripts/python.exe -m pytest -q

# linter — from the repository root
./.venv/Scripts/python.exe -m ruff check .
```

A full run is 882 tests, about 70–80 seconds on the development machine (Windows, Python 3.12). The shape of the suite and the verification scenarios are described in [Testing](testing.en.md).

## Pinned versions

`source/requirements.lock` is the hash-pinned lock of the runtime dependencies. Regenerate it after editing `source/requirements.txt`:

```bash
uv pip compile source/requirements.txt --generate-hashes --python-version 3.12 --python-platform windows -o source/requirements.lock
```

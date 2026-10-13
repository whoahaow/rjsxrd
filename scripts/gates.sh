#!/usr/bin/env bash
# scripts/gates.sh — Quality gate runner for rjsxrd
# Mirrors all CI steps defined in .github/workflows/ci.yml
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Color support
if [ -t 1 ]; then
    COLOR_BLUE="\033[1;34m"
    COLOR_GREEN="\033[1;32m"
    COLOR_RED="\033[1;31m"
    COLOR_YELLOW="\033[1;33m"
    COLOR_RESET="\033[0m"
else
    COLOR_BLUE=""
    COLOR_GREEN=""
    COLOR_RED=""
    COLOR_YELLOW=""
    COLOR_RESET=""
fi

# Detect Python environment
run_py() {
    "$PYTHON_BIN" "$@"
}

if [ -n "${VIRTUAL_ENV:-}" ] && [ -x "$VIRTUAL_ENV/bin/python" ]; then
    PYTHON_BIN="$VIRTUAL_ENV/bin/python"
elif [ -n "${VIRTUAL_ENV:-}" ] && [ -x "$VIRTUAL_ENV/Scripts/python.exe" ]; then
    PYTHON_BIN="$VIRTUAL_ENV/Scripts/python.exe"
elif [ -x "$REPO_ROOT/.venv/bin/python" ]; then
    PYTHON_BIN="$REPO_ROOT/.venv/bin/python"
elif [ -x "$REPO_ROOT/.venv/Scripts/python.exe" ]; then
    PYTHON_BIN="$REPO_ROOT/.venv/Scripts/python.exe"
elif command -v uv >/dev/null 2>&1; then
    run_py() {
        uv run python "$@"
    }
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    echo -e "${COLOR_RED}Error: Python interpreter not found in .venv, virtualenv, or PATH.${COLOR_RESET}" >&2
    exit 1
fi

FIX_MODE=false
FAST_MODE=false

usage() {
    echo "Usage: ./scripts/gates.sh [OPTIONS]"
    echo ""
    echo "Run CI quality gates locally before committing or pushing."
    echo ""
    echo "Options:"
    echo "  --fix       Auto-format with ruff and apply safe lint fixes before checking"
    echo "  --fast      Quick check: format, lint, types, and unit tests (skips slow coverage and pip-audit)"
    echo "  -h, --help  Show this help message"
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --fix)
            FIX_MODE=true
            shift
            ;;
        --fast)
            FAST_MODE=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${COLOR_RED}Unknown option: $1${COLOR_RESET}" >&2
            usage
            ;;
    esac
done

if [ "$FIX_MODE" = true ]; then
    echo -e "${COLOR_YELLOW}[FIX] Applying automatic formatting and lint fixes...${COLOR_RESET}"
    run_py -m ruff format .
    run_py -m ruff check --fix .
    echo ""
fi

run_gate() {
    local step="$1"
    local desc="$2"
    shift 2
    echo -e "${COLOR_BLUE}[GATE $step] $desc...${COLOR_RESET}"
    if "$@"; then
        echo -e "${COLOR_GREEN}[GATE $step] $desc: PASSED${COLOR_RESET}\n"
    else
        echo -e "${COLOR_RED}[GATE $step] $desc: FAILED${COLOR_RESET}" >&2
        exit 1
    fi
}

gate_format() {
    run_py -m ruff format --check .
}

gate_lint() {
    run_py -m ruff check .
}

gate_types() {
    (cd "$REPO_ROOT/source" && run_py -m mypy .)
}

gate_tests() {
    if [ "$FAST_MODE" = true ]; then
        (cd "$REPO_ROOT/source" && run_py -m pytest -m unit -q)
    else
        (cd "$REPO_ROOT/source" && run_py -m pytest --cov=. --cov-report=term-missing -q --cov-config=../pyproject.toml)
    fi
}

gate_audit() {
    if [ "$FAST_MODE" = true ]; then
        echo "Skipping dependency audit in --fast mode."
        return 0
    fi
    run_py -m pip_audit -r "$REPO_ROOT/source/requirements-dev.txt"
}

START_TIME=$(date +%s)

run_gate "1/5" "Format check (ruff format)" gate_format
run_gate "2/5" "Lint check (ruff check)" gate_lint
run_gate "3/5" "Type check (mypy)" gate_types
run_gate "4/5" "Tests & coverage (pytest)" gate_tests
run_gate "5/5" "Dependency audit (pip-audit)" gate_audit

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo -e "${COLOR_GREEN}========================================${COLOR_RESET}"
echo -e "${COLOR_GREEN} All quality gates passed (${ELAPSED}s)! ${COLOR_RESET}"
echo -e "${COLOR_GREEN}========================================${COLOR_RESET}"

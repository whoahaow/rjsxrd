"""Import smoke tests for the scripts/ entry points.

The scripts are user-facing commands documented in docs/development/testing.md,
but nothing in the suite imported them: a `from processors.config_processor
import _verify_config_file` inside `run_xray` referenced a symbol that does not
exist anywhere in the repo, so `--mode xray` could not run at all while the
suite stayed green.

These tests walk each script's imports and resolve every symbol they name,
without executing the scripts themselves.
"""

import ast
import importlib
import os

import pytest

pytestmark = pytest.mark.unit

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")


def _script_paths():
    return sorted(
        os.path.join(SCRIPTS_DIR, name) for name in os.listdir(SCRIPTS_DIR) if name.endswith(".py")
    )


def _function_defs(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def _import_from_nodes(scope):
    """Yield every `from X import Y` in a scope (module body or function)."""
    for node in ast.walk(scope):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            for alias in node.names:
                yield node.module, alias.name, node.lineno


def _unresolvable(imports):
    """Return the (module, symbol, line) triples whose symbol doesn't exist."""
    broken = []
    for module_name, symbol, lineno in imports:
        try:
            module = importlib.import_module(module_name)
        except ImportError as exc:
            broken.append((module_name, symbol, lineno, f"module import failed: {exc}"))
            continue
        if hasattr(module, symbol):
            continue
        try:
            importlib.import_module(f"{module_name}.{symbol}")
        except ImportError as exc:
            broken.append((module_name, symbol, lineno, f"symbol missing: {exc}"))
    return broken


def _assert_imports_resolve(path, imports):
    broken = _unresolvable(imports)
    assert broken == [], (
        f"{os.path.basename(path)} imports symbols that do not exist: "
        + ", ".join(
            f"{module}.{symbol} (line {lineno}: {reason})"
            for module, symbol, lineno, reason in broken
        )
    )


@pytest.mark.parametrize("path", _script_paths(), ids=os.path.basename)
def test_script_imports_resolve(path):
    """Every symbol imported by a script must exist."""
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read())

    _assert_imports_resolve(path, _import_from_nodes(tree))


@pytest.mark.parametrize("path", _script_paths(), ids=os.path.basename)
def test_scripts_import_as_modules(path):
    """Importing a script must not execute its benchmark or parse its args."""
    module_name = f"scripts.{os.path.splitext(os.path.basename(path))[0]}"

    importlib.import_module(module_name)


def test_benchmark_configs_run_xray_imports_resolve():
    """`run_xray`'s function-scoped imports must resolve without running it.

    The benchmark's xray mode documented in docs/development/testing.md reaches
    its verifier through a function-scoped import, so only resolving that scope
    catches a symbol that was never defined.
    """
    path = os.path.join(SCRIPTS_DIR, "benchmark_configs.py")
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read())

    run_xray = next((node for node in _function_defs(tree) if node.name == "run_xray"), None)
    assert run_xray is not None, "run_xray is missing from benchmark_configs.py"

    function_imports = list(_import_from_nodes(run_xray))
    assert function_imports, "run_xray no longer imports anything — update this test"

    _assert_imports_resolve(path, function_imports)


def test_benchmark_configs_load_configs_parsing(tmp_path):
    """The shared loader still drives both modes, skipping comments and blanks."""
    module = importlib.import_module("scripts.benchmark_configs")

    sample = tmp_path / "configs.txt"
    sample.write_text(
        "# comment\nvless://a@host.com:443\n\nvless://b@host.com:443\n", encoding="utf-8"
    )

    assert module.load_configs(str(sample)) == [
        "vless://a@host.com:443",
        "vless://b@host.com:443",
    ]
    assert module.load_configs(str(sample), count=1) == ["vless://a@host.com:443"]

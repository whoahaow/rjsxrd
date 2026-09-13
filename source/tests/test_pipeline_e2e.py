"""Offline end-to-end pipeline test: the real orchestrator, every seam stubbed.

``main.py`` sat at 0% coverage and ``ConfigPipeline`` at 37%; the P0 crashes an
earlier card fixed (an unbound local in the sync batch path, upload handlers
that evaporated under ``-O``) both lived in that untested band. This module
drives the real pipeline instead of a mocked-out copy: stage dispatch, dedup,
tagging, SNI/CIDR and security filtering, the file writers and the
``file_pairs`` assembly all run as they do in production.

Every outbound seam is replaced:

* the fetchers, the daily/sstap/upstream aggregators and the YAML converter
  return canned data — no HTTP client is ever built;
* the xray/TCP verifier is a stub returning deterministic working tuples, so no
  core binary is ever downloaded or spawned;
* ``URLStats`` is redirected at a temporary path, so a test run cannot rewrite
  the repository's ``data/url_stats.json`` or clean ``source/config/*.txt``;
* the Telegram proxy verification is replaced, but the file it reports is
  written for real so the upload pairs stay verifiable.

Two autouse guards make "offline" a property of the module rather than a
promise in a docstring: a socket connect or a process spawn fails the test.
They are deliberately scoped to this module — ``test_fetcher.py`` and
``test_ip_checker.py`` attempt real network on purpose and self-skip when it is
unavailable, so a global ``conftest.py`` guard would break them.

Coverage boundary: with a stub set this small the verifier never accumulates
the ``MAX_CONFIGS_PER_FILE`` (300) working configs that seal ``bypass-{N}.txt``
split files, so the progressive-seal path stays unexercised here (it has its
own unit tests in ``test_config_processor.py``). Everything else on the
documented output tree — ``default/``, ``bypass/raw/``, ``bypass/``,
``bypass-unsecure/``, ``tg-proxy/`` — is written and asserted.
"""

from __future__ import annotations

import inspect
import os
import socket
import subprocess
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

import config.settings as settings
import main as main_module
from fetchers.fetcher import FetchResult
from processors import config_processor
from processors.telegram_proxy_processor import ProxyEntry, TelegramProxyProcessor
from utils import bypass_builder, file_writer
from utils.file_utils import load_cidr_whitelist
from utils.url_stats import URLStats

# --- Canned sources -----------------------------------------------------------
# Clearly-fake hosts (RFC 2606): they never leave the process, and a fixture
# that used real hostnames would be indistinguishable from a real server list.
URLS_SECTION = ("https://example.invalid/subscription-main",)
URLS_EXTRA_BYPASS = ("https://example.invalid/subscription-extra",)
URLS_YAML = ("https://example.invalid/subscription.yaml",)

FETCHED_CONFIGS = (
    "trojan://fake-secret@a.example.invalid:443?security=tls&sni=a.example.invalid#fetched-a",
    "vless://11111111-1111-1111-1111-111111111111@b.example.invalid:2053"
    "?security=tls&sni=b.example.invalid&type=ws&path=%2Fws#fetched-b",
)
# The MTProto line is not a VPN config, so it never reaches a config file. It is
# there so the real Telegram scraper has something to extract.
FETCH_BODY = "\n".join(FETCHED_CONFIGS) + "\nhttps://t.me/proxy?server=10.0.0.9&port=443\n"

EXTRA_BYPASS_CONFIGS = (
    "trojan://extra-secret@x.example.invalid:8443?security=tls&sni=x.example.invalid#extra-a",
    "vless://22222222-2222-2222-2222-222222222222@y.example.invalid:443"
    "?security=tls&sni=y.example.invalid#extra-b",
)
DAILY_CONFIGS = (
    "trojan://daily-secret@d.example.invalid:9443?security=tls&sni=d.example.invalid#daily",
)
SSTAP_CONFIGS = (
    "vless://33333333-3333-3333-3333-333333333333@s.example.invalid:2087"
    "?security=tls&sni=s.example.invalid#sstap",
)
UPSTREAM_CONFIGS = (
    "trojan://upstream-secret@u.example.invalid:2083?security=tls&sni=u.example.invalid#upstream",
)
YAML_CONFIGS = (
    "trojan://yaml-secret@y2.example.invalid:443?security=tls&sni=y2.example.invalid#yaml",
)
MANUAL_CONFIGS = (
    "trojan://manual-secret@m.example.invalid:443?security=tls&sni=m.example.invalid#manual",
)

# All output folders on except the protocol split — see the class docstring of
# TestPipelineOutputTree for why that one flag cannot be exercised yet.
OUTPUT_FLAGS: dict[str, bool] = {
    "ENABLE_DEFAULT_FILES": True,
    "ENABLE_BYPASS_UNSECURE": True,
    "ENABLE_PROTOCOL_SPLIT": False,
    "ENABLE_TG_PROXY": True,
    "PUBLISH_RAW_FILES": True,
}

# What a full run publishes, as remote paths. Derived files (the numbered
# default/ shards) are matched by prefix instead of being pinned by name.
EXPECTED_REMOTE_PATHS = frozenset(
    {
        "githubmirror/bypass/bypass-all.txt",
        "githubmirror/bypass/raw/bypass-all-raw.txt",
        "githubmirror/bypass-unsecure/bypass-unsecure-all.txt",
        "githubmirror/bypass-unsecure/raw/bypass-unsecure-all-raw.txt",
        "githubmirror/default/all.txt",
        "githubmirror/default/all-secure.txt",
        "githubmirror/tg-proxy/all.txt",
        "source/config/URLS.txt",
        "source/config/servers.txt",
    }
)

_TG_PROXY_CALLS: list[tuple[list[Any], list[Any]]] = []


class _StubTelegramProxyProcessor(TelegramProxyProcessor):
    """TelegramProxyProcessor with the socket-opening verification replaced.

    ``load_manual_proxies()`` stays real (it only reads ``tg_proxies.txt``).
    Only the verification is replaced, and the file it reports is written for
    real — a pair whose local side does not exist must stay detectable.
    """

    def create_proxy_files(
        self,
        mtproto_proxies: Sequence[ProxyEntry],
        socks5_proxies: Sequence[ProxyEntry],
        verify_mtproto: bool = True,
        verify_socks5: bool = True,
        max_workers: int = 200,
    ) -> list[str]:
        _TG_PROXY_CALLS.append((list(mtproto_proxies), list(socks5_proxies)))
        path = Path(self.output_dir, "tg-proxy", "all.txt")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "#profile-title: tg-proxy t.me/rjsxrd\n\ntg://proxy?server=10.0.0.9\n", encoding="utf-8"
        )
        return [str(path)]


# --- Guards -------------------------------------------------------------------


def _refuse_network(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError("the offline pipeline test attempted a network call")


def _refuse_subprocess(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError("the offline pipeline test attempted to spawn a process")


@pytest.fixture(autouse=True)
def offline_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Turn any Python-level connect into a failure (module-scoped on purpose)."""
    monkeypatch.setattr(socket.socket, "connect", _refuse_network)
    monkeypatch.setattr(socket, "create_connection", _refuse_network)


@pytest.fixture(autouse=True)
def no_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    """Turn any process spawn into a failure — the core must stay unspawned."""
    monkeypatch.setattr(subprocess, "Popen", _refuse_subprocess)
    monkeypatch.setattr(subprocess, "run", _refuse_subprocess)


# --- Seams --------------------------------------------------------------------


def _fake_fetch_data(
    url: str,
    timeout: int = 5,
    max_attempts: int = 3,
    session: Any = None,
    proxy_url: str | None = None,
    token: str | None = None,
) -> FetchResult:
    """Canned HTTP response, one body per subscription URL.

    The bodies differ per URL because the sections are separate sources: the
    pipeline dedups across all of them, so a single body would leave the
    extra-bypass section empty and hide that path.
    """
    if url in URLS_EXTRA_BYPASS:
        body = "\n".join(EXTRA_BYPASS_CONFIGS) + "\n"
    elif url in URLS_YAML:
        body = "not-yaml"
    else:
        body = FETCH_BODY
    return FetchResult(text=body, status_code=200, success=True)


def _fake_verify_config_file(
    input_path: str,
    configs: list[str] | None = None,
    verbose: bool = False,
    tcp_ping: bool = False,
    config_to_sources: dict | None = None,
    stats: Any = None,
    progress_callback: Any = None,
) -> list[str]:
    """Stand-in for the xray/TCP verifier — deterministic ``(url, True, ms)``.

    The real ``verify_config_file`` returns the sorted list of working URLs;
    the ``(url, is_working, latency_ms)`` tuples are its internal shape, and the
    projection below mirrors it. No progress callback fires: with a stub set
    this small the real verifier never crosses its 300-working-configs
    threshold, so the return-value path is the live one.
    """
    if configs is None:
        configs = read_config_lines(input_path)
    results = [(cfg, True, float(index) * 10.0) for index, cfg in enumerate(configs)]
    if stats is not None and config_to_sources:
        for cfg, is_working, _ in results:
            for source in config_to_sources.get(cfg, []):
                stats.record_config_verification(source, cfg, is_working)
    return [cfg for cfg, is_working, _ in results if is_working]


def read_config_lines(path: str | Path) -> list[str]:
    """Read a written configs file back, skipping the subscription header."""
    return [
        line.strip()
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _fake_convert_yaml(content: str) -> list[str]:
    """The YAML converter seam: fixed configs instead of parsing Clash."""
    return list(YAML_CONFIGS)


@pytest.fixture
def pipeline_seams(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    """Replace every network and binary seam. Returns the recorded calls."""
    calls: dict[str, Any] = {}
    _TG_PROXY_CALLS.clear()

    monkeypatch.setattr(config_processor, "URLS", list(URLS_SECTION))
    monkeypatch.setattr(config_processor, "URLS_EXTRA_BYPASS", list(URLS_EXTRA_BYPASS))
    monkeypatch.setattr(config_processor, "URLS_YAML", list(URLS_YAML))
    monkeypatch.setattr(config_processor, "TELEGRAM_PROXY_URLS", [])
    monkeypatch.setattr(config_processor, "MANUAL_SERVERS", list(MANUAL_CONFIGS))
    monkeypatch.setattr(config_processor, "GITHUB_TOKEN", "")

    monkeypatch.setattr(config_processor, "fetch_data", _fake_fetch_data)

    def _daily_repo(patterns: Any, seen: Any, seen_lock: Any) -> list[str]:
        calls["daily_repo"] = {"patterns": patterns, "seen": seen, "seen_lock": seen_lock}
        return list(DAILY_CONFIGS)

    monkeypatch.setattr(config_processor, "fetch_configs_from_daily_repo", _daily_repo)
    monkeypatch.setattr(config_processor, "scrape_sstap_configs", lambda: list(SSTAP_CONFIGS))
    monkeypatch.setattr(
        config_processor,
        "fetch_upstream_dynamic_configs",
        lambda seen=None, seen_lock=None: list(UPSTREAM_CONFIGS),
    )
    monkeypatch.setattr("fetchers.yaml_converter.convert_yaml_to_vpn_configs", _fake_convert_yaml)

    # The real stats class, redirected at a temporary file: a test run must not
    # be able to touch the repository's stats, URLS.txt or servers.txt.
    def _stats() -> URLStats:
        return URLStats(path=str(tmp_path / "url_stats.json"))

    monkeypatch.setattr(config_processor, "URLStats", _stats)
    monkeypatch.setattr(config_processor, "TelegramProxyProcessor", _StubTelegramProxyProcessor)
    monkeypatch.setattr("utils.bypass_builder.verify_config_file", _fake_verify_config_file)
    calls["tg_proxy"] = _TG_PROXY_CALLS
    return calls


@pytest.fixture
def main_seams(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    """Replace the entry point's side effects that reach outside the process.

    ``ensure_xray_installed`` hands back a stub path instead of downloading a
    core. The health check, the resource monitor and the Telegram notifier are
    imported inside ``main()`` for the first two, so they are patched where they
    are defined.
    """
    calls: dict[str, Any] = {"notify_success": MagicMock(), "ensure_xray": MagicMock()}
    calls["ensure_xray"].return_value = str(tmp_path / "xray-stub")

    monkeypatch.setattr(main_module, "ensure_xray_installed", calls["ensure_xray"])
    monkeypatch.setattr("utils.health_check.health_check", lambda **kwargs: {"internet": True})
    monkeypatch.setattr("utils.health_check.print_health_report", lambda results: None)
    monkeypatch.setattr(main_module, "start_monitoring", lambda **kwargs: None)
    monkeypatch.setattr(main_module, "stop_monitoring", lambda: None)
    monkeypatch.setattr(main_module, "print_resource_report", lambda title: None)
    monkeypatch.setattr(main_module, "notify_start", lambda: None)
    monkeypatch.setattr(main_module, "notify_error", lambda message: None)
    monkeypatch.setattr(main_module, "notify_success", calls["notify_success"])
    monkeypatch.setattr(main_module, "print_logs", lambda: None)
    return calls


def run_pipeline(
    tmp_path: Path,
    *,
    output_dir: str | None = None,
    flag_overrides: dict[str, bool] | None = None,
) -> tuple[Path, list[tuple[str, str]]]:
    """Run the pipeline offline against a temporary output directory."""
    out = Path(output_dir) if output_dir else tmp_path / "out"
    file_pairs = config_processor.process_all_configs(
        output_dir=str(out),
        skip_xray=True,
        tcp_ping=True,
        verbose=True,
        flag_overrides=dict(flag_overrides or OUTPUT_FLAGS),
    )
    return out, file_pairs


@pytest.fixture
def foreign_cwd(tmp_path: Path) -> Iterator[Path]:
    """Run a test inside a directory that has nothing to do with the checkout.

    Restored in teardown rather than at the end of the test body: a leaked
    ``chdir`` poisons every test that follows it, nondeterministically.
    """
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    original = os.getcwd()
    os.chdir(foreign)
    try:
        yield foreign
    finally:
        os.chdir(original)


def _normalized(path: str | Path) -> str:
    """Comparison key for paths: case- and separator-insensitive on Windows."""
    return os.path.normcase(os.path.abspath(str(path)))


def _output_dir_defaults() -> dict[str, Any]:
    """Every production callable that carries a default output directory.

    Nine sites spell the literal out in the audit's list; a second pass found
    two more (the Telegram proxy processor and the numbered default writer).
    Each is inspected rather than trusted to a grep, because a default binds at
    import time and only the callable knows what it holds.
    """
    return {
        "main.main": main_module.main,
        "process_all_configs": config_processor.process_all_configs,
        "ConfigPipeline.__init__": config_processor.ConfigPipeline.__init__,
        "download_all_configs": config_processor.download_all_configs,
        "_write_subscription_file": config_processor._write_subscription_file,
        "create_all_configs_file": config_processor.create_all_configs_file,
        "create_secure_configs_file": config_processor.create_secure_configs_file,
        "create_protocol_split_files": config_processor.create_protocol_split_files,
        "create_working_config_files": bypass_builder.create_working_config_files,
        "create_numbered_default_files": file_writer.create_numbered_default_files,
        "TelegramProxyProcessor.__init__": TelegramProxyProcessor.__init__,
    }


# --- Tests --------------------------------------------------------------------


class TestPipelineOutputTree:
    """The stages a full run completes, asserted on the files it leaves."""

    def test_pipeline_writes_the_documented_output_tree(
        self, pipeline_seams: dict[str, Any], tmp_path: Path
    ) -> None:
        """Every documented output folder is written from the stubbed sources.

        ``ENABLE_PROTOCOL_SPLIT`` stays off. ``create_protocol_split_files``
        accumulates its upload list with ``all_file_pairs.extend(file_path)``,
        where the worker returns a path *string* — so switching the flag on
        contributes one entry per character to ``file_pairs`` instead of
        ``(local, remote)`` pairs, and the pair assertions below (rightly) fail.
        That defect belongs to the split-file writer, not to this card; it is
        reported instead of worked around by weakening the assertion.
        """
        out, file_pairs = run_pipeline(tmp_path)

        assert (out / "bypass" / "raw" / "bypass-all-raw.txt").is_file()
        assert (out / "bypass" / "bypass-all.txt").is_file()
        assert (out / "bypass-unsecure" / "raw" / "bypass-unsecure-all-raw.txt").is_file()
        assert (out / "bypass-unsecure" / "bypass-unsecure-all.txt").is_file()
        assert (out / "default" / "1.txt").is_file()
        assert (out / "default" / "all.txt").is_file()
        assert (out / "default" / "all-secure.txt").is_file()
        assert (out / "tg-proxy" / "all.txt").is_file()
        assert len(file_pairs) > 0

    def test_every_source_reaches_the_file_it_should(
        self, pipeline_seams: dict[str, Any], tmp_path: Path
    ) -> None:
        """Fetched, extra-bypass, daily, sstap, upstream, YAML and manual sources.

        The main-fetch configs use fake hosts, so the SNI/CIDR whitelist drops
        them from the bypass set while the extra-bypass and manual ones are
        spliced in after that filter. The raw file therefore proves the extra,
        manual and aggregator paths at once; ``default/`` proves the main fetch
        and every aggregator path.
        """
        out, _ = run_pipeline(tmp_path)
        raw = (out / "bypass" / "raw" / "bypass-all-raw.txt").read_text(encoding="utf-8")

        for config in (*EXTRA_BYPASS_CONFIGS, *MANUAL_CONFIGS):
            assert config in raw, f"{config} missing from bypass-all-raw.txt"
        assert FETCHED_CONFIGS[0] not in raw, "the SNI/CIDR whitelist did not filter"

        default_configs = (out / "default" / "1.txt").read_text(encoding="utf-8")
        for config in FETCHED_CONFIGS:
            assert config in default_configs

        everything = (out / "default" / "all.txt").read_text(encoding="utf-8")
        for config in (*FETCHED_CONFIGS, *DAILY_CONFIGS, *SSTAP_CONFIGS, *UPSTREAM_CONFIGS):
            assert config in everything, f"{config} missing from all.txt"
        for config in EXTRA_BYPASS_CONFIGS:
            assert config not in everything, "extra-bypass configs are not default/ material"

        assert pipeline_seams["daily_repo"]["patterns"] is settings.DAILY_DATE_PATTERNS
        assert len(pipeline_seams["tg_proxy"]) == 1, "the tg-proxy stage never ran"
        mtproto, _ = pipeline_seams["tg_proxy"][0]
        assert any("t.me/proxy" in entry for entry in mtproto), "the scraper extracted nothing"

    def test_bypass_all_is_the_verified_set_with_a_subscription_header(
        self, pipeline_seams: dict[str, Any], tmp_path: Path
    ) -> None:
        """The published master file: header plus the verifier's working configs."""
        out, _ = run_pipeline(tmp_path)
        content = (out / "bypass" / "bypass-all.txt").read_text(encoding="utf-8")

        assert content.startswith("#profile-title: bypass-all")
        assert "#announce:" in content
        assert "#subscription-userinfo:" in content

        working = read_config_lines(out / "bypass" / "bypass-all.txt")
        assert working
        for config in (*EXTRA_BYPASS_CONFIGS, *MANUAL_CONFIGS):
            assert any(line.startswith(config) for line in working)

    def test_unsecure_output_carries_the_sni_survivors(
        self, pipeline_seams: dict[str, Any], tmp_path: Path
    ) -> None:
        """bypass-unsecure/ is written from the same SNI survivors."""
        out, _ = run_pipeline(tmp_path)
        unsecure = read_config_lines(out / "bypass-unsecure" / "bypass-unsecure-all.txt")
        assert unsecure
        for config in EXTRA_BYPASS_CONFIGS:
            assert any(line.startswith(config) for line in unsecure)

    def test_stub_set_only_writes_master_bypass_files(
        self, pipeline_seams: dict[str, Any], tmp_path: Path
    ) -> None:
        """No ``bypass-{N}.txt`` below MAX_CONFIGS_PER_FILE working configs.

        Documents the harness boundary: the progressive seal needs 300 working
        configs, so a stub set this small must not produce numbered shards. The
        master file is asserted alongside so the glob cannot pass vacuously.
        """
        out, _ = run_pipeline(tmp_path)
        shards = sorted(path.name for path in (out / "bypass").glob("bypass-*.txt"))
        assert shards == ["bypass-all.txt"]


class TestUploadPairs:
    """The list handed to the uploaders is what ships broken publishes."""

    def test_the_expected_files_are_published(
        self, pipeline_seams: dict[str, Any], tmp_path: Path
    ) -> None:
        """Every documented output has a remote path in the upload list."""
        _, file_pairs = run_pipeline(tmp_path)

        for entry in file_pairs:
            assert isinstance(entry, tuple), f"{entry!r} is not a (local, remote) pair"
            local, remote = entry
            assert local and remote

        remotes = {remote for _, remote in file_pairs}
        missing = EXPECTED_REMOTE_PATHS - remotes
        assert not missing, f"nothing would be published for: {sorted(missing)}"
        for remote in remotes:
            assert remote.startswith(("githubmirror/", "source/config/")), remote

    def test_main_drives_the_pipeline_without_a_core_binary(
        self, pipeline_seams: dict[str, Any], main_seams: dict[str, Any], tmp_path: Path
    ) -> None:
        """``main()`` — the 0%-coverage path — from argument handling to completion.

        The xray branch is taken (``skip_xray=False``) with a stub binary path,
        and the verifier stub keeps the core unspawned; ``dry_run`` keeps the
        GitHub handlers out of the picture while still exercising the pipeline
        and the upload-pair assembly.
        """
        out = tmp_path / "main-out"
        main_module.main(
            dry_run=True,
            output_dir=str(out),
            skip_xray=False,
            tcp_ping=False,
            no_proxy_check=True,
            flag_overrides=dict(OUTPUT_FLAGS),
        )

        main_seams["ensure_xray"].assert_called_once()
        main_seams["notify_success"].assert_called_once()
        assert (out / "bypass" / "bypass-all.txt").is_file()
        assert (out / "default" / "all.txt").is_file()
        announced = main_seams["notify_success"].call_args.args[0]
        assert announced.endswith("configs working")


class TestPathResolution:
    """Output and source paths must not depend on the process directory.

    The tool runs from a cron entry, a service wrapper, an IDE runner and the
    repository root, and the working directory of those launches has nothing to
    do with the checkout. The output directory defaults and the two
    ``source/config/*.txt`` upload sources used to be relative literals, so a
    different cwd silently published nothing, or wrote the generated tree
    outside the repository.
    """

    def test_every_production_default_points_into_the_repository(self) -> None:
        """One definition, and every default derives from it."""
        expected_output = _normalized(Path(settings.REPO_ROOT, "githubmirror"))

        for name, callable_ in _output_dir_defaults().items():
            default = inspect.signature(callable_).parameters["output_dir"].default
            assert isinstance(default, str), f"{name} default is not a path: {default!r}"
            assert Path(default).is_absolute(), f"{name} default is relative: {default!r}"
            assert _normalized(default) == expected_output, name

        assert _normalized(settings.GITHUBMIRROR_DIR) == expected_output
        assert _normalized(settings.QR_CODES_DIR) == _normalized(
            Path(settings.REPO_ROOT, "qr-codes")
        )
        assert _normalized(settings.SOURCE_CONFIG_DIR) == _normalized(
            Path(settings.REPO_ROOT, "source", "config")
        )

    def test_defaults_match_the_documented_invocation(self) -> None:
        """Run from ``source/``, every path must land where it lands today.

        ``../githubmirror`` and ``../qr-codes`` resolved from ``<repo>/source``
        are ``<repo>/githubmirror`` and ``<repo>/qr-codes``; the derived
        constants must produce exactly those, so this fix cannot move a single
        published file for the documented invocation.
        """
        source_dir = settings.SOURCE_DIR

        assert _normalized(settings.GITHUBMIRROR_DIR) == _normalized(
            os.path.join(source_dir, "..", "githubmirror")
        )
        assert _normalized(settings.QR_CODES_DIR) == _normalized(
            os.path.join(source_dir, "..", "qr-codes")
        )
        # The CIDR whitelist default was "../source/config/cidrwhitelist.txt".
        assert _normalized(settings.SOURCE_CONFIG_DIR) == _normalized(
            os.path.join(source_dir, "..", "source", "config")
        )

    def test_the_two_config_upload_sources_are_absolute_repo_files(
        self, pipeline_seams: dict[str, Any], foreign_cwd: Path, tmp_path: Path
    ) -> None:
        """The URLS.txt / servers.txt pairs resolve from any directory."""
        _, file_pairs = run_pipeline(tmp_path)

        pairs = {
            remote: local for local, remote in file_pairs if remote.startswith("source/config/")
        }
        assert set(pairs) == {"source/config/URLS.txt", "source/config/servers.txt"}
        assert _normalized(pairs["source/config/URLS.txt"]) == _normalized(
            Path(settings.SOURCE_CONFIG_DIR, "URLS.txt")
        )
        assert _normalized(pairs["source/config/servers.txt"]) == _normalized(
            Path(settings.SOURCE_CONFIG_DIR, "servers.txt")
        )
        for local in pairs.values():
            assert Path(local).is_file()

    def test_a_run_from_a_foreign_cwd_writes_nothing_outside_the_output_dir(
        self, pipeline_seams: dict[str, Any], foreign_cwd: Path, tmp_path: Path
    ) -> None:
        """The inverse assertion: a chdir must not steer a single side effect.

        Both entries the run is allowed to add under ``tmp_path`` are its own
        sandbox: ``out/`` is the output directory the test passed, and
        ``url_stats.json`` is where the fixture redirected the stats file. A
        ``qr-codes/`` or ``githubmirror/`` entry here is the defect — the old
        literals put them next to whatever directory the process was launched
        from.
        """
        before = {path.name for path in tmp_path.iterdir()}

        out, _ = run_pipeline(tmp_path)

        after = {path.name for path in tmp_path.iterdir()}
        assert after - before == {"out", "url_stats.json"}
        assert out.is_dir()
        assert not (tmp_path / "qr-codes").exists()
        assert not (tmp_path / "githubmirror").exists()

    def test_the_cidr_whitelist_default_resolves_from_any_cwd(self, foreign_cwd: Path) -> None:
        """The third relative literal: the CIDR whitelist path.

        ``load_cidr_whitelist()`` defaulted to ``"../source/config/..."``, which
        is only correct from ``source/``. From any other directory the default
        must still find the repository's whitelist — a non-empty result proves
        it, because a missing file is logged and turned into an empty set.
        """
        assert load_cidr_whitelist()


class TestGuardsAndSideEffects:
    """The guards are what make the offline claim falsifiable."""

    def test_socket_connect_is_refused(self) -> None:
        with pytest.raises(AssertionError, match="network call"):
            socket.socket().connect(("example.invalid", 443))

    def test_process_spawn_is_refused(self) -> None:
        with pytest.raises(AssertionError, match="spawn a process"):
            subprocess.run(["true"])

    def test_url_stats_lands_in_the_temporary_directory(
        self, pipeline_seams: dict[str, Any], tmp_path: Path
    ) -> None:
        """The run reports its stats into the sandbox, not the repository."""
        run_pipeline(tmp_path)
        assert (tmp_path / "url_stats.json").is_file()

    def test_the_run_leaves_the_source_config_lists_untouched(
        self, pipeline_seams: dict[str, Any], tmp_path: Path
    ) -> None:
        """``URLS.txt`` and ``servers.txt`` are read, never rewritten, by a run.

        The stats auto-cleanup rewrites them when URLs or manual servers fail
        repeatedly; with every stubbed fetch succeeding there must be nothing to
        clean, so their mtime and size must survive the run.
        """
        config_dir = Path(settings.__file__).resolve().parent
        watched = [config_dir / name for name in ("URLS.txt", "servers.txt")]
        before = {path: (path.stat().st_mtime_ns, path.stat().st_size) for path in watched}

        run_pipeline(tmp_path)

        after = {path: (path.stat().st_mtime_ns, path.stat().st_size) for path in watched}
        assert after == before

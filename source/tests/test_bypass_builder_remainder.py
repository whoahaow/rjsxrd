"""Unit tests for bypass_builder end-of-run remainder flush, sealed_keys, and ping sort."""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import patch

import pytest

from utils import bypass_builder

pytestmark = pytest.mark.unit


def _url(i: int) -> str:
    return f"vless://uuid-{i:04d}@host-{i:04d}.example.com:443?security=reality#n{i:04d}"


def _read_bases(path: Path) -> list[str]:
    lines = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    return [re.split(r"#", line, maxsplit=1)[0].strip() for line in lines]


def _setup_raw(tmp_path: Path) -> tuple[Path, Path]:
    raw_dir = tmp_path / "bypass" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_path = raw_dir / "bypass-all-raw.txt"
    raw_path.write_text(f"# header\n{_url(0)}\n", encoding="utf-8")
    all_path = tmp_path / "bypass" / "bypass-all.txt"
    return raw_path, all_path


class TestBypassRemainderAndPingOrder:
    """Remainder flushing, missed-boundary recovery, preservation, and global ping sort."""

    def test_400_configs_seals_300_then_flushes_100_to_second_file(self, tmp_path: Path) -> None:
        raw_path, all_path = _setup_raw(tmp_path)
        all_urls = [_url(i) for i in range(400)]
        uploads: list[tuple[str, str]] = []

        def fake_verify(*_args, progress_callback=None, **_kwargs):
            if progress_callback:
                progress_callback(all_urls[:300], 300)
            return all_urls

        with patch.object(bypass_builder, "verify_config_file", side_effect=fake_verify):
            working, _ = bypass_builder.verify_and_write_bypass(
                str(raw_path),
                str(all_path),
                str(tmp_path),
                False,
                None,
                None,
                False,
                upload_file=lambda local, remote: uploads.append((local, remote)),
            )

        assert len(working) == 400
        b1 = _read_bases(tmp_path / "bypass" / "bypass-1.txt")
        b2 = _read_bases(tmp_path / "bypass" / "bypass-2.txt")
        ball = _read_bases(all_path)
        assert len(b1) == 300
        assert len(b2) == 100
        assert len(ball) == 400
        assert set(b1).isdisjoint(set(b2))
        assert set(b1) | set(b2) == set(ball)
        assert [r for _, r in uploads] == [
            "githubmirror/bypass/bypass-1.txt",
            "githubmirror/bypass/bypass-2.txt",
        ]

    def test_below_300_configs_flushes_into_bypass_1(self, tmp_path: Path) -> None:
        raw_path, all_path = _setup_raw(tmp_path)
        all_urls = [_url(i) for i in range(220)]
        uploads: list[str] = []

        with patch.object(bypass_builder, "verify_config_file", return_value=all_urls):
            working, _ = bypass_builder.verify_and_write_bypass(
                str(raw_path),
                str(all_path),
                str(tmp_path),
                False,
                None,
                None,
                False,
                upload_file=lambda _local, remote: uploads.append(remote),
            )

        assert len(working) == 220
        b1 = _read_bases(tmp_path / "bypass" / "bypass-1.txt")
        assert len(b1) == 220
        assert not (tmp_path / "bypass" / "bypass-2.txt").exists()
        assert uploads == ["githubmirror/bypass/bypass-1.txt"]

    def test_tail_crossing_600_boundary_seals_all_leftovers(self, tmp_path: Path) -> None:
        raw_path, all_path = _setup_raw(tmp_path)
        all_urls = [_url(i) for i in range(610)]

        def fake_verify(*_args, progress_callback=None, **_kwargs):
            if progress_callback:
                progress_callback(all_urls[:300], 300)
                progress_callback(all_urls[300:590], 590)
            return all_urls

        with patch.object(bypass_builder, "verify_config_file", side_effect=fake_verify):
            working, _ = bypass_builder.verify_and_write_bypass(
                str(raw_path), str(all_path), str(tmp_path), False, None, None, False
            )

        assert len(working) == 610
        b1 = _read_bases(tmp_path / "bypass" / "bypass-1.txt")
        b2 = _read_bases(tmp_path / "bypass" / "bypass-2.txt")
        b3 = _read_bases(tmp_path / "bypass" / "bypass-3.txt")
        assert (len(b1), len(b2), len(b3)) == (300, 300, 10)
        assert len(set(b1) | set(b2) | set(b3)) == 610

    def test_old_higher_numbered_files_are_preserved(self, tmp_path: Path) -> None:
        raw_path, all_path = _setup_raw(tmp_path)
        old_file = tmp_path / "bypass" / "bypass-4.txt"
        old_file.write_text("stale-but-preserved\n", encoding="utf-8")
        all_urls = [_url(i) for i in range(400)]

        with patch.object(bypass_builder, "verify_config_file", return_value=all_urls):
            bypass_builder.verify_and_write_bypass(
                str(raw_path), str(all_path), str(tmp_path), False, None, None, False
            )

        assert old_file.exists()
        assert old_file.read_text(encoding="utf-8") == "stale-but-preserved\n"

    def test_bypass_all_keeps_final_ping_order_over_mid_run_callback(self, tmp_path: Path) -> None:
        raw_path, all_path = _setup_raw(tmp_path)
        all_urls = [_url(i) for i in range(400)]

        def fake_verify(*_args, progress_callback=None, **_kwargs):
            # Mid-run snapshot saw indices 100..399 before fastest 0..99 finished.
            if progress_callback:
                progress_callback(all_urls[100:400], 300)
            # Final return from verify_config_file is globally sorted by ping (0..399).
            return all_urls

        with patch.object(bypass_builder, "verify_config_file", side_effect=fake_verify):
            bypass_builder.verify_and_write_bypass(
                str(raw_path), str(all_path), str(tmp_path), False, None, None, False
            )

        ball = _read_bases(all_path)
        b1 = _read_bases(tmp_path / "bypass" / "bypass-1.txt")
        b2 = _read_bases(tmp_path / "bypass" / "bypass-2.txt")
        assert ball == [re.split(r"#", u, maxsplit=1)[0] for u in all_urls]
        assert len(b1) == 300
        assert len(b2) == 100
        assert set(b1).isdisjoint(set(b2))
        assert set(b1) | set(b2) == set(ball)

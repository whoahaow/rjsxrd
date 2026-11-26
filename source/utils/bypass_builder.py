"""Bypass config verification and file building.

Extracted from config_processor.py. Handles Xray/TCP verification of bypass
configs and creates sorted working-config files.
"""

import contextlib
import glob
import os
import re
from collections import defaultdict
from collections.abc import Callable

from config.settings import (
    GITHUBMIRROR_DIR,
    MAX_CONFIGS_PER_FILE,
    VALIDATION_HTTP_TIMEOUT,
    VALIDATION_TCP_TIMEOUT,
)
from utils.config_helpers import natural_sort_key, path_in_output
from utils.file_writer import get_subscription_header, write_configs_file
from utils.logger import log
from utils.url_stats import URLStats


def _cleanup_stale_raw_split_shards(
    output_dir: str, main_path: str, raw_dir_glob: str, prefix: str
) -> None:
    """Remove stale raw input split shards (e.g. bypass-all-raw-1.txt) from a
    previous run when the main raw file exists for the current run."""
    if os.path.exists(main_path):
        for stale in glob.glob(path_in_output(output_dir, raw_dir_glob, f"{prefix}-*.txt")):
            if re.match(r".*-\d+\.txt$", stale):
                with contextlib.suppress(OSError):
                    os.remove(stale)


def _cleanup_stale_bypass_split_files(
    output_dir: str, prefix: str, current_file_count: int
) -> None:
    """Preserve existing split files ({prefix}-{N}.txt) across updates so subscribers
    can continue using working configs from previous runs while updates are incoming.
    """


def _write_sealed_chunk(
    chunk: list[tuple[float, str]],
    file_idx: int,
    output_dir: str,
    prefix: str,
    upload_file: Callable[[str, str], None] | None,
    sealed_keys: set | None,
) -> None:
    """Sort one chunk by latency, write `{prefix}-{N}.txt`, record keys, and upload."""
    from utils.file_utils import _get_dedup_key

    chunk.sort(key=lambda x: x[0])
    chunk_urls = [u for _, u in chunk]
    filename = f"{prefix}-{file_idx + 1}.txt"
    local_path = path_in_output(output_dir, prefix, filename)
    remote_path = f"githubmirror/{prefix}/{filename}"
    try:
        write_configs_file(
            local_path,
            chunk_urls,
            get_subscription_header(filename, config_count=len(chunk_urls)),
        )
        if sealed_keys is not None:
            for url in chunk_urls:
                key = _get_dedup_key(url)
                if key is not None:
                    sealed_keys.add(key)
        if upload_file:
            upload_file(local_path, remote_path)
    except (OSError, RuntimeError) as e:
        log(f"Progressive write failed for {local_path}: {e}")


def seal_bypass_files(
    accumulator: list[tuple[float, str]],
    output_dir: str,
    prefix: str,
    seen_keys: set,
    last_sealed_idx: int,
    upload_file: Callable[[str, str], None] | None = None,
    max_per_file: int = MAX_CONFIGS_PER_FILE,
    flush_partial: bool = False,
    sealed_keys: set | None = None,
) -> int:
    """Seal bypass-{N}.txt files from unsealed entries in the accumulator.

    During verification (`flush_partial=False`), only full `max_per_file` chunks
    are sealed. At the end of verification (`flush_partial=True`), any trailing
    `< max_per_file` remainder is also written to the next `{prefix}-{N}.txt`.
    """
    from utils.file_utils import _get_dedup_key

    new_idx = last_sealed_idx
    delta: list[tuple[float, str]] = []
    for latency, url in accumulator:
        key = _get_dedup_key(url)
        if key is None or key in seen_keys:
            continue
        delta.append((latency, url))
        seen_keys.add(key)

    offset = 0
    while offset + max_per_file <= len(delta):
        _write_sealed_chunk(
            delta[offset : offset + max_per_file],
            new_idx,
            output_dir,
            prefix,
            upload_file,
            sealed_keys,
        )
        offset += max_per_file
        new_idx += 1

    if flush_partial and offset < len(delta):
        _write_sealed_chunk(
            delta[offset:],
            new_idx,
            output_dir,
            prefix,
            upload_file,
            sealed_keys,
        )
        new_idx += 1

    return new_idx


def _has_raw_files_for(main_path: str, raw_dir: str, prefix: str) -> bool:
    """Check if any raw files exist (main or split shards)."""
    if os.path.exists(main_path):
        return True
    if os.path.isdir(raw_dir):
        return any(
            re.match(rf"{re.escape(prefix)}-\d+\.txt$", os.path.basename(p))
            for p in glob.glob(f"{raw_dir}/{prefix}-*.txt")
        )
    return False


def _write_empty_bypass_file(filepath: str, header_name: str) -> None:
    """Write empty bypass file with header. Catches I/O errors so caller doesn't crash."""
    try:
        write_configs_file(filepath, [], get_subscription_header(header_name))
    except OSError as e:
        log(f"Warning: could not write empty {filepath}: {e}")


def _gather_raw_files(main_path: str, raw_dir: str, prefix: str, label: str) -> list[str]:
    """Collect raw files to verify: main file if exists, otherwise split shards."""
    files = []
    if os.path.exists(main_path):
        files.append(main_path)
    elif os.path.isdir(raw_dir):
        split_files = sorted(glob.glob(f"{raw_dir}/{prefix}-*.txt"), key=natural_sort_key)
        split_files = [p for p in split_files if re.match(r".*-\d+\.txt$", p)]
        if split_files:
            files.extend(split_files)
            log(f"{label} not found, using {len(split_files)} split raw files")
    return files


def _load_raw_configs_into_set(filepath: str, target: set) -> None:
    """Load config lines from a raw file (skip comments) into an existing set."""
    try:
        with open(filepath, encoding="utf-8", buffering=65536) as f:
            target.update(
                line.strip() for line in f if line.strip() and not line.strip().startswith("#")
            )
    except (OSError, UnicodeDecodeError) as e:
        log(f"Warning: Could not read {filepath}: {e}")


def verify_config_file(
    input_path: str,
    configs: list[str] | None = None,
    verbose: bool = False,
    tcp_ping: bool = False,
    config_to_sources: dict | None = None,
    stats: URLStats | None = None,
    progress_callback: Callable | None = None,
) -> list[str]:
    """Verify configs in a file and return sorted working configs."""
    try:
        if configs is None:
            with open(input_path, encoding="utf-8") as f:
                configs = [
                    line.strip() for line in f if line.strip() and not line.strip().startswith("#")
                ]
            from utils.file_utils import deduplicate_configs

            configs = deduplicate_configs(configs)

        if not configs:
            log(f"No configs in {input_path}")
            return []

        all_results = []
        if tcp_ping:
            from utils.simple_tester import SimpleTester

            tester = SimpleTester(timeout=VALIDATION_TCP_TIMEOUT)
            all_results = tester.test_batch(
                configs, verbose=verbose, progress_callback=progress_callback
            )
        else:
            verifier = None
            try:
                from utils.xray_compat import filter_xray_compatible
                from utils.xray_tester import XrayTester

                verifier = XrayTester()
                if verifier.xray_path and os.path.isfile(verifier.xray_path):
                    log(f"Using Xray-core tester: {verifier.xray_path}")
                    # Final compat filter before xray sees these configs
                    configs, rejected = filter_xray_compatible(configs)
                    if rejected:
                        # Attributed to the file being verified: the filter's own
                        # line counts a batch, and a run verifies several, so
                        # without this no reader can tell which source lost configs.
                        log(
                            f"{input_path}: {len(rejected)} config(s) are not testable "
                            f"by xray, {len(configs)} go on to verification"
                        )
                    if not configs:
                        log("All configs filtered out by xray compat check")
                        all_results = []
                    else:
                        all_results = verifier.test_batch(
                            configs,
                            timeout=VALIDATION_HTTP_TIMEOUT,
                            verbose=verbose,
                            progress_callback=progress_callback,
                        )
                else:
                    xray_path_str = (
                        verifier.xray_path if verifier and verifier.xray_path else "default paths"
                    )
                    log(
                        f"WARNING: Xray not found at {xray_path_str}. "
                        f"Skipping verification of {len(configs)} configs. "
                        "Run `python3 main.py` (without --skip-xray) once to download xray, "
                        "or use --tcp-ping for TCP-only verification."
                    )
                    all_results = []
            finally:
                if verifier:
                    try:
                        verifier.cleanup()
                    except (AttributeError, OSError, RuntimeError) as cleanup_error:
                        if verbose:
                            log(f"Cleanup warning: {cleanup_error}")

        if stats and config_to_sources and all_results:
            source_counts: defaultdict[str, list[int]] = defaultdict(lambda: [0, 0])
            for cfg, is_working, _ in all_results:
                for src in config_to_sources.get(cfg, []):
                    source_counts[src][0] += 1
                    if is_working:
                        source_counts[src][1] += 1
                    stats.record_config_verification(src, cfg, is_working)
            # The accumulator has to be a list to be mutated in place, while
            # record_verified_yield takes (tested, working) tuples.
            stats.record_verified_yield({url: (c[0], c[1]) for url, c in source_counts.items()})

        working = [(cfg, s, lat) for cfg, s, lat in all_results if s]
        working.sort(key=lambda x: x[2])
        sorted_configs = [cfg for cfg, _, _ in working]
        log(f"Verification: {len(sorted_configs)}/{len(configs)} working (tcp_ping={tcp_ping})")
        return sorted_configs

    except (OSError, ValueError) as e:
        log(f"Error verifying {input_path}: {e}")
        return []


def _run_progressive_seal(
    working_chunk: list[str],
    accumulator: list[tuple[float, str]],
    sealed_keys: set,
    last_sealed_idx: list[int],
    output_dir: str,
    prefix: str,
    upload_file: Callable[[str, str], None] | None,
    progress_callback: Callable | None,
    total_tested: int,
) -> None:
    """Append progressive working URLs and seal any new full 300-config files."""
    for i, url in enumerate(working_chunk):
        accumulator.append((float(i), url))

    # Pass a copy of sealed_keys as seen_keys so unsealed leftovers stay eligible
    # for subsequent progressive batches and the final end-of-run flush.
    new_idx = seal_bypass_files(
        accumulator=accumulator,
        output_dir=output_dir,
        prefix=prefix,
        seen_keys=set(sealed_keys),
        last_sealed_idx=last_sealed_idx[0],
        upload_file=upload_file,
        sealed_keys=sealed_keys,
    )
    last_sealed_idx[0] = new_idx

    if progress_callback:
        try:
            progress_callback(list(working_chunk), total_tested)
        except (OSError, RuntimeError) as e:
            log(f"Progress callback error: {e}")


def _flush_unsealed_split_files(
    sorted_working: list[str],
    sealed_keys: set,
    last_sealed_idx: list[int],
    output_dir: str,
    prefix: str,
    upload_file: Callable[[str, str], None] | None,
) -> None:
    """Seal any unsealed full chunks plus the trailing <300 remainder at run end."""
    if not sorted_working:
        return
    final_acc = [(float(i), url) for i, url in enumerate(sorted_working)]
    last_sealed_idx[0] = seal_bypass_files(
        accumulator=final_acc,
        output_dir=output_dir,
        prefix=prefix,
        seen_keys=set(sealed_keys),
        last_sealed_idx=last_sealed_idx[0],
        upload_file=upload_file,
        flush_partial=True,
        sealed_keys=sealed_keys,
    )


def verify_and_write_bypass(
    bypass_all_raw_path: str,
    bypass_all_txt_path: str,
    output_dir: str,
    tcp_ping: bool,
    config_to_sources: dict | None,
    stats: URLStats | None,
    verbose: bool,
    progress_callback: Callable | None = None,
    upload_file: Callable[[str, str], None] | None = None,
) -> tuple:
    """STEP 1: Verify bypass-all-raw.txt and create bypass-all.txt with split files.

    Progressive upload flow:
      1. Hoist accumulator and dedup set to function scope.
      2. For each raw file, call verify_config_file with a callback that
         adds the working URLs to the global accumulator and seals any
         new full files (uploaded via upload_file).
      3. After all raw files, write bypass-all.txt from the full
         accumulator (in arrival order; seen_keys ensures no duplicates).
         Upload it.
      4. Clean up any local bypass-N.txt files whose index exceeds the
         current run's count (e.g. if a previous run produced 8 files
         but this run only produces 5, the extras 6-8 are removed locally).
    """
    from utils.file_utils import deduplicate_configs

    bypass_raw_dir = path_in_output(output_dir, "bypass", "raw")
    raw_files = _gather_raw_files(
        bypass_all_raw_path, bypass_raw_dir, "bypass-all-raw", "bypass-all-raw.txt"
    )
    if not raw_files:
        log("No bypass raw config files found, skipping")
        # Clean up any stale bypass-N.txt files from previous runs — this
        # run produced no bypass split files, so the previous run's
        # leftovers are stale locally.
        _cleanup_stale_bypass_split_files(
            output_dir=output_dir,
            prefix="bypass",
            current_file_count=0,
        )
        return [], []

    # Global accumulator for mid-run progressive sealing; sealed_keys holds only
    # dedup keys that were actually written to a bypass-{N}.txt file.
    accumulator: list[tuple[float, str]] = []
    sealed_keys: set = set()
    last_sealed_idx: list[int] = [0]
    verified_sorted: list[str] = []

    def _cb(sorted_working: list[str], total_tested: int) -> None:
        _run_progressive_seal(
            working_chunk=sorted_working,
            accumulator=accumulator,
            sealed_keys=sealed_keys,
            last_sealed_idx=last_sealed_idx,
            output_dir=output_dir,
            prefix="bypass",
            upload_file=upload_file,
            progress_callback=progress_callback,
            total_tested=total_tested,
        )

    for raw_file in raw_files:
        log(f"Verifying {os.path.basename(raw_file)}...")
        working_chunk = verify_config_file(
            raw_file,
            tcp_ping=tcp_ping,
            config_to_sources=config_to_sources,
            stats=stats,
            verbose=verbose,
            progress_callback=_cb,
        )
        if working_chunk:
            verified_sorted.extend(working_chunk)

    # Build the full deduped working set in true latency order from
    # verify_config_file(), then flush any unsealed full chunks plus the
    # trailing <300 remainder into the next bypass-{N}.txt file(s).
    working_bypass = deduplicate_configs(verified_sorted) if verified_sorted else []
    _flush_unsealed_split_files(
        sorted_working=working_bypass,
        sealed_keys=sealed_keys,
        last_sealed_idx=last_sealed_idx,
        output_dir=output_dir,
        prefix="bypass",
        upload_file=upload_file,
    )
    log(f"Bypass: {len(working_bypass)} unique working configs from {len(raw_files)} raw files")

    # Write bypass-all.txt (canonical master file, written once at the end)
    header = get_subscription_header("bypass-all", config_count=len(working_bypass))
    try:
        if working_bypass:
            write_configs_file(bypass_all_txt_path, working_bypass, header)
            log(f"Created {bypass_all_txt_path} with {len(working_bypass)} working configs")
        else:
            write_configs_file(bypass_all_txt_path, [], header)
            log(f"WARNING: 0 working configs found. Wrote empty {bypass_all_txt_path}")
    except OSError as e:
        log(f"ERROR: failed to write {bypass_all_txt_path}: {e}")
        return working_bypass, []

    # Clean up stale local bypass-N.txt files (those higher than current count)
    _cleanup_stale_bypass_split_files(
        output_dir=output_dir,
        prefix="bypass",
        current_file_count=last_sealed_idx[0],
    )

    return working_bypass, []


def verify_and_write_bypass_unsecure(
    bypass_unsecure_raw_path: str,
    bypass_unsecure_all_txt_path: str,
    bypass_all_raw_path: str,
    output_dir: str,
    working_bypass: list[str],
    tcp_ping: bool,
    config_to_sources: dict | None,
    stats: URLStats | None,
    verbose: bool,
    progress_callback: Callable | None = None,
    upload_file: Callable[[str, str], None] | None = None,
) -> list[str]:
    """STEP 2: Verify bypass-unsecure-all-raw.txt (configs not in secure set).

    Uses the same progressive-seal pattern as verify_and_write_bypass:
    a single accumulator and dedup set across the run, with each new
    full file uploaded via upload_file. The shared seen_keys set is
    passed in via working_bypass (so configs already in the secure set
    are not re-sealed).
    """
    unsecure_raw_dir = path_in_output(output_dir, "bypass-unsecure", "raw")
    unsecure_raw_files = _gather_raw_files(
        bypass_unsecure_raw_path,
        unsecure_raw_dir,
        "bypass-unsecure-all-raw",
        "bypass-unsecure-all-raw.txt",
    )
    if not unsecure_raw_files:
        log("bypass-unsecure-all-raw.txt not found, skipping")
        _write_empty_bypass_file(bypass_unsecure_all_txt_path, "bypass-unsecure-all")
        # Clean up any stale bypass-unsecure-N.txt files from previous runs —
        # this run produced no unsecure split files, so the previous run's
        # leftovers are stale locally (matching the bypass path's cleanup).
        _cleanup_stale_bypass_split_files(
            output_dir=output_dir,
            prefix="bypass-unsecure",
            current_file_count=0,
        )
        return []

    unsecure_configs: list[str] = []
    unsecure_seen: set = set()
    for raw_file in unsecure_raw_files:
        try:
            with open(raw_file, encoding="utf-8", buffering=65536) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and line not in unsecure_seen:
                        unsecure_seen.add(line)
                        unsecure_configs.append(line)
        except (OSError, UnicodeDecodeError) as e:
            log(f"Warning: Could not read unsecure raw file {raw_file}: {e}")

    all_bypass_configs: set[str] = set()
    bypass_raw_dir = path_in_output(output_dir, "bypass", "raw")
    if os.path.exists(bypass_all_raw_path):
        _load_raw_configs_into_set(bypass_all_raw_path, all_bypass_configs)
    if os.path.isdir(bypass_raw_dir):
        for raw_path in glob.glob(f"{bypass_raw_dir}/bypass-all-raw-*.txt"):
            if re.match(r".*-\d+\.txt$", raw_path) and os.path.exists(raw_path):
                _load_raw_configs_into_set(raw_path, all_bypass_configs)

    unsecure_only = [cfg for cfg in unsecure_configs if cfg not in all_bypass_configs]
    log(
        f"unsecure raw: {len(unsecure_configs)} total, {len(all_bypass_configs)} already tested, {len(unsecure_only)} new"
    )

    # Build bypass-unsecure accumulator and sealed set. Pre-seed sealed_keys
    # with the secure set's working configs so they are not re-sealed into
    # bypass-unsecure-N.txt files.
    from utils.file_utils import _get_dedup_key

    accumulator: list[tuple[float, str]] = []
    sealed_keys: set = {_get_dedup_key(u) for u in working_bypass if _get_dedup_key(u) is not None}
    last_sealed_idx: list[int] = [0]

    def _cb_uns(sorted_working: list[str], total_tested: int) -> None:
        _run_progressive_seal(
            working_chunk=sorted_working,
            accumulator=accumulator,
            sealed_keys=sealed_keys,
            last_sealed_idx=last_sealed_idx,
            output_dir=output_dir,
            prefix="bypass-unsecure",
            upload_file=upload_file,
            progress_callback=progress_callback,
            total_tested=total_tested,
        )

    if unsecure_only:
        working_unsecure = verify_config_file(
            unsecure_raw_files[0],
            unsecure_only,
            tcp_ping=tcp_ping,
            config_to_sources=config_to_sources,
            stats=stats,
            verbose=verbose,
            progress_callback=_cb_uns,
        )
        _flush_unsealed_split_files(
            sorted_working=working_unsecure,
            sealed_keys=sealed_keys,
            last_sealed_idx=last_sealed_idx,
            output_dir=output_dir,
            prefix="bypass-unsecure",
            upload_file=upload_file,
        )
        all_working = working_bypass + (working_unsecure or [])
    else:
        log("All configs already verified in secure set")
        all_working = working_bypass

    header = get_subscription_header("bypass-unsecure-all", config_count=len(all_working))
    try:
        if all_working:
            write_configs_file(bypass_unsecure_all_txt_path, all_working, header)
            log(f"Created {bypass_unsecure_all_txt_path} with {len(all_working)} working configs")
        else:
            write_configs_file(bypass_unsecure_all_txt_path, [], header)
            log(f"WARNING: 0 working configs. Wrote empty {bypass_unsecure_all_txt_path}")
    except OSError as e:
        log(f"ERROR: failed to write {bypass_unsecure_all_txt_path}: {e}")
        return []

    # Clean up stale local bypass-unsecure-N.txt files
    _cleanup_stale_bypass_split_files(
        output_dir=output_dir,
        prefix="bypass-unsecure",
        current_file_count=last_sealed_idx[0],
    )

    return []


def create_working_config_files(
    output_dir: str = GITHUBMIRROR_DIR,
    tcp_ping: bool = False,
    config_to_sources: dict | None = None,
    stats: URLStats | None = None,
    verbose: bool = False,
    progress_callback: Callable | None = None,
    upload_file: Callable[[str, str], None] | None = None,
) -> tuple:
    """Creates verified working config files sorted by ping (fastest first)."""
    bypass_all_raw_path = path_in_output(output_dir, "bypass", "raw", "bypass-all-raw.txt")
    bypass_all_txt_path = path_in_output(output_dir, "bypass", "bypass-all.txt")
    bypass_unsecure_raw_path = path_in_output(
        output_dir, "bypass-unsecure", "raw", "bypass-unsecure-all-raw.txt"
    )
    bypass_unsecure_all_txt_path = path_in_output(
        output_dir, "bypass-unsecure", "bypass-unsecure-all.txt"
    )

    _cleanup_stale_raw_split_shards(output_dir, bypass_all_raw_path, "bypass/raw", "bypass-all-raw")
    _cleanup_stale_raw_split_shards(
        output_dir, bypass_unsecure_raw_path, "bypass-unsecure/raw", "bypass-unsecure-all-raw"
    )

    bypass_raw_dir = path_in_output(output_dir, "bypass", "raw")
    unsecure_raw_dir = path_in_output(output_dir, "bypass-unsecure", "raw")
    has_bypass = _has_raw_files_for(bypass_all_raw_path, bypass_raw_dir, "bypass-all-raw")
    has_unsecure = _has_raw_files_for(
        bypass_unsecure_raw_path, unsecure_raw_dir, "bypass-unsecure-all-raw"
    )

    if not has_bypass and not has_unsecure:
        log("No bypass raw config files found for verification")
        _write_empty_bypass_file(bypass_all_txt_path, "bypass-all")
        _write_empty_bypass_file(bypass_unsecure_all_txt_path, "bypass-unsecure-all")
        # Clean up any stale bypass-{N}.txt and bypass-unsecure-{N}.txt
        # files from previous runs (matching the no-raw-files branch in
        # each sub-function).
        _cleanup_stale_bypass_split_files(
            output_dir=output_dir,
            prefix="bypass",
            current_file_count=0,
        )
        _cleanup_stale_bypass_split_files(
            output_dir=output_dir,
            prefix="bypass-unsecure",
            current_file_count=0,
        )
        return ([], [])

    working_bypass, bypass_files = verify_and_write_bypass(
        bypass_all_raw_path,
        bypass_all_txt_path,
        output_dir,
        tcp_ping,
        config_to_sources,
        stats,
        verbose,
        progress_callback=progress_callback,
        upload_file=upload_file,
    )

    unsecure_files = verify_and_write_bypass_unsecure(
        bypass_unsecure_raw_path,
        bypass_unsecure_all_txt_path,
        bypass_all_raw_path,
        output_dir,
        working_bypass,
        tcp_ping,
        config_to_sources,
        stats,
        verbose,
        progress_callback=progress_callback,
        upload_file=upload_file,
    )

    return bypass_files, unsecure_files

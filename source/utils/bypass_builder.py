"""Bypass config verification and file building.

Extracted from config_processor.py. Handles Xray/TCP verification of bypass
configs and creates sorted working-config files.
"""

import os
import glob
import re
from typing import List, Tuple, Optional, Callable

from utils.logger import log
from utils.config_helpers import natural_sort_key, path_in_output
from utils.file_writer import get_subscription_header, write_configs_file
from config.settings import MAX_FILE_SIZE_MB, MAX_CONFIGS_PER_FILE, VALIDATION_TCP_TIMEOUT, VALIDATION_HTTP_TIMEOUT
from utils.url_stats import URLStats
from collections import defaultdict


def _cleanup_stale_raw_split_shards(output_dir: str, main_path: str, raw_dir_glob: str, prefix: str) -> None:
    """Remove stale raw input split shards (e.g. bypass-all-raw-1.txt) from a
    previous run when the main raw file exists for the current run."""
    if os.path.exists(main_path):
        for stale in glob.glob(path_in_output(output_dir, raw_dir_glob, f"{prefix}-*.txt")):
            if re.match(r'.*-\d+\.txt$', stale):
                try:
                    os.remove(stale)
                except OSError:
                    pass


def _cleanup_stale_bypass_split_files(output_dir: str, prefix: str, current_file_count: int) -> None:
    """Remove stale bypass-{N}.txt output files whose index exceeds the current
    run's count. bypass-all.txt is preserved (it's the canonical master file).
    Local-only: does not touch the remote repository.
    """
    prefix_dir = path_in_output(output_dir, prefix)
    if not os.path.isdir(prefix_dir):
        return
    for i in range(current_file_count + 1, 1000):  # cap at 1000 to avoid runaway
        stale = os.path.join(prefix_dir, f"{prefix}-{i}.txt")
        if os.path.exists(stale):
            try:
                os.remove(stale)
            except OSError as e:
                log(f"Warning: could not remove stale {stale}: {e}")


def seal_bypass_files(
    accumulator: List[Tuple[float, str]],
    output_dir: str,
    prefix: str,
    seen_keys: set,
    last_sealed_idx: int,
    upload_file: Optional[Callable[[str, str], None]] = None,
    max_per_file: int = MAX_CONFIGS_PER_FILE,
) -> int:
    """Seal full bypass-{N}.txt files from the working accumulator.

    Walks the accumulator to find configs whose dedup_key is not in seen_keys.
    Each call processes the *delta* — the configs in accumulator that haven't
    been sealed yet. When the delta fills a full file, the next file is sealed:
    chunk is sorted by latency (ascending, independently within this file),
    written locally, and uploaded if upload_file is provided. The chunk's keys
    are added to seen_keys so they will never be re-sealed.

    The chunk is sorted within itself, but the order of files is determined
    by the accumulator's order. bypass-all.txt is the file that gets the
    global sort at the end of the run.

    After this call, files numbered (last_sealed_idx + 1) through the returned
    value are sealed and will not be re-written. The accumulator retains
    partial (un-sealed) configs for the next call.

    Args:
        accumulator: list of (latency, url) tuples in arrival order. May contain
            duplicates and configs already in seen_keys — both are filtered.
        output_dir: root output directory (e.g. "../githubmirror").
        prefix: "bypass" or "bypass-unsecure" — controls filename and remote path.
        seen_keys: set of dedup_keys already sealed. Mutated in place.
        last_sealed_idx: number of files already sealed (0 = none). The next file
            to seal will be numbered last_sealed_idx + 1.
        upload_file: optional callable(local_path, remote_path) for upload.
        max_per_file: chunk size (default 300).

    Returns:
        The new last_sealed_idx (number of files sealed after this call).
    """
    from utils.file_utils import _get_dedup_key

    new_idx = last_sealed_idx
    # Delta: only configs in this accumulator that are not yet sealed.
    # These are the configs we may add to files in THIS call.
    delta: List[Tuple[float, str]] = []
    for latency, url in accumulator:
        key = _get_dedup_key(url)
        if key is None or key in seen_keys:
            continue
        delta.append((latency, url))
        seen_keys.add(key)

    # Seal as many full files as the delta count now permits.
    # delta position [k*max_per_file : (k+1)*max_per_file] maps to file
    # (new_idx + k + 1).
    while (new_idx - last_sealed_idx + 1) * max_per_file <= len(delta):
        file_idx = new_idx
        start = (file_idx - last_sealed_idx) * max_per_file
        end = start + max_per_file
        chunk = delta[start:end]
        # Sort this chunk by latency ascending (independent per-file sort).
        # Each file's configs are independently sorted by latency so the
        # first config in each file is the fastest in that file. Global
        # order across files is not latency-sorted — that's the role of
        # bypass-all.txt, which is written once at the end.
        chunk.sort(key=lambda x: x[0])
        chunk_urls = [u for _, u in chunk]
        filename = f"{prefix}-{file_idx + 1}.txt"
        local_path = path_in_output(output_dir, prefix, filename)
        remote_path = f"githubmirror/{prefix}/{filename}"
        try:
            write_configs_file(
                local_path, chunk_urls,
                get_subscription_header(filename, config_count=len(chunk_urls)),
            )
            if upload_file:
                upload_file(local_path, remote_path)
        except (IOError, OSError, RuntimeError) as e:
            log(f"Progressive write failed for {local_path}: {e}")
        new_idx += 1
    return new_idx


def _has_raw_files_for(main_path: str, raw_dir: str, prefix: str) -> bool:
    """Check if any raw files exist (main or split shards)."""
    if os.path.exists(main_path):
        return True
    if os.path.isdir(raw_dir):
        return any(re.match(rf'{re.escape(prefix)}-\d+\.txt$', os.path.basename(p))
                   for p in glob.glob(f"{raw_dir}/{prefix}-*.txt"))
    return False


def _write_empty_bypass_file(filepath: str, header_name: str) -> None:
    """Write empty bypass file with header. Catches I/O errors so caller doesn't crash."""
    try:
        write_configs_file(filepath, [], get_subscription_header(header_name))
    except (IOError, OSError) as e:
        log(f"Warning: could not write empty {filepath}: {e}")


def _gather_raw_files(main_path: str, raw_dir: str, prefix: str, label: str) -> List[str]:
    """Collect raw files to verify: main file if exists, otherwise split shards."""
    files = []
    if os.path.exists(main_path):
        files.append(main_path)
    elif os.path.isdir(raw_dir):
        split_files = sorted(glob.glob(f"{raw_dir}/{prefix}-*.txt"), key=natural_sort_key)
        split_files = [p for p in split_files if re.match(r'.*-\d+\.txt$', p)]
        if split_files:
            files.extend(split_files)
            log(f"{label} not found, using {len(split_files)} split raw files")
    return files


def _load_raw_configs_into_set(filepath: str, target: set) -> None:
    """Load config lines from a raw file (skip comments) into an existing set."""
    try:
        with open(filepath, 'r', encoding='utf-8', buffering=65536) as f:
            target.update(line.strip() for line in f
                          if line.strip() and not line.strip().startswith('#'))
    except (IOError, OSError, UnicodeDecodeError) as e:
        log(f"Warning: Could not read {filepath}: {e}")


def verify_config_file(input_path: str, configs: List[str] = None, verbose: bool = False,
                        tcp_ping: bool = False, config_to_sources: dict = None,
                        stats: Optional[URLStats] = None,
                        progress_callback: Optional[Callable] = None) -> List[str]:
    """Verify configs in a file and return sorted working configs."""
    try:
        if configs is None:
            with open(input_path, 'r', encoding='utf-8') as f:
                configs = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            from utils.file_utils import deduplicate_configs
            configs = deduplicate_configs(configs)

        if not configs:
            log(f"No configs in {input_path}")
            return []

        all_results = []
        if tcp_ping:
            from utils.simple_tester import SimpleTester
            tester = SimpleTester(timeout=VALIDATION_TCP_TIMEOUT)
            all_results = tester.test_batch(configs, verbose=verbose, progress_callback=progress_callback)
        else:
            verifier = None
            try:
                from utils.xray_tester import XrayTester, filter_xray_compatible
                verifier = XrayTester()
                if verifier.xray_path and os.path.isfile(verifier.xray_path):
                    log(f"Using Xray-core tester: {verifier.xray_path}")
                    # Final compat filter before xray sees these configs
                    configs, rejected = filter_xray_compatible(configs)
                    if not configs:
                        log("All configs filtered out by xray compat check")
                        all_results = []
                    else:
                        all_results = verifier.test_batch(configs, timeout=VALIDATION_HTTP_TIMEOUT, verbose=verbose, progress_callback=progress_callback)
                else:
                    xray_path_str = verifier.xray_path if verifier and verifier.xray_path else "default paths"
                    log(f"WARNING: Xray not found at {xray_path_str}. "
                        f"Skipping verification of {len(configs)} configs. "
                        "Run `python3 main.py` (without --skip-xray) once to download xray, "
                        "or use --tcp-ping for TCP-only verification.")
                    all_results = []
            finally:
                if verifier:
                    try:
                        verifier.cleanup()
                    except (AttributeError, OSError, RuntimeError) as cleanup_error:
                        if verbose:
                            log(f"Cleanup warning: {cleanup_error}")

        if stats and config_to_sources and all_results:
            source_counts = defaultdict(lambda: [0, 0])
            for cfg, is_working, _ in all_results:
                for src in config_to_sources.get(cfg, []):
                    source_counts[src][0] += 1
                    if is_working:
                        source_counts[src][1] += 1
                    stats.record_config_verification(src, cfg, is_working)
            stats.record_verified_yield(dict(source_counts))

        working = [(cfg, s, l) for cfg, s, l in all_results if s]
        working.sort(key=lambda x: x[2])
        sorted_configs = [cfg for cfg, _, _ in working]
        log(f"Verification: {len(sorted_configs)}/{len(configs)} working (tcp_ping={tcp_ping})")
        return sorted_configs

    except (IOError, OSError, ValueError) as e:
        log(f"Error verifying {input_path}: {e}")
        return []


def _run_progressive_seal(
    working_chunk: List[str],
    accumulator: List[Tuple[float, str]],
    seen_keys: set,
    last_sealed_idx: List[int],
    output_dir: str,
    prefix: str,
    upload_file: Optional[Callable[[str, str], None]],
    progress_callback: Optional[Callable],
    total_tested: int,
) -> None:
    """Add a per-raw-file batch of working URLs to the global accumulator and
    seal any new full bypass-{N}.txt files. Called by the verification
    callback for each raw file's working results.

    Args:
        working_chunk: list of working URLs from this raw file (already
            sorted by latency by verify_config_file). Latencies are not
            available here so we use position-based synthetic latencies
            that preserve the existing arrival order.
        accumulator: global list of (latency, url) tuples across all raw
            files. Mutated in place.
        seen_keys: dedup_keys set. Mutated in place.
        last_sealed_idx: single-element list tracking how many files have
            been sealed so far. Mutated in place.
        output_dir, prefix, upload_file: passed to seal_bypass_files.
        progress_callback: optional upstream callback fired with current
            sorted_working list (for CLI progress display).
        total_tested: passed to progress_callback.
    """
    # Synthetic latencies preserve arrival order within this batch.
    # seal_bypass_files will sort each chunk by these latencies, so the
    # order within each file matches the per-raw-file order produced
    # by verify_config_file. The dedup (seen_keys) ensures configs from
    # earlier batches in the accumulator do not get re-sorted into a
    # later file's chunk.
    for i, url in enumerate(working_chunk):
        accumulator.append((float(i), url))

    # Seal any new full files. The accumulator may have grown enough to
    # fill one or more new files since the last seal.
    new_idx = seal_bypass_files(
        accumulator=accumulator,
        output_dir=output_dir,
        prefix=prefix,
        seen_keys=seen_keys,
        last_sealed_idx=last_sealed_idx[0],
        upload_file=upload_file,
    )
    last_sealed_idx[0] = new_idx

    if progress_callback:
        try:
            # Provide the full sorted working set for upstream display
            sorted_working = sorted(working_chunk)
            progress_callback(sorted_working, total_tested)
        except (IOError, OSError, RuntimeError) as e:
            log(f"Progress callback error: {e}")


def verify_and_write_bypass(bypass_all_raw_path: str, bypass_all_txt_path: str,
                              output_dir: str, tcp_ping: bool,
                              config_to_sources: Optional[dict],
                              stats: Optional[URLStats], verbose: bool,
                              progress_callback: Optional[Callable] = None,
                              upload_file: Optional[Callable[[str, str], None]] = None) -> tuple:
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
    raw_files = _gather_raw_files(bypass_all_raw_path, bypass_raw_dir, "bypass-all-raw", "bypass-all-raw.txt")
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

    # Global accumulator across all raw files
    accumulator: List[Tuple[float, str]] = []
    seen_keys: set = set()
    last_sealed_idx: List[int] = [0]

    # Track which raw files fired their callback at least once. If the
    # callback never fires (e.g. < 300 working configs, so no threshold
    # crossed), the accumulator doesn't grow for that raw file and we
    # need to process the return value as a fallback.
    callback_fired: List[bool] = [False]

    def _cb(sorted_working: List[str], total_tested: int) -> None:
        callback_fired[0] = True
        _run_progressive_seal(
            working_chunk=sorted_working,
            accumulator=accumulator,
            seen_keys=seen_keys,
            last_sealed_idx=last_sealed_idx,
            output_dir=output_dir,
            prefix="bypass",
            upload_file=upload_file,
            progress_callback=progress_callback,
            total_tested=total_tested,
        )

    for raw_file in raw_files:
        log(f"Verifying {os.path.basename(raw_file)}...")
        # verify_config_file returns the full sorted working set for this
        # raw file. In production the callback also fires incrementally
        # at 300/600/900 thresholds, but if a raw file has fewer than
        # 300 working configs the callback never fires — we must use the
        # return value as a fallback. When the callback DOES fire, the
        # return value is the same set (plus possibly more items added
        # after the last callback fire), so we dedup against accumulator
        # to avoid double-adding.
        callback_fired[0] = False
        working_chunk = verify_config_file(raw_file, tcp_ping=tcp_ping,
                                              config_to_sources=config_to_sources,
                                              stats=stats, verbose=verbose,
                                              progress_callback=_cb)
        if working_chunk and not callback_fired[0]:
            # Callback did not fire (working_count never crossed a 300
            # threshold for this raw file). Process the return value.
            _run_progressive_seal(
                working_chunk=working_chunk,
                accumulator=accumulator,
                seen_keys=seen_keys,
                last_sealed_idx=last_sealed_idx,
                output_dir=output_dir,
                prefix="bypass",
                upload_file=upload_file,
                progress_callback=None,
                total_tested=len(working_chunk),
            )
        elif working_chunk and callback_fired[0]:
            # Callback fired. The accumulator may be missing items added
            # by verify_config_file AFTER its last callback fire (the
            # working_chunk is the full final set). Check for items in
            # the return value that are not yet in seen and add them.
            from utils.file_utils import _get_dedup_key
            new_items = [u for u in working_chunk
                         if _get_dedup_key(u) is not None
                         and _get_dedup_key(u) not in seen_keys]
            if new_items:
                _run_progressive_seal(
                    working_chunk=new_items,
                    accumulator=accumulator,
                    seen_keys=seen_keys,
                    last_sealed_idx=last_sealed_idx,
                    output_dir=output_dir,
                    prefix="bypass",
                    upload_file=upload_file,
                    progress_callback=None,
                    total_tested=len(working_chunk),
                )

    # Final seal: catch any remaining full file (e.g. accumulator reached
    # exactly 600 at the end of the last raw file's callback, but the loop
    # condition was checked before the file was completed).
    if last_sealed_idx[0] * MAX_CONFIGS_PER_FILE < len(accumulator):
        final_idx = seal_bypass_files(
            accumulator=accumulator,
            output_dir=output_dir,
            prefix="bypass",
            seen_keys=seen_keys,
            last_sealed_idx=last_sealed_idx[0],
            upload_file=upload_file,
        )
        last_sealed_idx[0] = final_idx

    # Build the full deduped working set for bypass-all.txt and for the
    # return value. The accumulator is in arrival order from callback
    # fires plus the fallback paths. dedup is defensive: seen_keys has
    # already filtered duplicates during seal_bypass_files calls.
    working_bypass = [u for _, u in accumulator]
    if working_bypass:
        working_bypass = deduplicate_configs(working_bypass)
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
    except (IOError, OSError) as e:
        log(f"ERROR: failed to write {bypass_all_txt_path}: {e}")
        return working_bypass, []

    # Clean up stale local bypass-N.txt files (those higher than current count)
    _cleanup_stale_bypass_split_files(
        output_dir=output_dir,
        prefix="bypass",
        current_file_count=last_sealed_idx[0],
    )

    return working_bypass, []


def verify_and_write_bypass_unsecure(bypass_unsecure_raw_path: str,
                                       bypass_unsecure_all_txt_path: str,
                                       bypass_all_raw_path: str, output_dir: str,
                                       working_bypass: List[str], tcp_ping: bool,
                                       config_to_sources: Optional[dict],
                                       stats: Optional[URLStats],
                                       verbose: bool,
                                       progress_callback: Optional[Callable] = None,
                                       upload_file: Optional[Callable[[str, str], None]] = None) -> List[str]:
    """STEP 2: Verify bypass-unsecure-all-raw.txt (configs not in secure set).

    Uses the same progressive-seal pattern as verify_and_write_bypass:
    a single accumulator and dedup set across the run, with each new
    full file uploaded via upload_file. The shared seen_keys set is
    passed in via working_bypass (so configs already in the secure set
    are not re-sealed).
    """
    unsecure_raw_dir = path_in_output(output_dir, "bypass-unsecure", "raw")
    unsecure_raw_files = _gather_raw_files(bypass_unsecure_raw_path, unsecure_raw_dir,
                                            "bypass-unsecure-all-raw", "bypass-unsecure-all-raw.txt")
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

    unsecure_configs: List[str] = []
    unsecure_seen: set = set()
    for raw_file in unsecure_raw_files:
        try:
            with open(raw_file, 'r', encoding='utf-8', buffering=65536) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and line not in unsecure_seen:
                        unsecure_seen.add(line)
                        unsecure_configs.append(line)
        except (IOError, OSError, UnicodeDecodeError) as e:
            log(f"Warning: Could not read unsecure raw file {raw_file}: {e}")

    all_bypass_configs = set()
    bypass_raw_dir = path_in_output(output_dir, "bypass", "raw")
    if os.path.exists(bypass_all_raw_path):
        _load_raw_configs_into_set(bypass_all_raw_path, all_bypass_configs)
    if os.path.isdir(bypass_raw_dir):
        for f in glob.glob(f"{bypass_raw_dir}/bypass-all-raw-*.txt"):
            if re.match(r'.*-\d+\.txt$', f) and os.path.exists(f):
                _load_raw_configs_into_set(f, all_bypass_configs)

    unsecure_only = [cfg for cfg in unsecure_configs if cfg not in all_bypass_configs]
    log(f"unsecure raw: {len(unsecure_configs)} total, {len(all_bypass_configs)} already tested, {len(unsecure_only)} new")

    # Build bypass-unsecure accumulator and dedup set. Seed seen_keys with
    # the secure set's working configs so they are not re-sealed into
    # bypass-unsecure-N.txt files.
    from utils.file_utils import _get_dedup_key
    accumulator: List[Tuple[float, str]] = []
    seen_keys: set = {_get_dedup_key(u) for u in working_bypass if _get_dedup_key(u) is not None}
    last_sealed_idx: List[int] = [0]
    callback_fired: List[bool] = [False]

    def _cb_uns(sorted_working: List[str], total_tested: int) -> None:
        callback_fired[0] = True
        _run_progressive_seal(
            working_chunk=sorted_working,
            accumulator=accumulator,
            seen_keys=seen_keys,
            last_sealed_idx=last_sealed_idx,
            output_dir=output_dir,
            prefix="bypass-unsecure",
            upload_file=upload_file,
            progress_callback=progress_callback,
            total_tested=total_tested,
        )

    if unsecure_only:
        # Same fallback logic as verify_and_write_bypass: if the callback
        # never fires for this unsecure run (working_count < 300), or if
        # the return value has items not seen by the callback, process them.

        callback_fired[0] = False
        working_unsecure = verify_config_file(unsecure_raw_files[0], unsecure_only,
                                                 tcp_ping=tcp_ping,
                                                 config_to_sources=config_to_sources,
                                                 stats=stats, verbose=verbose,
                                                 progress_callback=_cb_uns)
        if working_unsecure and not callback_fired[0]:
            _run_progressive_seal(
                working_chunk=working_unsecure,
                accumulator=accumulator,
                seen_keys=seen_keys,
                last_sealed_idx=last_sealed_idx,
                output_dir=output_dir,
                prefix="bypass-unsecure",
                upload_file=upload_file,
                progress_callback=None,
                total_tested=len(working_unsecure),
            )
        elif working_unsecure and callback_fired[0]:
            from utils.file_utils import _get_dedup_key
            new_items = [u for u in working_unsecure
                         if _get_dedup_key(u) is not None
                         and _get_dedup_key(u) not in seen_keys]
            if new_items:
                _run_progressive_seal(
                    working_chunk=new_items,
                    accumulator=accumulator,
                    seen_keys=seen_keys,
                    last_sealed_idx=last_sealed_idx,
                    output_dir=output_dir,
                    prefix="bypass-unsecure",
                    upload_file=upload_file,
                    progress_callback=None,
                    total_tested=len(working_unsecure),
                )
        # Final seal after the run
        if last_sealed_idx[0] * MAX_CONFIGS_PER_FILE < len(accumulator):
            final_idx = seal_bypass_files(
                accumulator=accumulator,
                output_dir=output_dir,
                prefix="bypass-unsecure",
                seen_keys=seen_keys,
                last_sealed_idx=last_sealed_idx[0],
                upload_file=upload_file,
            )
            last_sealed_idx[0] = final_idx
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
    except (IOError, OSError) as e:
        log(f"ERROR: failed to write {bypass_unsecure_all_txt_path}: {e}")
        return []

    # Clean up stale local bypass-unsecure-N.txt files
    _cleanup_stale_bypass_split_files(
        output_dir=output_dir,
        prefix="bypass-unsecure",
        current_file_count=last_sealed_idx[0],
    )

    return []


def create_working_config_files(output_dir: str = "../githubmirror", tcp_ping: bool = False,
                                 config_to_sources: Optional[dict] = None,
                                 stats: Optional[URLStats] = None,
                                 verbose: bool = False,
                                 progress_callback: Optional[Callable] = None,
                                 upload_file: Optional[Callable[[str, str], None]] = None) -> tuple:
    """Creates verified working config files sorted by ping (fastest first)."""
    bypass_all_raw_path = path_in_output(output_dir, "bypass", "raw", "bypass-all-raw.txt")
    bypass_all_txt_path = path_in_output(output_dir, "bypass", "bypass-all.txt")
    bypass_unsecure_raw_path = path_in_output(output_dir, "bypass-unsecure", "raw", "bypass-unsecure-all-raw.txt")
    bypass_unsecure_all_txt_path = path_in_output(output_dir, "bypass-unsecure", "bypass-unsecure-all.txt")

    _cleanup_stale_raw_split_shards(output_dir, bypass_all_raw_path, "bypass/raw", "bypass-all-raw")
    _cleanup_stale_raw_split_shards(output_dir, bypass_unsecure_raw_path, "bypass-unsecure/raw", "bypass-unsecure-all-raw")

    bypass_raw_dir = path_in_output(output_dir, "bypass", "raw")
    unsecure_raw_dir = path_in_output(output_dir, "bypass-unsecure", "raw")
    has_bypass = _has_raw_files_for(bypass_all_raw_path, bypass_raw_dir, "bypass-all-raw")
    has_unsecure = _has_raw_files_for(bypass_unsecure_raw_path, unsecure_raw_dir, "bypass-unsecure-all-raw")

    if not has_bypass and not has_unsecure:
        log("No bypass raw config files found for verification")
        _write_empty_bypass_file(bypass_all_txt_path, "bypass-all")
        _write_empty_bypass_file(bypass_unsecure_all_txt_path, "bypass-unsecure-all")
        # Clean up any stale bypass-{N}.txt and bypass-unsecure-{N}.txt
        # files from previous runs (matching the no-raw-files branch in
        # each sub-function).
        _cleanup_stale_bypass_split_files(
            output_dir=output_dir, prefix="bypass", current_file_count=0,
        )
        _cleanup_stale_bypass_split_files(
            output_dir=output_dir, prefix="bypass-unsecure", current_file_count=0,
        )
        return ([], [])

    working_bypass, bypass_files = verify_and_write_bypass(
        bypass_all_raw_path, bypass_all_txt_path, output_dir, tcp_ping,
        config_to_sources, stats, verbose,
        progress_callback=progress_callback, upload_file=upload_file)

    unsecure_files = verify_and_write_bypass_unsecure(
        bypass_unsecure_raw_path, bypass_unsecure_all_txt_path,
        bypass_all_raw_path, output_dir, working_bypass, tcp_ping,
        config_to_sources, stats, verbose,
        progress_callback=progress_callback, upload_file=upload_file)

    return bypass_files, unsecure_files

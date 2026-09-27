"""Shared helper functions used by the config pipeline.

Extracted from processors/config_processor.py to keep the pipeline
module focused on orchestration. These are pure utility functions
with no dependency on ConfigPipeline internals.
"""

import base64
import binascii
import os
import re
import threading


def natural_sort_key(path: str) -> list[int | str]:
    """Sort key for file paths with numeric suffixes (e.g. -1.txt, -2.txt, -10.txt).

    Standard string sort gives '-10.txt' < '-2.txt' (lexicographic), which scrambles
    split shards. This splits on digits and sorts the numeric parts as integers.
    """
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", path)]


def resolve_flag(name: str, overrides: dict | None, default: bool) -> bool:
    """Resolve a feature flag value from CLI overrides, falling back to settings.

    Used by process_all_configs to honor per-run CLI overrides of the 5
    feature flags defined in config/settings.py. Without this, the flags
    would be snapshot-bound at import time and CLI overrides would be silently
    ignored.

    Args:
        name: The flag name (e.g. 'ENABLE_DEFAULT_FILES').
        overrides: Optional dict from CLI parsing. None = no overrides.
                   Missing key = fall back to the imported default.
        default: The imported module-level value from config.settings.

    Returns:
        bool: The effective flag value for this run.
    """
    if overrides is None:
        return default
    if name in overrides:
        return bool(overrides[name])
    return default


def add_unique(configs: list[str], target: list[str], seen: set, seen_lock: threading.Lock) -> int:
    """Append only configs not already in `seen` to `target`. Returns count added.

    Thread-safe. The seen set is checked under lock; the actual append to target
    is also under lock to prevent two threads appending the same config.

    Empty and whitespace-only strings are skipped (not counted as added).
    """
    if not configs:
        return 0
    added = 0
    with seen_lock:
        for cfg in configs:
            if not cfg or not cfg.strip() or cfg in seen:
                continue
            seen.add(cfg)
            target.append(cfg)
            added += 1
    return added


def path_in_output(output_dir: str, *parts: str) -> str:
    """Build a path under the output directory using os.path.join.

    Centralizes the 34 places that build paths like
    `f"{output_dir}/default/all.txt"` so they consistently use
    os.path.join (cross-platform path separators).

    Usage:
        path_in_output(output_dir, "default", "all.txt")

    Args:
        output_dir: The base output directory.
        *parts: Path components to join under output_dir. Empty strings are
                filtered out so trailing slashes don't cause empty components.

    Returns:
        The joined path string. Same return type as os.path.join.
    """
    return os.path.join(output_dir, *filter(None, parts))


# Pre-compiled base64 pattern for performance (used by try_decode_base64_content)
_BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/]+=*$")


def try_decode_base64_content(content: str) -> str | None:
    """Try to decode base64 content. Returns decoded string if successful, None otherwise.

    Uses quick heuristics to skip obvious non-base64 content before attempting decode.
    """
    try:
        content_stripped = content.strip()
        if not content_stripped:
            return None

        # Heuristic 1: If content has many newlines, probably not base64
        newline_ratio = content_stripped.count("\n") / len(content_stripped)
        if newline_ratio > 0.1:
            return None

        # Heuristic 2: If content already has protocol markers, not base64
        if "://" in content_stripped:
            return None

        # Heuristic 3: If content looks like plain text (spaces, common words), skip
        if " " in content_stripped and len(content_stripped) > 100:
            space_ratio = content_stripped.count(" ") / len(content_stripped)
            if space_ratio > 0.05:
                return None

        # Heuristic 4: Character distribution check (base64 has very specific charset)
        valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n")
        invalid_chars = sum(1 for c in content_stripped if c not in valid_chars)
        if invalid_chars > len(content_stripped) * 0.01:  # >1% invalid chars = not base64
            return None

        cleaned = content_stripped.replace("\n", "").replace(" ", "")
        if not _BASE64_PATTERN.match(cleaned):
            return None

        decoded_bytes = base64.b64decode(content_stripped)
        decoded_content = decoded_bytes.decode("utf-8", errors="ignore")

        if any(
            proto in decoded_content
            for proto in [
                "vless://",
                "vmess://",
                "trojan://",
                "ss://",
                "ssr://",
                "hysteria://",
                "hysteria2://",
                "hy2://",
                "tuic://",
            ]
        ):
            return decoded_content

        return None
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return None

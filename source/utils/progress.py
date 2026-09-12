"""Single source of truth for tqdm availability.

Before this module existed, three files (xray_tester.py, simple_tester.py,
telegram_proxy_verifier.py) each had their own try/except block for tqdm
imports, each maintained their own TQDM_AVAILABLE flag, and each had
inline `if TQDM_AVAILABLE and async_tqdm:` guards. Result: 4 places to keep
in sync, and the guard is more verbose than the fallback.

This module imports tqdm once at module load. If tqdm is missing, the
import fails loudly with a clear ImportError pointing here. The single
`is_available()` check is the only fallback in the codebase.
"""

try:
    from tqdm import tqdm
    from tqdm.asyncio import tqdm as async_tqdm

    _AVAILABLE = True
except ImportError:
    tqdm = None
    async_tqdm = None
    _AVAILABLE = False


def is_available() -> bool:
    """Return True if tqdm is importable."""
    return _AVAILABLE


def get_sync_pbar(*args, **kwargs):
    """Return a tqdm progress bar if available, else None.

    Callers check `if get_sync_pbar() is not None` and fall back to plain
    iteration if tqdm is missing. One-line API, single fallback point.
    """
    if not _AVAILABLE:
        return None
    if tqdm is None:
        raise RuntimeError("tqdm not available")
    return tqdm(*args, **kwargs)


def get_async_pbar(*args, **kwargs):
    """Async-tqdm progress bar (tqdm.asyncio.tqdm) if available, else None."""
    if not _AVAILABLE:
        return None
    if async_tqdm is None:
        raise RuntimeError("tqdm not available")
    return async_tqdm(*args, **kwargs)

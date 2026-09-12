"""Single source of truth for psutil availability.

All modules that need psutil should import from here instead of
duplicating the try/except ImportError pattern.
"""

try:
    import psutil

    HAS_PSUTIL = True
except ImportError:
    psutil = None  # type: ignore[assignment]
    HAS_PSUTIL = False


__all__ = ["psutil", "HAS_PSUTIL"]

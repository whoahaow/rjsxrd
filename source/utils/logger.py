"""Utility functions for the VPN configs generator.

Provides thread-safe logging with standardized levels (DEBUG, INFO, WARNING, ERROR).
All logs are collected by file index and printed to stderr to avoid interfering with tqdm.

This is a thin wrapper around stdlib logging that preserves the original public API.
"""

import logging
import re
import sys
from collections import defaultdict
from enum import IntEnum
from urllib.parse import urlparse


class LogLevel(IntEnum):
    """Standard logging levels matching Python logging module."""

    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50


# Level name mapping matching original output format (WARNING -> WARN)
# Using plain int keys for Pyright compatibility with logging.LogRecord.levelno
_LEVEL_NAMES = {
    LogLevel.DEBUG: "DEBUG",
    LogLevel.INFO: "INFO",
    LogLevel.WARNING: "WARN",
    LogLevel.ERROR: "ERROR",
    LogLevel.CRITICAL: "CRITICAL",
}
_LEVEL_NAMES_INT: dict[int, str] = {int(k): v for k, v in _LEVEL_NAMES.items()}


# In-memory log storage for backward compatibility (tests read from this)
LOGS_BY_FILE = defaultdict(list)

# Current log level (can be adjusted via environment or config)
CURRENT_LOG_LEVEL = LogLevel.INFO

# Regular expression to extract file index from message
_GITHUBMIRROR_INDEX_RE = re.compile(r"githubmirror/(\d+)\.txt")
updated_files = set()

# --- Stdlib logging setup (thin backend) ---
_logger = logging.getLogger("rjsxrd")
_logger.setLevel(logging.INFO)


class _LogFormatter(logging.Formatter):
    """Formats log records as [LEVEL] message, matching the original custom format."""

    def format(self, record: logging.LogRecord) -> str:
        level_name = _LEVEL_NAMES_INT.get(record.levelno, "INFO")
        return f"[{level_name}] {record.getMessage()}"


_handler = logging.StreamHandler(sys.stderr)
_handler.setFormatter(_LogFormatter())
_logger.addHandler(_handler)
_logger.propagate = False  # Don't duplicate to root logger


def _format_message(level: LogLevel, message: str) -> str:
    """Format message with level prefix.

    Preserved for test compatibility.

    Args:
        level: Log level
        message: Message text

    Returns:
        Formatted message string like '[INFO] message'
    """
    level_name = _LEVEL_NAMES.get(level, "INFO")
    return f"[{level_name}] {message}"


def _extract_index(msg: str) -> int:
    """Extract file index from message like 'githubmirror/12.txt'.

    Args:
        msg: Log message potentially containing file reference

    Returns:
        File index (0 if not found)
    """
    m = _GITHUBMIRROR_INDEX_RE.search(msg)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            pass
    return 0


def log(message: str, level: LogLevel = LogLevel.INFO) -> None:
    """Add message to thread-safe log dictionary and print to stderr.

    Args:
        message: Log message text
        level: Log level (default: INFO). Messages below CURRENT_LOG_LEVEL are suppressed.

    Example:
        log("Config downloaded", LogLevel.INFO)
        log("Debug info", LogLevel.DEBUG)  # Only shown if level lowered
        log("Something went wrong", LogLevel.ERROR)
    """
    # Suppress messages below current log level
    if level < CURRENT_LOG_LEVEL:
        return

    formatted = _format_message(level, message)
    idx = _extract_index(message)

    LOGS_BY_FILE[idx].append(formatted)

    # Use stdlib logging for thread-safe output to stderr
    _logger.log(level, message)


def debug(message: str) -> None:
    """Log debug message (only shown if log level set to DEBUG).

    Args:
        message: Debug message
    """
    log(message, LogLevel.DEBUG)


def info(message: str) -> None:
    """Log info message (default level).

    Args:
        message: Info message
    """
    log(message, LogLevel.INFO)


def warning(message: str) -> None:
    """Log warning message.

    Args:
        message: Warning message
    """
    log(message, LogLevel.WARNING)


def error(message: str) -> None:
    """Log error message.

    Args:
        message: Error message
    """
    log(message, LogLevel.ERROR)


def critical(message: str) -> None:
    """Log critical error message.

    Args:
        message: Critical error message
    """
    log(message, LogLevel.CRITICAL)


def set_log_level(level: LogLevel) -> None:
    """Set minimum log level for display.

    Args:
        level: Minimum level to display (e.g., LogLevel.DEBUG for verbose)
    """
    global CURRENT_LOG_LEVEL
    CURRENT_LOG_LEVEL = level
    _logger.setLevel(level)


def extract_source_name(url: str) -> str:
    """Extract readable source name from URL.

    Args:
        url: Source URL

    Returns:
        Human-readable source identifier
    """
    try:
        parsed = urlparse(url)
        path_parts = parsed.path.split("/")
        if len(path_parts) > 2:
            return f"{path_parts[1]}/{path_parts[2]}"
        return parsed.netloc
    except (ValueError, TypeError):
        return "Unknown source"


def print_logs() -> None:
    """Print all collected logs in ordered manner by file index."""
    ordered_keys = sorted(k for k in LOGS_BY_FILE.keys() if k != 0)
    output_lines = []

    for k in ordered_keys:
        output_lines.append(f"----- {k}.txt -----")
        output_lines.extend(LOGS_BY_FILE[k])

    if LOGS_BY_FILE.get(0):
        output_lines.append("----- General messages -----")
        output_lines.extend(LOGS_BY_FILE[0])

    print("\n".join(output_lines), file=sys.stderr, flush=True)

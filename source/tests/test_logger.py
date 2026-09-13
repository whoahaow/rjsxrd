"""Tests for utils/logger.py — thread-safe logging."""

import pytest

from utils.logger import (
    CURRENT_LOG_LEVEL,
    LOGS_BY_FILE,
    LogLevel,
    _extract_index,
    _format_message,
    critical,
    debug,
    error,
    extract_source_name,
    info,
    log,
    print_logs,
    set_log_level,
    warning,
)

pytestmark = pytest.mark.unit


class TestLogLevel:
    """LogLevel enum values match standard Python logging levels."""

    def test_debug_value(self):
        assert LogLevel.DEBUG == 10

    def test_info_value(self):
        assert LogLevel.INFO == 20

    def test_warning_value(self):
        assert LogLevel.WARNING == 30

    def test_error_value(self):
        assert LogLevel.ERROR == 40

    def test_critical_value(self):
        assert LogLevel.CRITICAL == 50


class TestExtractIndex:
    """Extract file index from log messages."""

    def test_extracts_number(self):
        assert _extract_index("githubmirror/12.txt") == 12

    def test_returns_zero_when_no_match(self):
        assert _extract_index("just a message") == 0

    def test_returns_zero_for_invalid_number(self):
        assert _extract_index("githubmirror/abc.txt") == 0

    def test_extracts_from_full_path(self):
        assert _extract_index("path/to/githubmirror/5.txt updated") == 5


class TestFormatMessage:
    """Format log messages with level prefix."""

    def test_debug_format(self):
        assert _format_message(LogLevel.DEBUG, "test") == "[DEBUG] test"

    def test_info_format(self):
        assert _format_message(LogLevel.INFO, "hi") == "[INFO] hi"

    def test_warning_format(self):
        assert _format_message(LogLevel.WARNING, "warn") == "[WARN] warn"

    def test_error_format(self):
        assert _format_message(LogLevel.ERROR, "err") == "[ERROR] err"

    def test_critical_format(self):
        assert _format_message(LogLevel.CRITICAL, "crit") == "[CRITICAL] crit"

    def test_unknown_level_falls_back_to_info(self):
        class FakeLevel:
            value = 99  # Not a real LogLevel

        result = _format_message(FakeLevel(), "msg")
        assert "[INFO]" in result


class TestLog:
    """Test the core log function."""

    def setup_method(self):
        LOGS_BY_FILE.clear()

    def test_log_adds_to_store(self):
        log("test message")
        assert len(LOGS_BY_FILE[0]) > 0

    def test_log_suppresses_below_level(self):
        original = CURRENT_LOG_LEVEL
        try:
            set_log_level(LogLevel.WARNING)
            log("debug msg", LogLevel.DEBUG)
            # DEBUG < WARNING, so nothing should be logged
            assert len(LOGS_BY_FILE[0]) == 0
        finally:
            set_log_level(original)

    def test_log_indexed_by_file(self):
        log("githubmirror/42.txt updated")
        assert len(LOGS_BY_FILE[42]) > 0

    def test_log_at_level(self):
        original = CURRENT_LOG_LEVEL
        try:
            set_log_level(LogLevel.DEBUG)
            log("debug msg", LogLevel.DEBUG)
            assert len(LOGS_BY_FILE[0]) > 0, "log should pass through at DEBUG level"
        finally:
            set_log_level(original)


class TestConvenienceFunctions:
    """debug(), info(), warning(), error(), critical() each call log() with right level."""

    def setup_method(self):
        LOGS_BY_FILE.clear()

    def test_debug_calls_log(self):
        original = CURRENT_LOG_LEVEL
        try:
            set_log_level(LogLevel.DEBUG)
            debug("debug test")
            assert any("debug test" in msg for msgs in LOGS_BY_FILE.values() for msg in msgs)
        finally:
            set_log_level(original)

    def test_info_calls_log(self):
        info("info test")
        assert any("info test" in msg for msgs in LOGS_BY_FILE.values() for msg in msgs)

    def test_warning_calls_log(self):
        warning("warning test")
        assert any("warning test" in msg for msgs in LOGS_BY_FILE.values() for msg in msgs)

    def test_error_calls_log(self):
        error("error test")
        assert any("error test" in msg for msgs in LOGS_BY_FILE.values() for msg in msgs)

    def test_critical_calls_log(self):
        critical("critical test")
        assert any("critical test" in msg for msgs in LOGS_BY_FILE.values() for msg in msgs)


class TestSetLogLevel:
    """set_log_level changes the global log level."""

    def test_changes_level(self):
        import utils.logger as logger_mod

        original = logger_mod.CURRENT_LOG_LEVEL
        try:
            set_log_level(LogLevel.DEBUG)
            assert logger_mod.CURRENT_LOG_LEVEL == LogLevel.DEBUG
        finally:
            set_log_level(original)


class TestExtractSourceName:
    """Extract human-readable name from URL."""

    def test_extracts_github_repo(self):
        name = extract_source_name("https://raw.githubusercontent.com/user/repo/main/configs")
        assert "user/repo" in name

    def test_returns_netloc_for_short_urls(self):
        name = extract_source_name("https://example.com")
        assert name == "example.com"

    def test_returns_unknown_on_error(self):
        # Pass an object that breaks urlparse
        result = extract_source_name(None)
        assert result == "Unknown source"


class TestPrintLogs:
    """print_logs outputs sorted by file index."""

    def test_prints_ordered_output(self, capsys):
        LOGS_BY_FILE.clear()
        LOGS_BY_FILE[0].append("[INFO] general msg")
        LOGS_BY_FILE[2].append("[INFO] file 2 msg")
        LOGS_BY_FILE[1].append("[INFO] file 1 msg")
        print_logs()
        captured = capsys.readouterr()
        # stderr output
        assert "1.txt" in captured.err
        assert "2.txt" in captured.err
        assert "General messages" in captured.err

    def test_empty_logs_no_crash(self, capsys):
        LOGS_BY_FILE.clear()
        print_logs()  # must not raise
        captured = capsys.readouterr()
        assert captured.err == "" or "-----" not in captured.err

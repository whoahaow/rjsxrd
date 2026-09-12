"""Telegram bot notification for pipeline events.

Sends start/success/error notifications via Telegram Bot API.
Uses only requests.post — no polling, no webhook, no long-running process.

Gated by TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID env vars.
If either is not set, all functions are silent no-ops.
"""

import os
import time
from datetime import datetime, timedelta, timezone

try:
    import requests as _requests
except ImportError:
    _requests = None  # type: ignore[assignment]


_TOKEN: str = os.environ.get("TELEGRAM_BOT_TOKEN", "")
_CHAT_ID: str = os.environ.get("TELEGRAM_CHAT_ID", "")
_ENABLED: bool = bool(_TOKEN and _CHAT_ID and _requests is not None)

# Track start time for duration calculation
_start_time: float = 0.0


def _send(text: str) -> None:
    """Send a message via Telegram Bot API. Silent no-op if not configured."""
    if not _ENABLED:
        return
    try:
        url = f"https://api.telegram.org/bot{_TOKEN}/sendMessage"
        _requests.post(url, data={
            "chat_id": _CHAT_ID,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }, timeout=10)
    except (_requests.RequestException, OSError):
        pass  # never let notifications crash the pipeline


def notify_start() -> None:
    """Send 'pipeline started' notification."""
    global _start_time
    _start_time = time.time()
    msk = timezone(timedelta(hours=3))
    now = datetime.now(msk).strftime("%d.%m.%Y %H:%M:%S")
    _send(
        "\ud83d\udd04 <b>rjsxrd: запуск</b>\n"
        f"\u23f0 {now}"
    )


def notify_success(stats: str) -> None:
    """Send 'pipeline completed successfully' notification.

    Args:
        stats: Short one-liner with results (e.g. '243/512 verified, 2m14s').
    """
    elapsed = time.time() - _start_time if _start_time else 0
    mins, secs = divmod(int(elapsed), 60)
    duration = f"{mins}min {secs}s" if mins else f"{secs}s"
    _send(
        "\u2705 <b>rjsxrd: готово</b>\n"
        f"{stats}\n"
        f"\u23f1 {duration}"
    )


def notify_error(error_msg: str) -> None:
    """Send 'pipeline failed' notification.

    Args:
        error_msg: Short error description (first 200 chars).
    """
    elapsed = time.time() - _start_time if _start_time else 0
    mins, secs = divmod(int(elapsed), 60)
    duration = f"{mins}min {secs}s" if mins else f"{secs}s"
    truncated = error_msg[:200]
    _send(
        "\u274c <b>rjsxrd: ошибка</b>\n"
        f"<code>{truncated}</code>\n"
        f"\u23f1 {duration}"
    )

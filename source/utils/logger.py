"""Utility functions for the VPN configs generator."""

import threading
from collections import defaultdict
import re

# Thread-safe logging
LOGS_BY_FILE = defaultdict(list)
_LOG_LOCK = threading.Lock()
_UPDATED_FILES_LOCK = threading.Lock()

# Regular expression to extract file index from message
_GITHUBMIRROR_INDEX_RE = re.compile(r"githubmirror/(\d+)\.txt")
updated_files = set()


def _extract_index(msg: str) -> int:
    """Пытается извлечь номер файла из строки вида 'githubmirror/12.txt'."""
    m = _GITHUBMIRROR_INDEX_RE.search(msg)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            pass
    return 0


def log(message: str):
    """Добавляет сообщение в общий словарь логов потокобезопасно."""
    idx = _extract_index(message)
    with _LOG_LOCK:
        LOGS_BY_FILE[idx].append(message)


def extract_source_name(url: str) -> str:
    """Извлекает понятное имя источника из URL."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path_parts = parsed.path.split('/')
        if len(path_parts) > 2:
            return f"{path_parts[1]}/{path_parts[2]}"
        return parsed.netloc
    except:
        return "Источник"


def print_logs():
    """Prints all collected logs in an ordered manner."""
    ordered_keys = sorted(k for k in LOGS_BY_FILE.keys() if k != 0)
    output_lines = []

    for k in ordered_keys:
        output_lines.append(f"----- {k}.txt -----")
        output_lines.extend(LOGS_BY_FILE[k])

    if LOGS_BY_FILE.get(0):
        output_lines.append("----- Общие сообщения -----")
        output_lines.extend(LOGS_BY_FILE[0])

    print("\n".join(output_lines))
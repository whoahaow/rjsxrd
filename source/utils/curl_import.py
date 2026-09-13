"""Shared curl_cffi import — single source of truth.

Replaces identical try/except blocks in xray_tester.py, xray_batch.py,
and telegram_proxy_verifier.py. Import the symbols you need from here.

curl_cffi is an optional dependency: when it is missing, the import itself must
still succeed and the caller decides what to do based on CURL_CFFI_AVAILABLE.
Both session classes therefore stay bound (to None) in that branch, which is why
they are declared as Any rather than as the classes they normally hold.
"""

from typing import Any

CURL_CFFI_AVAILABLE: bool
CurlSession: Any
AsyncSession: Any

try:
    from curl_cffi.requests import AsyncSession as _AsyncSession
    from curl_cffi.requests import Session as _CurlSession

    CURL_CFFI_AVAILABLE = True
    CurlSession = _CurlSession
    AsyncSession = _AsyncSession
except ImportError:
    CURL_CFFI_AVAILABLE = False
    CurlSession = None
    AsyncSession = None

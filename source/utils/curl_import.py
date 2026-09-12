"""Shared curl_cffi import — single source of truth.

Replaces identical try/except blocks in xray_tester.py, xray_batch.py,
and telegram_proxy_verifier.py. Import the symbols you need from here.
"""

try:
    from curl_cffi.requests import AsyncSession
    from curl_cffi.requests import Session as CurlSession
    CURL_CFFI_AVAILABLE = True
except ImportError:
    CURL_CFFI_AVAILABLE = False
    CurlSession = None
    AsyncSession = None

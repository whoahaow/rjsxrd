"""Tests for utils/ip_checker._make_request.

The 10th-pass lesson: mocked tests don't catch real import/runtime bugs.
These tests include a real-runtime check (smoke test against a public
endpoint) in addition to mocked tests, so we catch things like
'a subagent imported the wrong package' before users do.
"""

import socket

from utils.ip_verifier import _make_request


class TestMakeRequestImportPath:
    """Verify the import path actually works (the lesson from 10th pass)."""

    def test_make_request_is_importable(self):
        """The function is reachable via utils.ip_verifier."""
        assert callable(_make_request)

    def test_make_request_signature(self):
        """The function takes (url, proxies=, timeout=) — explicit params."""
        import inspect
        sig = inspect.signature(_make_request)
        params = list(sig.parameters.keys())
        assert params == ['url', 'proxies', 'timeout'], (
            f"expected [url, proxies, timeout], got {params}"
        )

class TestMakeRequestNormalPath:
    """When curl_cffi is available, it is preferred."""

    def test_uses_curl_cffi_when_available(self):
        """curl_cffi.Session is used; requests.get is NOT called."""
        from unittest.mock import MagicMock, patch

        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_session.get.return_value = mock_response
        mock_session.__enter__.return_value = mock_session

        # requests is imported inside the function body, so we patch
        # the top-level module to catch any accidental fallback calls.
        with patch('curl_cffi.requests.Session', return_value=mock_session):
            with patch('requests.get') as mock_requests_get:
                result = _make_request(
                    'https://example.com', timeout=5.0
                )
                assert result.status_code == 200
                mock_requests_get.assert_not_called()
                mock_session.get.assert_called_once_with(
                    'https://example.com', proxies=None, timeout=5.0
                )

class TestMakeRequestFallback:
    """When curl_cffi is missing, falls back to requests."""

    def test_falls_back_to_requests_when_curl_cffi_missing(self):
        """If curl_cffi.requests.Session cannot be imported, plain requests is used."""
        import types
        from unittest.mock import MagicMock, patch

        # Build a fake curl_cffi module tree without a Session attribute.
        # When _make_request does 'from curl_cffi.requests import Session',
        # the import machinery finds these fake modules in sys.modules,
        # then fails to get 'Session' — raises ImportError, triggering
        # the fallback to requests.get.
        fake_curl_cffi = types.ModuleType('curl_cffi')
        fake_requests_sub = types.ModuleType('curl_cffi.requests')
        fake_curl_cffi.requests = fake_requests_sub
        # No 'Session' attribute set — this is by design.

        fake_modules = {
            'curl_cffi': fake_curl_cffi,
            'curl_cffi.requests': fake_requests_sub,
        }

        with patch.dict('sys.modules', fake_modules):
            with patch('requests.get') as mock_requests_get:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_requests_get.return_value = mock_response
                result = _make_request(
                    'https://example.com', timeout=5.0
                )
                assert result.status_code == 200
                mock_requests_get.assert_called_once_with(
                    'https://example.com', proxies=None, timeout=5.0
                )

class TestMakeRequestRuntimeSmoke:
    """A real HTTP request — the 10th-pass lesson in action.

    Skips if no internet (CI environments without network). The point is
    to catch import/runtime bugs that mocked tests miss.
    """

    def test_real_request_to_public_endpoint(self):
        """Can actually make a real HTTP GET to a public endpoint."""
        try:
            response = _make_request(
                'https://ifconfig.me/ip', timeout=3.0
            )
        except (socket.gaierror, OSError, ConnectionError) as e:
            import pytest
            pytest.skip(f"no internet for smoke test: {e}")

        assert response is not None
        # 200, 301, and 302 are all acceptable success statuses
        assert response.status_code in (200, 301, 302), (
            f"unexpected status {response.status_code} for ifconfig.me"
        )
        body = response.text.strip()
        assert body, "response body should be non-empty"

class TestGetRealIP:
    """Test get_real_ip with mocked HTTP responses."""

    def test_returns_ip_from_ipwhois(self):
        """First URL (ipwho.is) returns a valid IP."""
        from unittest.mock import MagicMock, patch

        from utils.ip_verifier import get_real_ip

        mock_response = MagicMock()
        mock_response.json.return_value = {'ip': '1.2.3.4'}
        with patch('utils.ip_verifier._make_request', return_value=mock_response):
            ip = get_real_ip(timeout=5.0)
        assert ip == '1.2.3.4'

    def test_falls_back_to_ipify(self):
        """If ipwho.is fails, try api.ipify.org."""
        from unittest.mock import MagicMock, patch

        from utils.ip_verifier import get_real_ip

        call_count = [0]
        def mock_request(url, **kw):
            call_count[0] += 1
            if 'ipwho.is' in url:
                raise ConnectionError("first URL failed")
            mock_resp = MagicMock()
            mock_resp.json.return_value = {'ip': '5.6.7.8'}
            return mock_resp

        with patch('utils.ip_verifier._make_request', side_effect=mock_request):
            ip = get_real_ip(timeout=5.0)
        assert ip == '5.6.7.8'

    def test_falls_back_to_ifconfig(self):
        """If ipwho.is and ipify fail, try ifconfig.me."""
        from unittest.mock import MagicMock, patch

        from utils.ip_verifier import get_real_ip

        call_count = [0]
        def mock_request(url, **kw):
            call_count[0] += 1
            if 'ifconfig.me' in url:
                mock_resp = MagicMock()
                mock_resp.text = '9.10.11.12\n'
                mock_resp.json.side_effect = ValueError("not json")
                return mock_resp
            raise ConnectionError(f"{url} failed")

        with patch('utils.ip_verifier._make_request', side_effect=mock_request):
            ip = get_real_ip(timeout=5.0)
        assert ip == '9.10.11.12'

    def test_returns_none_when_all_fail(self):
        """If all URLs fail, returns None."""
        from unittest.mock import patch

        from utils.ip_verifier import get_real_ip

        with patch('utils.ip_verifier._make_request', side_effect=ConnectionError("no net")):
            ip = get_real_ip(timeout=5.0)
        assert ip is None

class TestGetProxyIP:
    """Test get_proxy_ip with mocked HTTP responses."""

    def test_returns_ip_through_proxy(self):
        """Returns IP from ipwho.is through proxies."""
        from unittest.mock import MagicMock, patch

        from utils.ip_verifier import get_proxy_ip

        mock_response = MagicMock()
        mock_response.json.return_value = {'ip': '1.2.3.4'}
        with patch('utils.ip_verifier._make_request', return_value=mock_response):
            ip = get_proxy_ip('socks5h://127.0.0.1:1080', timeout=5.0)
        assert ip == '1.2.3.4'

    def test_passes_proxies_to_request(self):
        """The proxy URL is passed as proxies dict to _make_request."""
        from unittest.mock import MagicMock, patch

        from utils.ip_verifier import get_proxy_ip

        mock_response = MagicMock()
        mock_response.json.return_value = {'ip': '1.2.3.4'}
        with patch('utils.ip_verifier._make_request', return_value=mock_response) as mock_req:
            get_proxy_ip('socks5h://127.0.0.1:1080', timeout=5.0)
        # _make_request should be called with proxies matching the URL
        _, kwargs = mock_req.call_args
        assert kwargs.get('proxies') == {'http': 'socks5h://127.0.0.1:1080',
                                          'https': 'socks5h://127.0.0.1:1080'}

    def test_returns_none_when_all_fail(self):
        """If all URLs fail, returns None."""
        from unittest.mock import patch

        from utils.ip_verifier import get_proxy_ip

        with patch('utils.ip_verifier._make_request', side_effect=ConnectionError("no net")):
            ip = get_proxy_ip('socks5h://127.0.0.1:1080', timeout=5.0)
        assert ip is None

class TestVerifyProtection:
    """Test verify_protection — the high-level wrapper."""

    def test_detects_different_ips(self):
        """When real_ip != proxy_ip, active=True, different=True."""
        from unittest.mock import MagicMock, patch

        from utils.ip_verifier import verify_protection

        call_count = [0]
        def mock_request(url, proxies=None, timeout=5.0):
            call_count[0] += 1
            mock_resp = MagicMock()
            if 'ipwho.is' in url:
                if call_count[0] <= 2:
                    # First call = no proxy (get_real_ip), second = with proxy (get_proxy_ip)
                    # Third call = country check
                    pass
                mock_resp.json.return_value = {'ip': '5.5.5.5' if call_count[0] > 1 else '1.2.3.4',
                                                'country': 'ProxyLand'}
            elif 'ipify' in url:
                mock_resp.json.return_value = {'ip': '1.2.3.4'}
            else:
                mock_resp.text = '1.2.3.4'
                mock_resp.json.side_effect = ValueError("not json")
            return mock_resp

        with patch('utils.ip_verifier._make_request', side_effect=mock_request):
            result = verify_protection(proxy_host='127.0.0.1', proxy_port=1080, timeout=5.0)

        assert result['active'] is True
        assert result['different'] is True
        assert result['real_ip'] is not None
        assert result['proxy_ip'] is not None
        assert result['error'] is None

    def test_returns_error_on_failure(self):
        """If get_real_ip raises, error is captured."""
        from unittest.mock import patch

        from utils.ip_verifier import verify_protection

        with patch('utils.ip_verifier.get_real_ip', side_effect=RuntimeError("test error")):
            result = verify_protection(timeout=5.0)
        assert result['error'] is not None
        assert result['active'] is False

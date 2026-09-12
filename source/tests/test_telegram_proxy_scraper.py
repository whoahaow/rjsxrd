"""Unit tests for Telegram proxy scraper."""


from fetchers.telegram_proxy_scraper import TelegramProxyScraper


class TestExtractProxies:
    """Test proxy extraction from content."""

    def test_extract_mtproto_standard(self):
        """Test extracting standard MTProto proxy URL."""
        content = 'Check out this proxy: https://t.me/proxy?server=1.2.3.4&port=443&secret=abcd1234'
        mtproto, socks5 = TelegramProxyScraper.extract_proxies(content)

        assert len(mtproto) == 1
        assert 't.me/proxy' in mtproto[0]
        assert 'server=1.2.3.4' in mtproto[0]
        assert len(socks5) == 0

    def test_extract_mtproto_tg_protocol(self):
        """Test extracting MTProto with tg:// protocol."""
        content = 'tg://proxy?server=5.6.7.8&port=8443&secret=xyz789'
        mtproto, socks5 = TelegramProxyScraper.extract_proxies(content)

        assert len(mtproto) == 1
        assert 't.me/proxy' in mtproto[0]  # Should be converted to t.me format

    def test_extract_socks5_standard(self):
        """Test extracting standard SOCKS5 proxy."""
        content = 'SOCKS5: https://t.me/socks?server=proxy.example.com&port=1080&user=admin&pass=secret'
        mtproto, socks5 = TelegramProxyScraper.extract_proxies(content)

        assert len(socks5) == 1
        assert 't.me/socks' in socks5[0]
        assert len(mtproto) == 0

    def test_extract_socks5_raw_format(self):
        """Test extracting raw socks5:// format."""
        content = 'Raw proxy: socks5://user:pass@192.168.1.1:1080'
        mtproto, socks5 = TelegramProxyScraper.extract_proxies(content)

        assert len(socks5) == 1
        assert 't.me/socks' in socks5[0]  # Should be converted

    def test_extract_multiple_proxies(self):
        """Test extracting multiple proxies from content."""
        content = '''
        MTProto 1: https://t.me/proxy?server=1.1.1.1&port=443&secret=abc
        MTProto 2: https://t.me/proxy?server=2.2.2.2&port=8443&secret=def
        SOCKS5: https://t.me/socks?server=3.3.3.3&port=1080
        '''
        mtproto, socks5 = TelegramProxyScraper.extract_proxies(content)

        assert len(mtproto) == 2
        assert len(socks5) == 1

    def test_extract_mixed_formats(self):
        """Test extracting mixed proxy formats."""
        content = '''
        Standard: https://t.me/proxy?server=a.com&port=443&secret=x
        TG protocol: tg://proxy?server=b.com&port=8443&secret=y
        Without protocol: t.me/proxy?server=c.com&port=443&secret=z
        '''
        mtproto, socks5 = TelegramProxyScraper.extract_proxies(content)

        assert len(mtproto) == 3  # All should be extracted

    def test_no_proxies_in_content(self):
        """Test content with no proxies."""
        content = 'Just some regular text without any proxy links'
        mtproto, socks5 = TelegramProxyScraper.extract_proxies(content)

        assert len(mtproto) == 0
        assert len(socks5) == 0

    def test_extract_ip_port_format(self):
        """Test extracting bare IP:PORT format."""
        content = 'Proxy list:\n192.168.1.100:1080\n10.0.0.1:8080'
        mtproto, socks5 = TelegramProxyScraper.extract_proxies(content)

        assert len(socks5) > 0  # Should convert to t.me/socks format

class TestProxyValidation:
    """Test proxy validation."""

    def test_valid_mtproto_proxy(self):
        """Test validation of valid MTProto proxy."""
        url = 'https://t.me/proxy?server=1.2.3.4&port=443&secret=abcd1234'
        assert TelegramProxyScraper._is_valid_mtproto_proxy(url) is True

    def test_invalid_mtproto_missing_params(self):
        """Test validation fails for missing params."""
        url = 'https://t.me/proxy?server=1.2.3.4'  # Missing port and secret
        assert TelegramProxyScraper._is_valid_mtproto_proxy(url) is False

    def test_invalid_mtproto_bad_port(self):
        """Test validation fails for invalid port."""
        url = 'https://t.me/proxy?server=1.2.3.4&port=99999&secret=abcd'
        assert TelegramProxyScraper._is_valid_mtproto_proxy(url) is False

    def test_valid_socks5_proxy(self):
        """Test validation of valid SOCKS5 proxy."""
        url = 'https://t.me/socks?server=proxy.com&port=1080'
        assert TelegramProxyScraper._is_valid_socks5_proxy(url) is True

    def test_valid_socks5_with_auth(self):
        """Test validation of SOCKS5 with auth."""
        url = 'https://t.me/socks?server=proxy.com&port=1080&user=admin&pass=secret'
        assert TelegramProxyScraper._is_valid_socks5_proxy(url) is True

    def test_invalid_socks5_missing_port(self):
        """Test validation fails for missing port."""
        url = 'https://t.me/socks?server=proxy.com'
        assert TelegramProxyScraper._is_valid_socks5_proxy(url) is False

class TestDeduplication:
    """Test proxy deduplication."""

    def test_remove_duplicates(self):
        """Test removing duplicate proxies."""
        proxies = [
            'https://t.me/proxy?server=1.1.1.1&port=443&secret=abc',
            'https://t.me/proxy?server=2.2.2.2&port=8443&secret=def',
            'https://t.me/proxy?server=1.1.1.1&port=443&secret=abc',  # Duplicate
        ]

        unique = TelegramProxyScraper.deduplicate_proxies(proxies)

        assert len(unique) == 2

    def test_preserve_order(self):
        """Test that deduplication preserves order."""
        proxies = [
            'https://t.me/proxy?server=1.1.1.1&port=443&secret=a',
            'https://t.me/proxy?server=2.2.2.2&port=8443&secret=b',
            'https://t.me/proxy?server=1.1.1.1&port=443&secret=a',  # Duplicate
            'https://t.me/proxy?server=3.3.3.3&port=443&secret=c',
        ]

        unique = TelegramProxyScraper.deduplicate_proxies(proxies)

        assert unique[0] == proxies[0]
        assert unique[1] == proxies[1]
        assert unique[2] == proxies[3]

class TestURLConversion:
    """Test URL format conversions."""

    def test_convert_tg_to_telegram(self):
        """Test converting tg:// to t.me/proxy format."""
        tg_url = 'tg://proxy?server=1.2.3.4&port=443&secret=abc'
        result = TelegramProxyScraper._convert_tg_to_telegram_format(tg_url)

        assert result.startswith('https://t.me/proxy?')
        assert 'server=1.2.3.4' in result

    def test_convert_socks5_to_telegram(self):
        """Test converting socks5:// to t.me/socks format."""
        socks5_url = 'socks5://user:pass@proxy.com:1080'
        result = TelegramProxyScraper._convert_socks5_to_telegram_format(socks5_url)

        assert result.startswith('https://t.me/socks?')
        assert 'server=proxy.com' in result
        assert 'port=1080' in result

    def test_convert_ip_port_to_socks5(self):
        """Test converting IP:PORT to t.me/socks format."""
        ip_port = '192.168.1.1:1080'
        result = TelegramProxyScraper._convert_ip_port_to_socks5(ip_port)

        assert result.startswith('https://t.me/socks?')
        assert 'server=192.168.1.1' in result
        assert 'port=1080' in result

    def test_clean_proxy_url_removes_punctuation(self):
        """Test cleaning removes trailing punctuation."""
        url = 'https://t.me/proxy?server=1.2.3.4&port=443&secret=abc.'
        cleaned = TelegramProxyScraper._clean_proxy_url(url)

        assert not cleaned.endswith('.')

    def test_clean_proxy_url_decodes(self):
        """Test cleaning decodes URL-encoded chars."""
        url = 'https%3A%2F%2Ft.me%2Fproxy'  # URL encoded
        cleaned = TelegramProxyScraper._clean_proxy_url(url)

        assert cleaned == 'https://t.me/proxy'

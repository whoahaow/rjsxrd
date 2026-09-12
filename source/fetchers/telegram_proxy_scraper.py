"""Telegram proxy scraper module for extracting MTProto and SOCKS5 proxies."""

import re
from urllib.parse import unquote


class TelegramProxyScraper:
    """Scrapes Telegram proxy links from text content."""

    # Regex patterns for different proxy types
    MTPROTO_PATTERNS = [
        # https://t.me/proxy?server=1.2.3.4&port=443&secret=...
        r'https://t\.me/proxy\?[^\s\"\'<>]+',
        # http://t.me/proxy?server=... (without s)
        r'http://t\.me/proxy\?[^\s\"\'<>]+',
        # t.me/proxy?server=... (no protocol)
        r'(?<!://)t\.me/proxy\?[^\s\"\'<>]+',
        # tg://proxy?server=1.2.3.4&port=443&secret=...
        r'tg://proxy\?[^\s\"\'<>]+',
    ]

    SOCKS5_PATTERNS = [
        # https://t.me/socks?server=domain.com&port=1080&user=user&pass=pass
        r'https://t\.me/socks\?[^\s\"\'<>]+',
        # http://t.me/socks?server=... (without s)
        r'http://t\.me/socks\?[^\s\"\'<>]+',
        # t.me/socks?server=... (no protocol)
        r'(?<!://)t\.me/socks\?[^\s\"\'<>]+',
        # tg://socks?server=... (tg protocol)
        r'tg://socks\?[^\s\"\'<>]+',
        # Raw socks5:// format
        r'socks5://[^\s\"\'<>]+',
        # http://IP:PORT format
        r'http://(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}',
        # Bare IP:PORT format (common in proxy lists)
        r'(?:^|[\s\n])(?:(?:\d{1,3}\.){3}\d{1,3}:\d{2,5})(?:[\s\n]|$)',
    ]

    @staticmethod
    def extract_proxies(content: str) -> tuple[list[str], list[str]]:
        """
        Extract Telegram proxy links from content.

        Returns:
            Tuple[List[str], List[str]]: (mtproto_proxies, socks5_proxies)
        """
        mtproto_proxies = []
        socks5_proxies = []

        # Extract MTProto proxies
        for pattern in TelegramProxyScraper.MTPROTO_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                # Clean up the match and decode if needed
                cleaned_proxy = TelegramProxyScraper._clean_proxy_url(match)

                # Convert tg:// format to t.me/proxy format if needed
                if cleaned_proxy.startswith('tg://proxy?'):
                    converted_proxy = TelegramProxyScraper._convert_tg_to_telegram_format(cleaned_proxy)
                    if converted_proxy and TelegramProxyScraper._is_valid_mtproto_proxy(converted_proxy):
                        mtproto_proxies.append(converted_proxy)
                else:
                    if cleaned_proxy and TelegramProxyScraper._is_valid_mtproto_proxy(cleaned_proxy):
                        mtproto_proxies.append(cleaned_proxy)

        # Extract SOCKS5 proxies
        for pattern in TelegramProxyScraper.SOCKS5_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                # Clean up the match and decode if needed
                cleaned_proxy = TelegramProxyScraper._clean_proxy_url(match)

                # Convert tg://socks? format to t.me/socks format if needed
                if cleaned_proxy.startswith('tg://socks?'):
                    converted_proxy = TelegramProxyScraper._convert_tg_socks_to_telegram_format(cleaned_proxy)
                    if converted_proxy and TelegramProxyScraper._is_valid_socks5_proxy(converted_proxy):
                        socks5_proxies.append(converted_proxy)
                # Convert raw socks5:// format to t.me/socks format if needed
                elif cleaned_proxy.startswith('socks5://'):
                    converted_proxy = TelegramProxyScraper._convert_socks5_to_telegram_format(cleaned_proxy)
                    if converted_proxy and TelegramProxyScraper._is_valid_socks5_proxy(converted_proxy):
                        socks5_proxies.append(converted_proxy)
                # Convert bare IP:PORT format to t.me/socks format
                elif re.match(r'^https?://(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}$', cleaned_proxy):
                    # Extract IP and port from http(s)://IP:PORT format
                    ip_port_match = re.search(r'(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}', cleaned_proxy)
                    if ip_port_match:
                        converted_proxy = TelegramProxyScraper._convert_ip_port_to_socks5(ip_port_match.group())
                        if converted_proxy and TelegramProxyScraper._is_valid_socks5_proxy(converted_proxy):
                            socks5_proxies.append(converted_proxy)
                elif re.match(r'^(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}$', cleaned_proxy):
                    # Bare IP:PORT format
                    converted_proxy = TelegramProxyScraper._convert_ip_port_to_socks5(cleaned_proxy)
                    if converted_proxy and TelegramProxyScraper._is_valid_socks5_proxy(converted_proxy):
                        socks5_proxies.append(converted_proxy)
                else:
                    if cleaned_proxy and TelegramProxyScraper._is_valid_socks5_proxy(cleaned_proxy):
                        socks5_proxies.append(cleaned_proxy)

        return mtproto_proxies, socks5_proxies

    @staticmethod
    def _clean_proxy_url(url: str) -> str:
        """Clean and decode proxy URL if necessary."""
        # Remove trailing punctuation and quotes
        url = url.rstrip('.,;:!?)\'"').lstrip('(\'"')

        # Trim whitespace
        url = url.strip()

        # Normalize http:// to https://
        if url.startswith('http://'):
            url = 'https://' + url[7:]

        # Add https:// prefix if missing (for t.me links without protocol)
        if url.startswith('t.me/'):
            url = 'https://' + url

        # URL decode if needed
        try:
            decoded_url = unquote(url)
            if decoded_url != url:
                url = decoded_url
        except (ValueError, TypeError):
            pass

        return url

    @staticmethod
    def _convert_ip_port_to_socks5(ip_port: str) -> str:
        """Convert bare IP:PORT format to t.me/socks format."""
        # Match IP:PORT pattern
        match = re.match(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})', ip_port)
        if not match:
            return ""

        ip, port_str = match.groups()
        port = int(port_str)

        # Validate port range
        if port < 1 or port > 65535:
            return ""

        # Convert to t.me/socks format
        return f"https://t.me/socks?server={ip}&port={port}"

    @staticmethod
    def _is_valid_mtproto_proxy(url: str) -> bool:
        """Validate MTProto proxy URL format."""
        # Check if it's a valid MTProto proxy format
        if not (url.startswith('https://t.me/proxy?') or url.startswith('http://t.me/proxy?') or url.startswith('tg://proxy?')):
            return False

        # Extract parameters
        if '?' not in url:
            return False

        # Determine the parameter part depending on the URL scheme
        if url.startswith('https://t.me/proxy?') or url.startswith('tg://proxy?'):
            params = url.split('?', 1)[1]
        else:
            return False

        required_params = ['server', 'port', 'secret']

        for param in required_params:
            if f'{param}=' not in params:
                return False

        # Basic validation of server and port
        server_match = re.search(r'server=([^&]+)', params)
        port_match = re.search(r'port=(\d+)', params)

        if not server_match or not port_match:
            return False

        # Check if port is reasonable (1-65535)
        try:
            port = int(port_match.group(1))
            if port < 1 or port > 65535:
                return False
        except ValueError:
            return False

        return True

    @staticmethod
    def _convert_tg_to_telegram_format(tg_url: str) -> str:
        """Convert tg://proxy format to t.me/proxy format."""
        if not tg_url.startswith('tg://proxy?'):
            return ""

        # Extract the query parameters part
        query_params = tg_url[len('tg://proxy?'):]

        # Build the t.me/proxy URL
        telegram_url = f"https://t.me/proxy?{query_params}"

        return telegram_url

    @staticmethod
    def _convert_tg_socks_to_telegram_format(tg_url: str) -> str:
        """Convert tg://socks? format to t.me/socks format."""
        if not tg_url.startswith('tg://socks?'):
            return ""

        # Extract the query parameters part
        query_params = tg_url[len('tg://socks?'):]

        # Build the t.me/socks URL
        telegram_url = f"https://t.me/socks?{query_params}"

        return telegram_url

    @staticmethod
    def _convert_socks5_to_telegram_format(socks5_url: str) -> str:
        """Convert raw socks5:// format to t.me/socks format."""
        if not socks5_url.startswith('socks5://'):
            return ""

        # Parse the socks5 URL
        # Format: socks5://host:port or socks5://user:password@host:port
        url_parts = socks5_url[9:]  # Remove 'socks5://' prefix

        # Check if there are credentials in the URL
        if '@' in url_parts:
            auth_and_host_port = url_parts.split('@')
            auth_part = auth_and_host_port[0]
            host_port_part = auth_and_host_port[1]

            # Split auth part into username and password
            if ':' in auth_part:
                username, password = auth_part.split(':', 1)
            else:
                username = auth_part
                password = ""
        else:
            username = ""
            password = ""
            host_port_part = url_parts

        # Split host and port
        if ':' in host_port_part:
            host, port_str = host_port_part.rsplit(':', 1)  # Use rsplit to handle IPv6 addresses
        else:
            return ""  # Invalid format

        try:
            port = int(port_str)
            if port < 1 or port > 65535:
                return ""
        except ValueError:
            return ""

        # Build the t.me/socks URL
        if username and password:
            telegram_url = f"https://t.me/socks?server={host}&port={port}&user={username}&pass={password}"
        else:
            telegram_url = f"https://t.me/socks?server={host}&port={port}"

        return telegram_url

    @staticmethod
    def _is_valid_socks5_proxy(url: str) -> bool:
        """Validate SOCKS5 proxy URL format."""
        # Check if it's a valid SOCKS5 proxy format
        if not (url.startswith('https://t.me/socks?') or url.startswith('http://t.me/socks?') or url.startswith('socks5://')):
            return False

        # Handle t.me/socks format
        if url.startswith('https://t.me/socks?'):
            # Extract parameters
            if '?' not in url:
                return False

            params = url.split('?', 1)[1]
            required_params = ['server', 'port']

            for param in required_params:
                if f'{param}=' not in params:
                    return False

            # Basic validation of server and port
            server_match = re.search(r'server=([^&]+)', params)
            port_match = re.search(r'port=(\d+)', params)

            if not server_match or not port_match:
                return False

            # Check if port is reasonable (1-65535)
            try:
                port = int(port_match.group(1))
                if port < 1 or port > 65535:
                    return False
            except ValueError:
                return False

        # Handle socks5:// format
        elif url.startswith('socks5://'):
            # Parse the socks5 URL
            url_parts = url[9:]  # Remove 'socks5://' prefix

            # Check if there are credentials in the URL
            if '@' in url_parts:
                auth_and_host_port = url_parts.split('@')
                host_port_part = auth_and_host_port[1]
            else:
                host_port_part = url_parts

            # Split host and port
            if ':' in host_port_part:
                host, port_str = host_port_part.rsplit(':', 1)  # Use rsplit to handle IPv6 addresses
            else:
                return False  # Invalid format

            try:
                port = int(port_str)
                if port < 1 or port > 65535:
                    return False
            except ValueError:
                return False

        return True

    @staticmethod
    def deduplicate_proxies(proxies: list[str]) -> list[str]:
        """Remove duplicate proxies from the list."""
        seen = set()
        unique_proxies = []

        for proxy in proxies:
            if proxy not in seen:
                seen.add(proxy)
                unique_proxies.append(proxy)

        return unique_proxies

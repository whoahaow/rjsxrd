"""fetchers package — data source fetchers and converters."""

from fetchers.daily_repo_fetcher import fetch_configs_from_daily_repo, generate_dated_urls
from fetchers.fetcher import FetchResult, build_session, fetch_data
from fetchers.sstap_scraper import scrape_sstap_configs
from fetchers.telegram_proxy_scraper import TelegramProxyScraper
from fetchers.upstream_aggregator import fetch_upstream_dynamic_configs
from fetchers.yaml_converter import convert_yaml_to_vpn_configs

__all__ = [
    "FetchResult",
    "fetch_data",
    "build_session",
    "convert_yaml_to_vpn_configs",
    "TelegramProxyScraper",
    "fetch_upstream_dynamic_configs",
    "scrape_sstap_configs",
    "fetch_configs_from_daily_repo",
    "generate_dated_urls",
]

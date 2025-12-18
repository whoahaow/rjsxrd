"""Configuration settings for VPN config generator."""

import os
from datetime import datetime
import zoneinfo

# Repository settings
GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "whoahaow/rjsxrd"  # Updated repository name

# Time settings
ZONE = zoneinfo.ZoneInfo("Europe/Moscow")
THISTIME = datetime.now(ZONE)
OFFSET = THISTIME.strftime("%H:%M | %d.%m.%Y")

# URL sources - 25 sources for files 1-25
URLS = [
    "https://github.com/sakha1370/OpenRay/raw/refs/heads/main/output/all_valid_proxies.txt",  # 1
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",  # 2
    "https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt",  # 3
    "https://raw.githubusercontent.com/acymz/AutoVPN/refs/heads/main/data/V2.txt",  # 4
    "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/config.txt",  # 5
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",  # 6
    "https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/trojan.txt",  # 7
    "https://raw.githubusercontent.com/YasserDivaR/pr0xy/refs/heads/main/ShadowSocks2021.txt",  # 8
    "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt",  # 9
    "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/vless",  # 10
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",  # 11
    "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/all",  # 12
    "https://github.com/Kwinshadow/TelegramV2rayCollector/raw/refs/heads/main/sublinks/mix.txt",  # 13
    "https://github.com/LalatinaHub/Mineral/raw/refs/heads/master/result/nodes",  # 14
    "https://raw.githubusercontent.com/miladtahanian/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt",  # 15
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/refs/heads/main/sub",  # 16
    "https://github.com/MhdiTaheri/V2rayCollector_Py/raw/refs/heads/main/sub/Mix/mix.txt",  # 17
    "https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/vmess.txt",  # 18
    "https://github.com/MhdiTaheri/V2rayCollector/raw/refs/heads/main/sub/mix",  # 19
    "https://github.com/Argh94/Proxy-List/raw/refs/heads/main/All_Config.txt",  # 20
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/merged.txt",  # 21
    "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri",  # 22
    "https://raw.githubusercontent.com/AzadNetCH/Clash/refs/heads/main/AzadNet.txt",  # 23
    "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/STR.BYPASS#STR.BYPASS%F0%9F%91%BE",  # 24
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",  # 25
    "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt",  # 26
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",  # 27
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/refs/heads/main/All_Configs_Sub.txt",  # 28
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/all_extracted_configs.txt",  # 29
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/all_configs.txt",  # 30
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/refs/heads/master/sub/sub_merge.txt",  # 31
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/Best-Results/proxies.txt",  # 32
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/refs/heads/main/configtg.txt",  # 33
    "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/refs/heads/main/configs/Vless.txt",  # 34
    "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/refs/heads/main/configs/Hysteria2.txt",  # 35
    "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/refs/heads/main/configs/ShadowSocks.txt",  # 36
    "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/refs/heads/main/configs/Trojan.txt",  # 37
    "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/refs/heads/main/configs/Vmess.txt",  # 38
    "https://raw.githubusercontent.com/kort0881/vpn-key-vless/refs/heads/main/subscriptions/all.txt",  # 39
    "https://raw.githubusercontent.com/NiREvil/vless/main/sub/SSTime",  # 40
    "https://raw.githubusercontent.com/ndsphonemy/proxy-sub/refs/heads/main/all.txt",  # 41
    "https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/proxies.txt",  # 42
    "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/refs/heads/main/Reality",  # 43
    "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/all.txt",  # 44
    

]

# Extra URLs for SNI/CIDR bypass configs (after original config files)
EXTRA_URLS_FOR_BYPASS = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Cable.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://jsnegsukavsos.hb.ru-msk.vkcloud-storage.ru/love",
]

# SNI domains for filtering - Russian white-list bypass
def load_sni_domains():
    """Load SNI domains from whitelist-all.txt file."""
    config_dir = os.path.dirname(__file__)  # Get the directory of the current file
    whitelist_path = os.path.join(config_dir, 'whitelist-all.txt')
    try:
        with open(whitelist_path, 'r', encoding='utf-8') as f:
            domains = [line.strip() for line in f if line.strip()]
        return domains
    except FileNotFoundError:
        print(f"whitelist-all.txt not found at {whitelist_path}, using empty list")
        return []

SNI_DOMAINS = load_sni_domains()

# Split configuration
MAX_SERVERS_PER_FILE = 300

# Other settings
DEFAULT_MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "16"))
CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/138.0.0.0 Safari/537.36"
)
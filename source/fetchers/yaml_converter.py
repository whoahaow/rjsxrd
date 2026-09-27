"""YAML to VPN config converter module."""

import base64
from typing import Any
from urllib.parse import quote

import yaml

from utils.file_utils import is_valid_vpn_config_url
from utils.logger import log


def convert_yaml_to_vpn_configs(yaml_content: str) -> list[str]:
    """
    Convert YAML configuration to VPN config URLs (vmess://, vless://, etc.).

    Args:
        yaml_content: Raw YAML content as string

    Returns:
        List of VPN config URLs in proper format
    """
    try:
        # Parse the YAML content
        yaml_data = yaml.safe_load(yaml_content)

        if not yaml_data:
            log("YAML content is empty or invalid")
            return []

        configs = []

        # Handle different YAML structures
        if isinstance(yaml_data, dict):
            configs.extend(_extract_configs_from_dict(yaml_data))
        elif isinstance(yaml_data, list):
            for item in yaml_data:
                if isinstance(item, dict):
                    configs.extend(_extract_configs_from_dict(item))

        # Filter out invalid configs
        return [config for config in configs if is_valid_vpn_config_url(config)]

    except yaml.YAMLError as e:
        log(f"Error parsing YAML: {e}")
        return []
    except (TypeError, ValueError, KeyError) as e:
        log(f"Unexpected error converting YAML to VPN configs: {e}")
        return []


def _extract_configs_from_dict(data: dict[str, Any]) -> list[str]:
    """Extract VPN configs from a YAML dictionary."""
    configs = []

    # Check if this dictionary represents a proxy configuration
    if _is_proxy_config(data):
        config = _convert_proxy_to_url(data)
        if config:
            configs.append(config)

    # Recursively search for proxy configurations in nested structures
    for value in data.values():
        if isinstance(value, dict):
            configs.extend(_extract_configs_from_dict(value))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    configs.extend(_extract_configs_from_dict(item))

    return configs


def _is_proxy_config(data: dict[str, Any]) -> bool:
    """Check if a dictionary represents a proxy configuration."""
    # Common proxy configuration indicators
    proxy_indicators = [
        "type",  # Most proxy configs have a type field
        "server",
        "port",  # Server and port are common
        "name",  # Name is common
    ]

    # Check if it has a type field with a known proxy type
    if "type" in data and data["type"] in [
        "vmess",
        "vless",
        "trojan",
        "ss",
        "ssr",
        "tuic",
        "hysteria",
        "hysteria2",
        "hy2",
    ]:
        return True

    # Check if it has enough proxy indicators
    found_indicators = [key for key in proxy_indicators if key in data]
    return len(found_indicators) >= 2


def _convert_proxy_to_url(proxy_config: dict[str, Any]) -> str:
    """Convert a proxy configuration dictionary to a VPN URL."""
    proxy_type = proxy_config.get("type", "").lower()

    if proxy_type == "vmess":
        return _convert_vmess_to_url(proxy_config)
    if proxy_type in ["vless", "trojan", "ss", "ssr", "tuic", "hysteria", "hysteria2", "hy2"]:
        # For other types, we'll create a generic URL format
        return _convert_generic_to_url(proxy_config)
    # Try to determine the type based on available fields
    return _try_convert_to_url(proxy_config)


def _convert_vmess_to_url(config: dict[str, Any]) -> str:
    """Convert VMess config to vmess:// URL."""
    try:
        # Prepare the VMess config object
        vmess_obj = {
            "v": "2",
            "ps": config.get("name", ""),
            "add": config.get("server", ""),
            "port": str(config.get("port", "")),
            "id": config.get(
                "uuid", config.get("password", "")
            ),  # For some configs, password might be used instead of uuid
            "aid": str(config.get("alterId", 0)),
            "scy": config.get("cipher", "auto"),
            "net": config.get("network", "tcp"),
            "type": config.get("type", "none"),
            "host": config.get("host", ""),
            "path": config.get("path", ""),
            "tls": "tls" if config.get("tls", False) or config.get("ssl", False) else "",
            "sni": config.get("servername", ""),
            "alpn": config.get("alpn", ""),
            "fp": config.get("fingerprint", "chrome"),
        }

        # Clean up empty values
        vmess_obj = {k: v for k, v in vmess_obj.items() if v != ""}

        # Convert to JSON and encode as base64
        import json

        json_str = json.dumps(vmess_obj, separators=(",", ":"))
        encoded = base64.b64encode(json_str.encode()).decode()

        return f"vmess://{encoded}"
    except (TypeError, ValueError) as e:
        log(f"Error converting VMess config: {e}")
        return ""


def _convert_generic_to_url(config: dict[str, Any]) -> str:
    """Convert generic proxy config to appropriate URL format."""
    proxy_type = config.get("type", "").lower()

    if proxy_type == "vless":
        return _build_vless_url(config)
    if proxy_type == "trojan":
        return _build_trojan_url(config)
    if proxy_type in ["ss", "shadowsocks"]:
        return _build_shadowsocks_url(config)
    if proxy_type in ["ssr", "shadowsocksr"]:
        return _build_shadowsocksr_url(config)
    if proxy_type in ["tuic"]:
        return _build_tuic_url(config)
    if proxy_type in ["hysteria", "hysteria2", "hy2"]:
        return _build_hysteria_url(config)
    # Try to determine the type based on available fields
    return _try_convert_to_url(config)


def _build_vless_url(config: dict[str, Any]) -> str:
    """Build VLESS URL from config."""
    try:
        server = config.get("server", "")
        port = config.get("port", "")
        uuid = config.get("uuid", config.get("password", ""))

        if not all([server, port, uuid]):
            return ""

        # Build query parameters
        params = []

        # Network type
        network = config.get("network", "tcp")
        params.append(f"type={network}")

        # TLS settings
        if config.get("tls", False) or config.get("ssl", False):
            params.append("security=tls")
            if "servername" in config:
                params.append(f"sni={config['servername']}")
        else:
            params.append("security=none")

        # Additional network-specific options
        if network == "ws":
            if "path" in config:
                params.append(f"path={config['path']}")
            if "host" in config:
                params.append(f"host={config['host']}")
        elif network == "grpc":
            if "serviceName" in config:
                params.append(f"serviceName={config['serviceName']}")

        # Add other parameters as needed
        if "flow" in config:
            params.append(f"flow={config['flow']}")

        query = "&".join(params)
        return f"vless://{uuid}@{server}:{port}?{query}#{config.get('name', 'VLESS Config')}"
    except (TypeError, ValueError) as e:
        log(f"Error building VLESS URL: {e}")
        return ""


def _build_trojan_url(config: dict[str, Any]) -> str:
    """Build Trojan URL from config."""
    try:
        server = config.get("server", "")
        port = config.get("port", "")
        password = config.get("password", config.get("uuid", ""))

        if not all([server, port, password]):
            return ""

        # Build query parameters
        params = []

        # TLS settings
        if config.get("tls", True):
            params.append("security=tls")
            if "sni" in config:
                params.append(f"sni={config['sni']}")
            elif "servername" in config:
                params.append(f"sni={config['servername']}")
        else:
            params.append("security=none")

        # Network type
        network = config.get("network", "tcp")
        params.append(f"type={network}")

        # Additional network-specific options
        if network == "ws":
            if "path" in config:
                params.append(f"path={config['path']}")
            if "host" in config:
                params.append(f"host={config['host']}")

        query = "&".join(params)
        return f"trojan://{password}@{server}:{port}?{query}#{config.get('name', 'Trojan Config')}"
    except (TypeError, ValueError) as e:
        log(f"Error building Trojan URL: {e}")
        return ""


def _build_shadowsocks_url(config: dict[str, Any]) -> str:
    """Build Shadowsocks URL from config."""
    try:
        server = config.get("server", "")
        port = config.get("port", "")
        password = config.get("password", "")
        cipher = config.get("cipher", "chacha20-ietf-poly1305")

        if not all([server, port, password, cipher]):
            return ""

        # Encode the credentials
        credentials = f"{cipher}:{password}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()

        return (
            f"ss://{encoded_credentials}@{server}:{port}#{config.get('name', 'Shadowsocks Config')}"
        )
    except (TypeError, ValueError) as e:
        log(f"Error building Shadowsocks URL: {e}")
        return ""


def _build_shadowsocksr_url(config: dict[str, Any]) -> str:
    """Build ShadowsocksR URL from config."""
    try:
        server = config.get("server", "")
        port = config.get("port", "")
        password = config.get("password", "")
        cipher = config.get("cipher", "chacha20-ietf-poly1305")
        protocol = config.get("protocol", "origin")
        obfs = config.get("obfs", "plain")

        if not all([server, port, password, cipher]):
            return ""

        # The SSR link is one urlsafe-base64 token: the colon-separated fields,
        # their `/?` parameter tail, and the password base64'd inside all of that.
        # Emitting those fields in the open leaves a string that starts with `ssr://`
        # and is not one -- every reader decodes the authority as base64, finds the
        # `:` and `_` of a hostname are not the alphabet's, and answers None. So the
        # node is published without ever being verified, and the security filter
        # cannot see the cipher to call it weak.
        def _b64(value: str) -> str:
            return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")

        fields = f"{server}:{port}:{protocol}:{cipher}:{obfs}:{_b64(password)}"
        query_parts = []
        if "name" in config:
            query_parts.append(f"remarks={_b64(str(config['name']))}")
        if query_parts:
            fields += "/?" + "&".join(query_parts)

        return f"ssr://{_b64(fields)}"
    except (TypeError, ValueError) as e:
        log(f"Error building ShadowsocksR URL: {e}")
        return ""


def _build_tuic_url(config: dict[str, Any]) -> str:
    """Build TUIC URL from config."""
    try:
        server = config.get("server", "")
        port = config.get("port", "")
        uuid = config.get("uuid", "")
        password = config.get("password", "")

        if not all([server, port, uuid]):
            return ""

        # Build query parameters
        params = []

        # TLS settings
        params.append("security=tls")
        if "sni" in config:
            params.append(f"sni={config['sni']}")

        # UDP relay mode
        if "udp_relay_mode" in config:
            params.append(f"udp={config['udp_relay_mode']}")

        # Congestion control
        if "congestion_control" in config:
            params.append(f"congestion_control={config['congestion_control']}")

        query = "&".join(params)

        # Use password if available, otherwise just uuid
        auth = f"{uuid}:{password}" if password else uuid
        return f"tuic://{auth}@{server}:{port}?{query}#{config.get('name', 'TUIC Config')}"
    except (TypeError, ValueError) as e:
        log(f"Error building TUIC URL: {e}")
        return ""


def _build_hysteria_url(config: dict[str, Any]) -> str:
    """Build a Hysteria URL from a Clash proxy dict.

    The version decides the scheme, and it is not cosmetic: Clash's `hysteria`
    speaks v1 and `hysteria2` speaks v2, while xray only implements v2. Labelling
    everything `hysteria2://` — which is what this did — sent v1 nodes off as
    version-2 configs whose parameters would then be ignored, so they failed
    verification like dead servers. Emitted as `hysteria://` instead, the
    compatibility filter refuses them with the real reason.

    The auth token goes in the userinfo, where the hysteria2 URI scheme puts it,
    and only parameters the scheme defines are written: `type=webtransport` was a
    guess that no parser reads, and the bandwidth parameters belong to v1.
    """
    try:
        server = config.get("server", "")
        port = config.get("port", "")

        if not all([server, port]):
            return ""

        is_v2 = str(config.get("type", "")).lower() in ("hysteria2", "hy2")
        scheme = "hysteria2" if is_v2 else "hysteria"

        auth = config.get("auth_str") or config.get("password") or config.get("obfs-password")
        # Token in the userinfo for both versions; v1 also accepts auth_str.
        userinfo = f"{quote(str(auth), safe='')}@" if auth else ""

        params: list[str] = []
        if is_v2:
            if "sni" in config:
                params.append(f"sni={quote(str(config['sni']), safe='')}")
            if "obfs" in config:
                params.append(f"obfs={quote(str(config['obfs']), safe='')}")
            if "obfs-password" in config:
                params.append(f"obfs-password={quote(str(config['obfs-password']), safe='')}")
            if config.get("skip-cert-verify"):
                params.append("insecure=1")
            if "pinSHA256" in config:
                params.append(f"pinSHA256={quote(str(config['pinSHA256']), safe='')}")
        else:
            if "protocol" in config:
                params.append(f"protocol={quote(str(config['protocol']), safe='')}")
            if "sni" in config:
                params.append(f"sni={quote(str(config['sni']), safe='')}")
            if config.get("insecure"):
                params.append("insecure=1")
            if "up" in config:
                params.append(f"upmbps={quote(str(config['up']), safe='')}")
            if "down" in config:
                params.append(f"downmbps={quote(str(config['down']), safe='')}")

        query = f"?{'&'.join(params)}" if params else ""
        name = config.get("name", "Hysteria2 Config" if is_v2 else "Hysteria Config")
        return f"{scheme}://{userinfo}{server}:{port}/{query}#{quote(str(name), safe='')}"
    except (TypeError, ValueError) as e:
        log(f"Error building Hysteria URL: {e}")
        return ""


def _try_convert_to_url(config: dict[str, Any]) -> str:
    """Try to determine the proxy type and convert to URL."""
    # Try to identify the type based on available fields
    if "uuid" in config and "security" in config:
        # Likely a VLESS config
        config["type"] = "vless"
        return _build_vless_url(config)
    if "password" in config and "sni" in config:
        # Likely a Trojan config
        config["type"] = "trojan"
        return _build_trojan_url(config)
    if "cipher" in config and "password" in config:
        # Likely a Shadowsocks config
        config["type"] = "ss"
        return _build_shadowsocks_url(config)
    # Cannot determine the type
    return ""

"""YAML to VPN config converter module."""

import yaml
import base64
from typing import List, Dict, Any
from utils.logger import log
from utils.file_utils import is_valid_vpn_config_url


def convert_yaml_to_vpn_configs(yaml_content: str) -> List[str]:
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
        valid_configs = [config for config in configs if is_valid_vpn_config_url(config)]
        
        return valid_configs
        
    except yaml.YAMLError as e:
        log(f"Error parsing YAML: {e}")
        return []
    except Exception as e:
        log(f"Unexpected error converting YAML to VPN configs: {e}")
        return []


def _extract_configs_from_dict(data: Dict[str, Any]) -> List[str]:
    """Extract VPN configs from a YAML dictionary."""
    configs = []
    
    # Check if this dictionary represents a proxy configuration
    if _is_proxy_config(data):
        config = _convert_proxy_to_url(data)
        if config:
            configs.append(config)
    
    # Recursively search for proxy configurations in nested structures
    for key, value in data.items():
        if isinstance(value, dict):
            configs.extend(_extract_configs_from_dict(value))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    configs.extend(_extract_configs_from_dict(item))
    
    return configs


def _is_proxy_config(data: Dict[str, Any]) -> bool:
    """Check if a dictionary represents a proxy configuration."""
    # Common proxy configuration indicators
    proxy_indicators = [
        'type',  # Most proxy configs have a type field
        'server', 'port',  # Server and port are common
        'name',  # Name is common
    ]
    
    # Check if it has a type field with a known proxy type
    if 'type' in data and data['type'] in ['vmess', 'vless', 'trojan', 'ss', 'ssr', 'tuic', 'hysteria', 'hysteria2', 'hy2']:
        return True
    
    # Check if it has enough proxy indicators
    found_indicators = [key for key in proxy_indicators if key in data]
    return len(found_indicators) >= 2


def _convert_proxy_to_url(proxy_config: Dict[str, Any]) -> str:
    """Convert a proxy configuration dictionary to a VPN URL."""
    proxy_type = proxy_config.get('type', '').lower()
    
    if proxy_type == 'vmess':
        return _convert_vmess_to_url(proxy_config)
    elif proxy_type in ['vless', 'trojan', 'ss', 'ssr', 'tuic', 'hysteria', 'hysteria2', 'hy2']:
        # For other types, we'll create a generic URL format
        return _convert_generic_to_url(proxy_config)
    else:
        # Try to determine the type based on available fields
        return _try_convert_to_url(proxy_config)


def _convert_vmess_to_url(config: Dict[str, Any]) -> str:
    """Convert VMess config to vmess:// URL."""
    try:
        # Prepare the VMess config object
        vmess_obj = {
            'v': '2',
            'ps': config.get('name', ''),
            'add': config.get('server', ''),
            'port': str(config.get('port', '')),
            'id': config.get('uuid', config.get('password', '')),  # For some configs, password might be used instead of uuid
            'aid': str(config.get('alterId', 0)),
            'scy': config.get('cipher', 'auto'),
            'net': config.get('network', 'tcp'),
            'type': config.get('type', 'none'),
            'host': config.get('host', ''),
            'path': config.get('path', ''),
            'tls': 'tls' if config.get('tls', False) or config.get('ssl', False) else '',
            'sni': config.get('servername', ''),
            'alpn': config.get('alpn', ''),
            'fp': config.get('fingerprint', 'chrome'),
        }
        
        # Clean up empty values
        vmess_obj = {k: v for k, v in vmess_obj.items() if v != ''}
        
        # Convert to JSON and encode as base64
        import json
        json_str = json.dumps(vmess_obj, separators=(',', ':'))
        encoded = base64.b64encode(json_str.encode()).decode()
        
        return f"vmess://{encoded}"
    except Exception as e:
        log(f"Error converting VMess config: {e}")
        return ""


def _convert_generic_to_url(config: Dict[str, Any]) -> str:
    """Convert generic proxy config to appropriate URL format."""
    proxy_type = config.get('type', '').lower()
    
    if proxy_type == 'vless':
        return _build_vless_url(config)
    elif proxy_type == 'trojan':
        return _build_trojan_url(config)
    elif proxy_type in ['ss', 'shadowsocks']:
        return _build_shadowsocks_url(config)
    elif proxy_type in ['ssr', 'shadowsocksr']:
        return _build_shadowsocksr_url(config)
    elif proxy_type in ['tuic']:
        return _build_tuic_url(config)
    elif proxy_type in ['hysteria', 'hysteria2', 'hy2']:
        return _build_hysteria_url(config)
    else:
        # Try to determine the type based on available fields
        return _try_convert_to_url(config)


def _build_vless_url(config: Dict[str, Any]) -> str:
    """Build VLESS URL from config."""
    try:
        server = config.get('server', '')
        port = config.get('port', '')
        uuid = config.get('uuid', config.get('password', ''))
        
        if not all([server, port, uuid]):
            return ""
        
        # Build query parameters
        params = []
        
        # Network type
        network = config.get('network', 'tcp')
        params.append(f"type={network}")
        
        # TLS settings
        if config.get('tls', False) or config.get('ssl', False):
            params.append("security=tls")
            if 'servername' in config:
                params.append(f"sni={config['servername']}")
        else:
            params.append("security=none")
        
        # Additional network-specific options
        if network == 'ws':
            if 'path' in config:
                params.append(f"path={config['path']}")
            if 'host' in config:
                params.append(f"host={config['host']}")
        elif network == 'grpc':
            if 'serviceName' in config:
                params.append(f"serviceName={config['serviceName']}")
        
        # Add other parameters as needed
        if 'flow' in config:
            params.append(f"flow={config['flow']}")
        
        query = "&".join(params)
        return f"vless://{uuid}@{server}:{port}?{query}#{config.get('name', 'VLESS Config')}"
    except Exception as e:
        log(f"Error building VLESS URL: {e}")
        return ""


def _build_trojan_url(config: Dict[str, Any]) -> str:
    """Build Trojan URL from config."""
    try:
        server = config.get('server', '')
        port = config.get('port', '')
        password = config.get('password', config.get('uuid', ''))
        
        if not all([server, port, password]):
            return ""
        
        # Build query parameters
        params = []
        
        # TLS settings
        if config.get('tls', True):
            params.append("security=tls")
            if 'sni' in config:
                params.append(f"sni={config['sni']}")
            elif 'servername' in config:
                params.append(f"sni={config['servername']}")
        else:
            params.append("security=none")
        
        # Network type
        network = config.get('network', 'tcp')
        params.append(f"type={network}")
        
        # Additional network-specific options
        if network == 'ws':
            if 'path' in config:
                params.append(f"path={config['path']}")
            if 'host' in config:
                params.append(f"host={config['host']}")
        
        query = "&".join(params)
        return f"trojan://{password}@{server}:{port}?{query}#{config.get('name', 'Trojan Config')}"
    except Exception as e:
        log(f"Error building Trojan URL: {e}")
        return ""


def _build_shadowsocks_url(config: Dict[str, Any]) -> str:
    """Build Shadowsocks URL from config."""
    try:
        server = config.get('server', '')
        port = config.get('port', '')
        password = config.get('password', '')
        cipher = config.get('cipher', 'chacha20-ietf-poly1305')
        
        if not all([server, port, password, cipher]):
            return ""
        
        # Encode the credentials
        credentials = f"{cipher}:{password}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        
        return f"ss://{encoded_credentials}@{server}:{port}#{config.get('name', 'Shadowsocks Config')}"
    except Exception as e:
        log(f"Error building Shadowsocks URL: {e}")
        return ""


def _build_shadowsocksr_url(config: Dict[str, Any]) -> str:
    """Build ShadowsocksR URL from config."""
    try:
        server = config.get('server', '')
        port = config.get('port', '')
        password = config.get('password', '')
        cipher = config.get('cipher', 'chacha20-ietf-poly1305')
        protocol = config.get('protocol', 'origin')
        obfs = config.get('obfs', 'plain')
        
        if not all([server, port, password, cipher]):
            return ""
        
        # Build the SSR URL format
        # ssr://server:port:protocol:method:obfs:base64encode(password)/?remarks=base64encode(remarks)&protoparam=base64encode(protoparam)&obfsparam=base64encode(obfsparam)
        
        params = f"{server}:{port}:{protocol}:{cipher}:{obfs}:{base64.b64encode(password.encode()).decode()}"
        
        # Add query parameters
        query_parts = []
        if 'name' in config:
            query_parts.append(f"remarks={base64.b64encode(config['name'].encode()).decode()}")
        
        url = f"ssr://{params}/?" + "&".join(query_parts)
        return url
    except Exception as e:
        log(f"Error building ShadowsocksR URL: {e}")
        return ""


def _build_tuic_url(config: Dict[str, Any]) -> str:
    """Build TUIC URL from config."""
    try:
        server = config.get('server', '')
        port = config.get('port', '')
        uuid = config.get('uuid', '')
        password = config.get('password', '')
        
        if not all([server, port, uuid]):
            return ""
        
        # Build query parameters
        params = []
        
        # TLS settings
        params.append("security=tls")
        if 'sni' in config:
            params.append(f"sni={config['sni']}")
        
        # UDP relay mode
        if 'udp_relay_mode' in config:
            params.append(f"udp={config['udp_relay_mode']}")
        
        # Congestion control
        if 'congestion_control' in config:
            params.append(f"congestion_control={config['congestion_control']}")
        
        query = "&".join(params)
        
        # Use password if available, otherwise just uuid
        auth = f"{uuid}:{password}" if password else uuid
        return f"tuic://{auth}@{server}:{port}?{query}#{config.get('name', 'TUIC Config')}"
    except Exception as e:
        log(f"Error building TUIC URL: {e}")
        return ""


def _build_hysteria_url(config: Dict[str, Any]) -> str:
    """Build Hysteria URL from config."""
    try:
        server = config.get('server', '')
        port = config.get('port', '')
        
        if not all([server, port]):
            return ""
        
        # Build query parameters
        params = []
        
        # Authentication
        if 'auth_str' in config:
            params.append(f"auth={config['auth_str']}")
        elif 'password' in config:
            params.append(f"auth={config['password']}")
        
        # TLS settings
        if 'sni' in config:
            params.append(f"sni={config['sni']}")
        
        # Obfs
        if 'obfs' in config:
            params.append(f"obfs={config['obfs']}")
        
        # Up/Down bandwidth
        if 'up_mbps' in config:
            params.append(f"upmbps={config['up_mbps']}")
        if 'down_mbps' in config:
            params.append(f"downmbps={config['down_mbps']}")
        
        # Protocol (for hysteria2)
        if config.get('type', '').lower() in ['hysteria2', 'hy2']:
            params.append("type=webtransport")  # Default type for hysteria2
        
        query = "&".join(params)
        return f"hysteria2://{server}:{port}?{query}#{config.get('name', 'Hysteria Config')}"
    except Exception as e:
        log(f"Error building Hysteria URL: {e}")
        return ""


def _try_convert_to_url(config: Dict[str, Any]) -> str:
    """Try to determine the proxy type and convert to URL."""
    # Try to identify the type based on available fields
    if 'uuid' in config and 'security' in config:
        # Likely a VLESS config
        config['type'] = 'vless'
        return _build_vless_url(config)
    elif 'password' in config and 'sni' in config:
        # Likely a Trojan config
        config['type'] = 'trojan'
        return _build_trojan_url(config)
    elif 'cipher' in config and 'password' in config:
        # Likely a Shadowsocks config
        config['type'] = 'ss'
        return _build_shadowsocks_url(config)
    else:
        # Cannot determine the type
        return ""
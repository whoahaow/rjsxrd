"""File handling utilities."""

import os
from typing import List, Set
import re
import base64
import json
from utils.logger import log


def save_to_local_file(path: str, content: str):
    """Saves content to a local file."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as file:
        file.write(content)
    log(f"Данные сохранены локально в {path}")


def load_from_local_file(path: str) -> str:
    """Loads content from a local file."""
    if not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8") as file:
        return file.read()


def split_config_file(content: str, max_lines_per_file: int = 300) -> List[str]:
    """Splits a config file content into smaller parts."""
    lines = content.strip().split('\n')
    # Remove empty lines
    lines = [line.strip() for line in lines if line.strip()]
    
    chunks = []
    for i in range(0, len(lines), max_lines_per_file):
        chunk = '\n'.join(lines[i:i + max_lines_per_file])
        chunks.append(chunk)
    
    return chunks


def extract_host_port(line: str):
    """Extracts host and port from a config line."""
    if not line: 
        return None
    if line.startswith("vmess://"):
        try:
            payload = line[8:]
            rem = len(payload) % 4
            if rem: 
                payload += '=' * (4 - rem)
            decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
            if decoded.startswith('{'):
                j = json.loads(decoded)
                host = j.get('add') or j.get('host') or j.get('ip')
                port = j.get('port')
                if host and port: 
                    return str(host), str(port)
        except Exception: 
            pass
        return None
    m = re.search(r'(?:@|//)([\w\.-]+):(\d{1,5})', line)
    if m: 
        return m.group(1), m.group(2)
    return None


def deduplicate_configs(configs: List[str]) -> List[str]:
    """Deduplicates configs based on host:port combination."""
    seen_full = set()
    seen_hostport = set()
    unique_configs = []

    for cfg in configs:
        c = cfg.strip()
        if not c or c in seen_full: 
            continue
        seen_full.add(c)

        hostport = extract_host_port(c)
        if hostport:
            key = f"{hostport[0].lower()}:{hostport[1]}"
            if key in seen_hostport: 
                continue
            seen_hostport.add(key)
        unique_configs.append(c)

    return unique_configs


def prepare_config_content(content: str) -> List[str]:
    """Prepares and normalizes config content by separating glued configs."""
    # Add newlines before known protocol prefixes that might be glued to previous lines
    content = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2|hy2)://', r'\n\1://', content)
    lines = content.splitlines()
    # Filter out empty lines and comments
    configs = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith('#'):
            configs.append(line)
    return configs
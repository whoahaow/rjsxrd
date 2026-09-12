"""Worker function for the SNI/CIDR filter.

Lives in a separate module so it can be pickled to subprocess workers
without needing to re-import the parent module that owns the dispatch
function. This is a standard pattern for multiprocessing in Python.
"""
import ipaddress

# Cross-module imports (normal — worker imports from file_utils, not itself).
# _VPN_PROTOCOL_PATTERN is the single source of truth in file_utils.
# extract_host_port is the dispatch-based host/port extractor.
from utils.file_utils import _VPN_PROTOCOL_PATTERN, extract_host_port
from utils.security_filter import has_insecure_setting


def _filter_sni_cidr_chunk(args) -> list[str]:
    """Filter one chunk of configs by SNI domain whitelist + CIDR whitelist.

    Module-level for pickling (multiprocessing). Receives a single tuple
    so executor.map() can pass it directly without unpacking.
    """
    chunk, automaton, cidr_whitelist, filter_secure = args

    result = []
    for config in chunk:
        try:
            if not _VPN_PROTOCOL_PATTERN.match(config):
                continue
            if filter_secure and has_insecure_setting(config):
                continue
            # Call extract_host_port ONCE. The previous code called it twice
            # (directly + via extract_ip_from_config), decoding each config's
            # URL twice. Now we use the result for both SNI and CIDR checks.
            host_port = extract_host_port(config)
            if not host_port:
                continue
            host, _ = host_port
            # Try parsing host as a literal IP (no re-parsing the URL).
            ip = None
            try:
                ip = str(ipaddress.ip_address(host))
            except (ValueError, ipaddress.AddressValueError):
                ip = None

            if host and automaton and automaton.find_matches_as_strings(host.lower()):
                result.append(config)
                continue
            if ip and cidr_whitelist and ip in cidr_whitelist:
                result.append(config)
                continue
        except (ValueError, IndexError, TypeError):
            continue
    return result

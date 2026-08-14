> **Language:** [Русский](proxy-chains.md) · [English](proxy-chains.en.md)

# Proxy chains

Support for multi-level routing through Xray `dialerProxy`. Allows you to route traffic through a chain of several VLESS servers within one Xray process.

**Status:** experimental feature.

## Architecture

```
App → Xray (SOCKS5 :22000)
                  ↓
             VLESS Hop 1 (chain-0)
                  ↓ dialerProxy="chain-1"
             VLESS Hop 2 (chain-1)
                  ↓
              Internet
```

## Usage

```bash
python main.py --proxy-chain="vless://hop1,vless://hop2,vless://hop3"
```

**Requirements:**
- Minimum 2 proxies in the chain
- All proxies must be of the same type (VLESS or VMess)

### Supported transports

| Transport | Compatibility |
|-----------|---------------|
| VLESS + WebSocket + TLS | ✅ Full |
| VLESS + HTTPUpgrade + TLS | ✅ Full |
| VMess + WebSocket + TLS | ✅ Full |
| VLESS + Reality | ❌ Incompatible with dialerProxy |
| VLESS + TCP | ⚠️ Possible issues |

**Important:** Reality does not work with `dialerProxy` due to the specifics of the transport mechanism at the socket level.

## URL format for compatible configs

```
vless://uuid@example.com:443?encryption=none&security=tls&type=ws&host=example.com&path=%2F
```

## Implementation

The `create_chain_config()` function in `source/utils/xray_tester.py`:

1. Reverses the hop order for correct routing
2. Generates an Xray config with multiple outbounds and `dialerProxy`
3. Launches one Xray process with a single SOCKS5 inbound
4. Monitors connection stability in a background thread (every 30 s)

## Limitations

- The first hop sees your real IP
- The Reality protocol is not supported
- The feature is experimental, issues with individual servers are possible

## ProxyMonitor — chain monitoring

When a proxy chain is launched, a `ProxyMonitor` is created in a background thread:

- **Check interval:** every 30 s
- **What it checks:** the chain's SOCKS port via an HTTP request to `https://www.gstatic.com/generate_204`
- **IP comparison:** requests the external IP through the chain and compares it with the real IP (without the proxy)
- **Registration:** registered in the unified `ProcessRegistry` (`register_monitor()`) for correct graceful shutdown — during cleanup, monitors are stopped before the Xray processes are terminated
- **Stopping:** when `main.py` finishes, the monitor is stopped before the Xray processes are killed

## Troubleshooting

**The chain only exits through the first hop:**
Check the transport — Reality is probably being used. Switch to WebSocket.

**The connection drops immediately:**
Check the path (`path`) and host (`host`) in each URL. Make sure TLS is enabled (the `security=tls` parameter).

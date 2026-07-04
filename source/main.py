"""Main module for VPN config generator with refactored, streamlined logic."""

import os
import sys
import argparse
import signal
from typing import Optional, List, Tuple, Any

from utils.logger import log, print_logs
from utils.download_xray import ensure_xray_installed
from processors.config_processor import process_all_configs
from utils.github_handler import GitHubHandler
from utils.proxy_detector import find_active_proxy_port
from utils.ip_verifier import verify_protection
from utils.resource_monitor import start_monitoring, stop_monitoring, print_resource_report
from utils.process_registry import default_registry, install_signal_handler

import requests

from utils.telegram_notifier import notify_start, notify_success, notify_error


def _signal_handler(signum, frame) -> None:
    """Handle SIGINT/SIGTERM for graceful shutdown."""
    log("\nInterrupted, cleaning up...")

    # Stop resource monitoring
    stop_monitoring()

    # Stop proxy monitors before killing Xray (they depend on SOCKS port).
    # ProxyMonitor instances are tracked in the shared ProcessRegistry, so
    # default_registry.cleanup(force=True) at the bottom handles them.
    # But we need to stop them BEFORE the xray processes, so do it explicitly
    # here in the signal handler.
    from utils.process_registry import default_registry as registry
    # The registry's cleanup() stops monitors first, then processes.
    # Run monitor-only cleanup here so xray cleanup via force=True below
    # doesn't attempt monitor cleanup again (registry is cleared after first call).
    registry.cleanup(force=True)

    # Force-cleanup all tracked xray processes (the shared registry also
    # restores proxy env vars via its registered callbacks).
    default_registry.cleanup(force=True)

    # Give cleanup 2 seconds to complete
    import time
    time.sleep(2)

    log("Cleanup complete, exiting...")
    sys.exit(0)


def register_signal_handlers() -> None:
    """Register signal handlers and init runtime environment. Idempotent."""
    os.environ['PYTHONUNBUFFERED'] = '1'
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(line_buffering=True)
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    # Also install process_registry's atexit cleanup (runs on normal exit).
    # This is safe — install_signal_handler() won't override main.py's
    # signal handlers (it checks getsignal first), but WILL register the
    # atexit fallback so the shared registry cleanup runs even on clean exit.
    install_signal_handler()


def _setup_proxy_and_monitoring(
    proxy_chain: Optional[str],
    proxy_url: Optional[str],
    no_proxy_check: bool,
) -> Tuple[Optional[int], bool, Any]:
    """Set up proxy chain, single proxy, or auto-detect.

    Returns:
        Tuple of (socks_port, cleanup_needed, proxy_monitor).
        Calls sys.exit(1) on fatal proxy setup failure.
    """
    proxy_socks_port = None
    proxy_cleanup_needed = False
    proxy_monitor = None

    if proxy_chain:
        chain_list = [p.strip() for p in proxy_chain.split(',') if p.strip()]
        if len(chain_list) < 2:
            log("ERROR: --proxy-chain requires at least 2 comma-separated proxy URLs")
            sys.exit(1)

        log(f"Setting up proxy chain: {len(chain_list)} hops (EXPERIMENTAL)")
        from utils.proxy_monitor import ProxyMonitor
        from utils.ip_verifier import setup_proxy_chain
        result = setup_proxy_chain(chain_list, timeout=8.0)

        if result['active']:
            proxy_cleanup_needed = True
            log(f"[OK] Proxy chain SUCCESSFUL: {result['proxy_ip']} ({result.get('country', 'Unknown')})")
            if result.get('socks_port'):
                proxy_socks_port = result['socks_port']
                log(f"[OK] SOCKS proxy on port {proxy_socks_port}")

            proxy_monitor = ProxyMonitor(result['socks_port'], result['real_ip'], check_interval=30)
            proxy_monitor.start()
            log("\nProxy chain active (EXPERIMENTAL), starting config generation...\n")
        else:
            log("[FAIL] FAILED to setup proxy chain!")
            if result.get('error'):
                log(f"  Error: {result['error']}")
            log("\nPossible causes:")
            log("  • One of the proxy servers is offline or unreachable")
            log("  • Network connectivity issues")
            log("  • Invalid proxy configuration")
            log("\nWhat to do:")
            log("  1. Check that both proxy servers are working")
            log("  2. Try different proxy servers")
            log("  3. Run the command again with new proxies")
            log("\nExample:")
            log("  python main.py --proxy-chain=\"vless://new1@server1:443,vless://new2@server2:443\"")
            sys.exit(1)

    elif proxy_url:
        log(f"Setting up proxy: {proxy_url.split('://')[0]}://***...")
        from utils.ip_verifier import setup_global_proxy
        result = setup_global_proxy(proxy_url, timeout=8.0)

        if result['active']:
            proxy_cleanup_needed = True
            log(f"[OK] Proxy connection SUCCESSFUL: {result['proxy_ip']} ({result.get('country', 'Unknown')})")
            if result.get('socks_port'):
                proxy_socks_port = result['socks_port']
                log(f"[OK] SOCKS proxy running on port {proxy_socks_port}")
        else:
            log("[FAIL] FAILED to connect through proxy!")
            if result.get('error'):
                log(f"  Error: {result['error']}")
            log("ERROR: Proxy verification failed. Check your config and try again.")
            sys.exit(1)

    elif not no_proxy_check:
        log("Checking for active proxy...")
        proxy_port = find_active_proxy_port()

        if proxy_port:
            log(f"Proxy detected on port {proxy_port}")
            log("Verifying proxy protection...")
            protection = verify_protection(proxy_port=proxy_port, timeout=5.0)

            if protection['active']:
                log(f"Proxy protection ACTIVE: {protection['proxy_ip']} ({protection.get('country', 'Unknown')})")
            else:
                log("WARNING: Proxy not protecting IP!")
                log(f"  Proxy IP: {protection['proxy_ip']}")
                log("  IPs are the same - proxy may not be working!")
                log("Continuing anyway (use --no-proxy-check to skip this check)")
        else:
            log("WARNING: No active proxy detected on common ports (10808, 2080, 7890, etc.)")
            log("Connect to VPN first, or use --proxy=<url> or --no-proxy-check")

    return proxy_socks_port, proxy_cleanup_needed, proxy_monitor


def _run_pipeline_and_upload(
    output_dir: str,
    skip_xray: bool,
    tcp_ping: bool,
    verbose: bool,
    flag_overrides: Optional[dict],
    dry_run: bool,
    use_git: bool,
) -> bool:
    """Run the config pipeline and upload results.

    If not dry_run and not use_git: uploads files progressively during
    verification (every 300 working configs). Falls back to single batch
    upload at the end for any remaining files.

    Returns True if pipeline completed without upload errors.
    Calls sys.exit(1) on upload failures.
    """
    upload_fn = None
    github_handler = None
    updater = None

    if not dry_run and use_git:
        from utils.git_updater import GitUpdater
        updater = GitUpdater()
        def upload_fn(local_path: str, remote_path: str) -> None:
            """Commit + push file progressively so it appears on GitHub live,
            mid-verification. These auto commits are squashed at the end by
            commit_and_push_files."""
            try:
                filename = remote_path.split("/")[-1]
                updater.commit_and_push_single(local_path, f"auto: update {filename}")
            except Exception as e:
                log(f"Warning: progressive push failed for {local_path}: {e}")
    elif not dry_run:
        github_handler = GitHubHandler()
        def upload_fn(local_path: str, remote_path: str) -> None:
            github_handler.upload_file(local_path, remote_path)

    file_pairs = process_all_configs(
        output_dir, skip_xray=skip_xray, tcp_ping=tcp_ping,
        verbose=verbose, flag_overrides=flag_overrides,
        upload_fn=upload_fn,
    )

    pipeline_ok = False
    if not dry_run and file_pairs:
        if use_git:
            assert updater is not None
            # Progressively staged files are already in the index.
            # commit_and_push_files handles commit + push with auto-cleanup.
            success = updater.commit_and_push_files(file_pairs)
            if not success:
                log("ERROR: Git update failed")
                notify_error("Git update failed")
                sys.exit(1)
        else:
            # Upload remaining files (pre-verify was already uploaded,
            # progressive files were already uploaded — this catches
            # bypass-all.txt, URLS.txt, servers.txt, and any files that
            # were overwritten by the final verification step)
            failures = github_handler.upload_multiple_files(file_pairs)
            if failures > 0:
                log(f"ERROR: {failures} upload(s) failed")
                notify_error(f"{failures} upload(s) failed")
                sys.exit(1)
    pipeline_ok = True

    return pipeline_ok


def main(
    dry_run: bool = False,
    output_dir: str = "../githubmirror",
    skip_xray: bool = False,
    use_git: bool = False,
    no_proxy_check: bool = False,
    proxy_url: str = None,
    proxy_chain: str = None,
    tcp_ping: bool = False,
    verbose: bool = False,
    flag_overrides: dict = None,
) -> None:
    """Main execution function.

    Args:
        dry_run: Only download and save locally, don't upload/commit
        output_dir: Output directory for generated files
        skip_xray: Skip Xray-core download/use (TCP-only verification)
        use_git: Use git commands for committing instead of GitHub API
        no_proxy_check: Skip proxy detection/verification
        proxy_url: Single proxy URL to use
        proxy_chain: Comma-separated proxy chain (proxy1,proxy2)
        tcp_ping: Use TCP ping instead of Xray-core (faster, less accurate).
                   Implies --skip-xray.
        verbose: Enable verbose logging (e.g., skipped config details)
        flag_overrides: Optional dict overriding the 5 feature flags from
                       settings.py. None = use defaults.
    """
    # --tcp-ping implies --skip-xray
    if tcp_ping and skip_xray:
        log("Note: --tcp-ping implies --skip-xray; --skip-xray is redundant but consistent.")
    if tcp_ping:
        skip_xray = True

    # Health check before starting
    from utils.health_check import health_check, print_health_report
    xray_path = ensure_xray_installed() if not skip_xray else None
    health_results = health_check(xray_path=str(xray_path) if xray_path else None)
    print_health_report(health_results)

    if not health_results.get('internet'):
        log("WARNING: No internet connectivity detected — upload will fail, generating configs anyway")
        log("  Check DNS servers (DNS_SERVERS in health_check.py) if this is unexpected")

    # Start resource monitoring
    start_monitoring(sample_interval=2.0)
    log("Starting VPN config generation...")
    log("Resource monitoring active (CPU, RAM, Network)")
    notify_start()

    # Setup proxy (chain, single, or auto-detect)
    # Must be inside try/finally so stop_monitoring + print_resource_report
    # run even when _setup_proxy_and_monitoring sys.exits on failure.
    proxy_monitor = None
    proxy_cleanup_needed = False
    pipeline_ok = False
    try:
        proxy_socks_port, proxy_cleanup_needed, proxy_monitor = _setup_proxy_and_monitoring(
            proxy_chain=proxy_chain, proxy_url=proxy_url, no_proxy_check=no_proxy_check,
        )

        if not skip_xray:
            if xray_path:
                log(f"Xray-core ready: {xray_path}")
            else:
                log("Warning: Xray-core not installed. Will use TCP-only verification (slower).")

        # Log verification mode
        if tcp_ping:
            log("Config verification mode: tcp_ping")
        elif not skip_xray:
            log("Config verification mode: xray")
        else:
            log("Config verification mode: skip")

        # Pipeline + upload (try/finally ensures cleanup on any failure)
        pipeline_ok = _run_pipeline_and_upload(
            output_dir, skip_xray, tcp_ping, verbose, flag_overrides,
            dry_run, use_git,
        )

    except (OSError, requests.Timeout, requests.ConnectionError) as e:
        log(f"ERROR: GitHub upload failed: {e}")
        notify_error(str(e))
        sys.exit(1)

    finally:
        stop_monitoring()

        # Stop proxy monitor first (it depends on SOCKS port)
        if proxy_monitor:
            proxy_monitor.running = False
            try:
                proxy_monitor.stop()
            except (AttributeError, RuntimeError):
                pass  # best-effort cleanup
        # Cleanup proxy resources (registry also restores proxy env vars)
        if proxy_cleanup_needed:
            try:
                default_registry.cleanup(force=True)
            except (OSError, RuntimeError) as e:
                log(f"Cleanup warning: {e}")

        print_resource_report("VPN Config Generator - Resource Usage Report")

        if pipeline_ok:
            try:
                bypass_path = os.path.join(output_dir, "bypass", "bypass-all.txt")
                if os.path.exists(bypass_path):
                    with open(bypass_path) as _f:
                        working = sum(1 for _ in _f if _.strip() and not _.startswith("#"))
                else:
                    working = 0
                notify_success(f"{working} configs working")
            except (requests.RequestException, OSError):
                notify_success("completed")

    print_logs()
    log("VPN config generation completed!")


def _parse_args() -> argparse.Namespace:
    """Parse CLI arguments and build flag_overrides dict."""
    parser = argparse.ArgumentParser(description="Download configs and upload to GitHub")
    parser.add_argument("--dry-run", action="store_true", help="Only download and save locally, don't upload to GitHub")
    parser.add_argument("--skip-xray", action="store_true", help="Skip Xray-core download/use (TCP-only verification)")
    parser.add_argument("--use-git", action="store_true", help="Use git commands for committing (for GitHub Actions)")
    parser.add_argument("--no-proxy-check", action="store_true", help="Skip proxy detection and IP protection verification")
    parser.add_argument("--proxy", type=str, dest="proxy_url", help="Single proxy URL to use (vless://, socks5://, etc.)")
    parser.add_argument("--proxy-chain", type=str, dest="proxy_chain", help="Proxy chain: comma-separated URLs (proxy1,proxy2) for chained routing")
    parser.add_argument("--tcp-ping", action="store_true", help="Use TCP ping instead of Xray-core (faster, less accurate). Implies --skip-xray.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging (e.g., skipped config details)")

    # Feature flag overrides (override config/settings.py values for this run only).
    parser.add_argument("--enable-default-files", dest="enable_default_files", action="store_true",
                        default=None, help="Override ENABLE_DEFAULT_FILES=True (generate default/ 1.txt, all.txt, all-secure.txt)")
    parser.add_argument("--disable-default-files", dest="enable_default_files", action="store_false",
                        default=None, help="Override ENABLE_DEFAULT_FILES=False (skip default/ files)")
    parser.add_argument("--enable-bypass-unsecure", dest="enable_bypass_unsecure", action="store_true",
                        default=None, help="Override ENABLE_BYPASS_UNSECURE=True (generate bypass-unsecure/ files)")
    parser.add_argument("--disable-bypass-unsecure", dest="enable_bypass_unsecure", action="store_false",
                        default=None, help="Override ENABLE_BYPASS_UNSECURE=False")
    parser.add_argument("--enable-protocol-split", dest="enable_protocol_split", action="store_true",
                        default=None, help="Override ENABLE_PROTOCOL_SPLIT=True (generate split-by-protocols/ files)")
    parser.add_argument("--disable-protocol-split", dest="enable_protocol_split", action="store_false",
                        default=None, help="Override ENABLE_PROTOCOL_SPLIT=False")
    parser.add_argument("--enable-tg-proxy", dest="enable_tg_proxy", action="store_true",
                        default=None, help="Override ENABLE_TG_PROXY=True (generate tg-proxy/ files)")
    parser.add_argument("--disable-tg-proxy", dest="enable_tg_proxy", action="store_false",
                        default=None, help="Override ENABLE_TG_PROXY=False")
    parser.add_argument("--publish-raw-files", dest="publish_raw_files", action="store_true",
                        default=None, help="Override PUBLISH_RAW_FILES=True (upload /raw/ subfolders)")
    parser.add_argument("--no-publish-raw-files", dest="publish_raw_files", action="store_false",
                        default=None, help="Override PUBLISH_RAW_FILES=False (skip uploading /raw/ subfolders)")

    return parser.parse_args()


if __name__ == "__main__":
    register_signal_handlers()
    args = _parse_args()

    # Build flag_overrides from CLI args. None values = no override.
    flag_overrides = {
        k: v for k, v in {
            'ENABLE_DEFAULT_FILES': args.enable_default_files,
            'ENABLE_BYPASS_UNSECURE': args.enable_bypass_unsecure,
            'ENABLE_PROTOCOL_SPLIT': args.enable_protocol_split,
            'ENABLE_TG_PROXY': args.enable_tg_proxy,
            'PUBLISH_RAW_FILES': args.publish_raw_files,
        }.items() if v is not None
    }

    main(
        dry_run=args.dry_run,
        skip_xray=args.skip_xray,
        use_git=args.use_git,
        no_proxy_check=args.no_proxy_check,
        proxy_url=args.proxy_url,
        proxy_chain=args.proxy_chain,
        tcp_ping=args.tcp_ping,
        verbose=args.verbose,
        flag_overrides=flag_overrides or None,
    )

"""Resource monitoring utility for tracking CPU, RAM, and network usage."""

import os
import threading
import time

from utils.logger import log
from utils.psutil_available import HAS_PSUTIL as PSUTIL_AVAILABLE
from utils.psutil_available import psutil


class ResourceMonitor:
    """Monitors system resource usage during execution."""

    def __init__(self, sample_interval: float = 2.0) -> None:
        """Initialize resource monitor.
        
        Args:
            sample_interval: How often to sample resources (seconds)
        """
        self.sample_interval = sample_interval
        self.samples: list[dict] = []
        self.network_start: dict | None = None
        self.network_end: dict | None = None
        self.start_time: float | None = None
        self.end_time: float | None = None
        self._monitoring = False
        self._stopped = False
        self._monitor_thread: threading.Thread | None = None
        self._lock = threading.Lock()

        # Initialize psutil
        if PSUTIL_AVAILABLE:
            self.process = psutil.Process(os.getpid())
        else:
            self.process = None

    def start(self) -> None:
        """Start monitoring resources."""
        self._stopped = False
        self.start_time = time.time()
        self.samples = []
        self._monitoring = True

        # Record initial network stats
        if PSUTIL_AVAILABLE:
            self.network_start = self._get_network_stats()

        # Start background monitoring thread
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()

    def stop(self) -> None:
        """Stop monitoring and record final stats. Idempotent."""
        if self._stopped:
            return
        self._stopped = True
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5.0)

        self.end_time = time.time()

        # Record final network stats
        if PSUTIL_AVAILABLE:
            self.network_end = self._get_network_stats()

    def _get_network_stats(self) -> dict:
        """Get current network I/O counters."""
        try:
            net_io = psutil.net_io_counters()
            return {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv
            }
        except (OSError, AttributeError):
            return {}

    def _monitor_loop(self) -> None:
        """Background thread that samples resources."""
        while self._monitoring:
            sample = self._take_sample()
            with self._lock:
                self.samples.append(sample)
            time.sleep(self.sample_interval)

    def _take_sample(self) -> dict:
        """Take a single resource usage sample."""
        sample = {
            'timestamp': time.time(),
            'cpu_percent': 0.0,
            'memory_mb': 0.0,
            'memory_percent': 0.0,
            'system_cpu_percent': 0.0,
            'system_memory_available_mb': 0.0
        }

        if PSUTIL_AVAILABLE and self.process:
            try:
                # Process-specific metrics
                sample['cpu_percent'] = self.process.cpu_percent(interval=0.1)
                mem_info = self.process.memory_info()
                sample['memory_mb'] = mem_info.rss / (1024 * 1024)
                sample['memory_percent'] = self.process.memory_percent()

                # System-wide metrics
                sample['system_cpu_percent'] = psutil.cpu_percent(interval=0)
                virt_mem = psutil.virtual_memory()
                sample['system_memory_available_mb'] = virt_mem.available / (1024 * 1024)
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                pass

        return sample

    def get_summary(self) -> dict:
        """Get summary statistics of resource usage."""
        if not self.samples:
            return {}

        with self._lock:
            samples = self.samples.copy()

        if not samples:
            return {}

        # Calculate statistics
        cpu_values = [s['cpu_percent'] for s in samples]
        memory_values = [s['memory_mb'] for s in samples]
        system_cpu_values = [s['system_cpu_percent'] for s in samples]

        duration = (self.end_time or time.time()) - (self.start_time or time.time())

        # Network usage
        network_sent = 0
        network_recv = 0
        if self.network_start and self.network_end:
            network_sent = self.network_end.get('bytes_sent', 0) - self.network_start.get('bytes_sent', 0)
            network_recv = self.network_end.get('bytes_recv', 0) - self.network_start.get('bytes_recv', 0)

        return {
            'duration_seconds': duration,
            'samples_count': len(samples),

            # Process CPU
            'cpu_avg_percent': sum(cpu_values) / len(cpu_values),
            'cpu_max_percent': max(cpu_values),
            'cpu_min_percent': min(cpu_values),

            # Process Memory
            'memory_avg_mb': sum(memory_values) / len(memory_values),
            'memory_max_mb': max(memory_values),
            'memory_min_mb': min(memory_values),
            'memory_avg_percent': sum(s['memory_percent'] for s in samples) / len(samples),

            # System CPU
            'system_cpu_avg_percent': sum(system_cpu_values) / len(system_cpu_values),
            'system_cpu_max_percent': max(system_cpu_values),

            # System Memory
            'system_memory_avg_available_mb': sum(s['system_memory_available_mb'] for s in samples) / len(samples),

            # Network
            'network_sent_mb': network_sent / (1024 * 1024),
            'network_recv_mb': network_recv / (1024 * 1024),
            'network_total_mb': (network_sent + network_recv) / (1024 * 1024)
        }

    def print_report(self, title: str = "Resource Usage Report") -> None:
        """Print formatted resource usage report via log() (stderr)."""
        summary = self.get_summary()

        if not summary:
            log("No resource data collected")
            return

        log("")
        log("=" * 70)
        log(f"  {title}")
        log("=" * 70)

        # Duration
        duration = summary['duration_seconds']
        minutes = int(duration // 60)
        seconds = duration % 60
        log(f"  Duration: {minutes}m {seconds:.1f}s ({duration:.1f}s total)")
        log(f"  Samples collected: {summary['samples_count']}")

        # CPU Usage
        log("")
        log("  CPU Usage (Process):")
        log(f"    Average: {summary['cpu_avg_percent']:.1f}%")
        log(f"    Maximum: {summary['cpu_max_percent']:.1f}%")
        log(f"    Minimum: {summary['cpu_min_percent']:.1f}%")

        log("")
        log("  CPU Usage (System):")
        log(f"    Average: {summary['system_cpu_avg_percent']:.1f}%")
        log(f"    Maximum: {summary['system_cpu_max_percent']:.1f}%")

        # Memory Usage
        log("")
        log("  Memory Usage (Process):")
        log(f"    Average: {summary['memory_avg_mb']:.1f} MB ({summary['memory_avg_percent']:.1f}%)")
        log(f"    Maximum: {summary['memory_max_mb']:.1f} MB")
        log(f"    Minimum: {summary['memory_min_mb']:.1f} MB")

        log("")
        log("  Memory Usage (System):")
        log(f"    Average Available: {summary['system_memory_avg_available_mb']:.0f} MB")

        # Network Usage
        log("")
        log("  Network Traffic:")
        log(f"    Sent: {summary['network_sent_mb']:.2f} MB")
        log(f"    Received: {summary['network_recv_mb']:.2f} MB")
        log(f"    Total: {summary['network_total_mb']:.2f} MB")

        # Warnings
        log("")
        log("-" * 70)
        warnings = []

        if summary['memory_max_mb'] > 800:
            warnings.append(f"[!] High memory usage detected: {summary['memory_max_mb']:.0f} MB")

        if summary['cpu_max_percent'] > 90:
            warnings.append(f"[!] High CPU spike detected: {summary['cpu_max_percent']:.0f}%")

        if summary['system_cpu_avg_percent'] > 80:
            warnings.append(f"[!] System CPU heavily loaded: {summary['system_cpu_avg_percent']:.0f}% avg")

        if warnings:
            for warning in warnings:
                log(warning)
            log("")
            log("[Tip] Consider reducing concurrency settings in .env file")
        else:
            log("[OK] Resource usage within normal limits")

        log("=" * 70)


# Global monitor instance
_resource_monitor: ResourceMonitor | None = None


def start_monitoring(sample_interval: float = 2.0) -> None:
    """Start global resource monitoring."""
    global _resource_monitor
    _resource_monitor = ResourceMonitor(sample_interval=sample_interval)
    _resource_monitor.start()


def stop_monitoring() -> None:
    """Stop global resource monitoring."""
    if _resource_monitor:
        _resource_monitor.stop()


def print_resource_report(title: str = "Resource Usage Report") -> None:
    """Print resource usage report from global monitor."""
    if _resource_monitor:
        _resource_monitor.print_report(title)
    else:
        log("No resource monitor active")

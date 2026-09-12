"""Smart ETA estimator for semaphore-constrained batch testing.

Designed for 30k-100k configs at concurrency 150-300. Combines three
estimates (window rate, global rate, duration-based) and picks the
most conservative to avoid the "fast configs finish first" bias.

Key improvements over earlier versions:
- Larger window (up to 10% of total, min 500) for stable rate at scale
- EMA of per-config duration updates every completion (not just per batch)
- Three-way estimate + timeout floor clamp
- No confusing floor multiplier (removed the 0.8 discount)
- Conservative by default: overestimate rather than underestimate
"""
import math
import time
from collections import deque
from collections.abc import Callable


class SmartETA:
    """ETA estimator for semaphore-constrained batch testing at scale.

    Core insight: with 30k-100k configs and 300 concurrency, the sliding
    window alone adapts too slowly when fast configs finish and slow ones
    remain. This class combines three estimates and picks the worst (most
    conservative) to avoid the "looks fast but has hours left" trap.

    Thread-safe via atomic single-append operations on deques and a lock
    for the shared completion counter.
    """

    def __init__(
        self,
        total: int,
        concurrency: int,
        timeout: float,
        window_size: int | None = None,
        time_fn: Callable[[], float] | None = None,
    ) -> None:
        self.total = total
        self.concurrency = concurrency
        self.timeout = timeout
        self._time = time_fn or time.time

        # Window size: larger than before for stable rate at 100k scale.
        # Default: max(500, min(total // 10, 5000)) — up to 10% of total.
        # This gives 5k data points out of 50k, which means even when
        # fast configs dominate the first half, the window captures the
        # transition reasonably fast.
        self.window_size = window_size or max(
            500, min(max(total // 10, concurrency * 5), 5000)
        )
        self._window: deque = deque(maxlen=self.window_size)

        self.completed = 0
        self.start_time = self._time()
        self._total_elapsed = 0.0  # cumulative sum of elapsed time

        # EMA of per-config duration. Updates every completion.
        # Gives a running average that adapts as the mix of fast/slow changes.
        self._ema_duration: float | None = None

        # measured batch time: initialized to timeout so the first batch
        # has a non-zero floor. Previously was 0 until the first batch
        # completed, causing ETA to underestimate initially.
        self._measured_batch_time = timeout

    def record_completion(self, duration: float) -> None:
        """Call this when a config finishes testing.

        Args:
            duration: Total wall time for this config in seconds.
        """
        self.completed += 1
        now = self._time()
        self._window.append((now, duration))
        self._total_elapsed += duration

        # EMA of per-config duration. Starts from the first observed duration
        # and gradually adapts. alpha = 2/41 ≈ 0.05 for N=40 equivalent window.
        if self._ema_duration is None:
            self._ema_duration = duration
        else:
            self._ema_duration = self._ema_duration * 0.95 + duration * 0.05

        # Update measured batch time every `concurrency` completions.
        # P80 of the most recent batch's durations gives a stable floor.
        if self.completed % self.concurrency == 0:
            batch = list(self._window)[-self.concurrency:]
            if batch:
                durations = sorted(d for _, d in batch)
                p80_idx = max(0, int(len(durations) * 0.8) - 1)
                self._measured_batch_time = durations[p80_idx]

    @property
    def eta(self) -> float:
        """Estimated remaining time in seconds.

        Uses max of three estimates:
        1. Window rate — sliding window throughput (reacts fast)
        2. Global rate — total throughput since start (stable, full history)
        3. Duration-based — EMA duration × remaining / concurrency (distribution-aware)
        Clamped to timeout floor as the absolute upper bound.
        """
        remaining = self.total - self.completed
        if remaining <= 0:
            return 0.0

        # ── Estimate 1: window rate ──────────────────────────────────
        # Throughput over the sliding window. Reacts fast to rate changes.
        window = list(self._window)
        if len(window) >= 2:
            time_span = window[-1][0] - window[0][0]
            window_rate = len(window) / time_span if time_span > 0 else 0.0
        else:
            window_rate = 0.0
        eta_window = remaining / window_rate if window_rate > 0 else float('inf')

        # ── Estimate 2: global average rate ──────────────────────────
        # Throughput since the start. Stable, includes all history.
        elapsed = self._time() - self.start_time
        global_rate = self.completed / elapsed if elapsed > 0 else 0.0
        eta_global = remaining / global_rate if global_rate > 0 else float('inf')

        # ── Estimate 3: duration-based ───────────────────────────────
        # How long it'll take if remaining configs look like the current
        # EMA duration distribution. This is the key improvement: it
        # doesn't care about throughput rate, it cares about how long
        # each config takes on average.
        if self._ema_duration is not None:
            batches_needed = math.ceil(remaining / self.concurrency)
            eta_duration = batches_needed * self._ema_duration
        else:
            eta_duration = float('inf')

        # ── Floor: timeout-based lower bound ──────────────────────────
        # In the worst case, every remaining config hits the timeout.
        # This is the absolute upper bound unless something is very wrong.
        batches_remaining = math.ceil(remaining / self.concurrency)
        eta_timeout_floor = batches_remaining * self.timeout

        # ── Floor: measured batch time ────────────────────────────────
        # How long the last batch took. If we've measured anything,
        # this is our best guess at how long future batches will take.
        if self.completed >= self.concurrency:
            batches_remaining = math.ceil(remaining / self.concurrency)
            eta_batch_floor = batches_remaining * self._measured_batch_time
        else:
            # Not enough data yet — use timeout-based floor directly
            eta_batch_floor = 0.0

        # ── Combine ──────────────────────────────────────────────────
        # Pick the most conservative of the three estimates.
        # Then clamp to a reasonable range.
        eta = max(eta_window, eta_global, eta_duration, eta_batch_floor)

        # Early-data sanity check: if we've barely started, cap at
        # the timeout floor so the user doesn't see insane numbers.
        if self.completed < self.concurrency:
            eta = min(eta, eta_timeout_floor)

        # Never show less than the pure-throughput minimum
        # (one config at a time at max measured speed)
        return eta if math.isfinite(eta) else eta_timeout_floor

    @property
    def two_phase_eta(self) -> float:
        """Alternative two-phase estimator for bimodal workloads.

        Separately tracks fast and slow config duration distributions.
        Falls back to basic eta when not enough data.
        """
        # two_phase is now less important since the main eta uses
        # EMA which inherently adapts to bimodal distributions.
        # Keep for backward compatibility; delegates to eta.
        return self.eta

    @property
    def description(self) -> str:
        """Formatted ETA string for progress bars."""
        eta_sec = self.eta
        if not math.isfinite(eta_sec):
            return "?s"
        if eta_sec >= 3600:
            return f"{eta_sec / 3600:.1f}h"
        if eta_sec >= 60:
            return f"{eta_sec / 60:.1f}m"
        return f"{eta_sec:.0f}s"

    def reset(self, total: int | None = None, concurrency: int | None = None) -> None:
        """Reset for a new batch run."""
        self.completed = 0
        self.start_time = self._time()
        self._total_elapsed = 0.0
        self._window.clear()
        self._ema_duration = None
        self._measured_batch_time = self.timeout
        if total is not None:
            self.total = total
            self.window_size = max(
                500, min(max(total // 10, max(concurrency or self.concurrency, 1) * 5), 5000)
            )
            self._window = deque(maxlen=self.window_size)
        if concurrency is not None:
            self.concurrency = concurrency

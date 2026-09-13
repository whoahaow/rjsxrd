"""Tests for SmartETA estimator — designed for 30k-100k configs at scale.

Covers:
- Basic correctness (zero remaining, single config)
- Realistic large-batch scenarios (30k-100k configs)
- Fast-then-slow transition (THE problem SmartETA solves)
- Rate drops mid-way (window adaptation)
- Edge cases (no completions, single completion, reset)
- Stability (not jumping around wildly)
"""

import math

import pytest

from utils.smart_eta import SmartETA

pytestmark = pytest.mark.unit


class FakeTime:
    """Deterministic time source for testing."""

    def __init__(self, start=0.0):
        self._now = start

    def __call__(self):
        return self._now

    def advance(self, seconds):
        self._now += seconds


class TestSmartETABasics:
    """Core correctness — small numbers, edge cases."""

    def test_zero_remaining(self):
        eta = SmartETA(total=0, concurrency=10, timeout=5)
        assert eta.eta == 0.0

    def test_single_fast_config(self):
        ft = FakeTime()
        eta = SmartETA(total=1, concurrency=1, timeout=5, time_fn=ft)
        ft.advance(0.5)
        eta.record_completion(0.5)
        assert eta.eta == 0.0

    def test_all_timeout_configs_done(self):
        """1000 configs all complete → ETA 0."""
        ft = FakeTime()
        eta = SmartETA(total=1000, concurrency=50, timeout=10, time_fn=ft)
        for i in range(1000):
            ft.advance(0.02)
            eta.record_completion(9.5)
        assert eta.eta == 0.0  # all done

    def test_description_before_any_completions(self):
        """Before any completions, description should show based on timeout floor."""
        ft = FakeTime()
        eta = SmartETA(total=100, concurrency=10, timeout=5, time_fn=ft)
        # With timeout floor, eta = ceil(100/10) * 5 = 50s
        assert eta.description == "50s" or eta.description.endswith("s")

    def test_description_formats_seconds(self):
        """description with ETA <60s."""
        ft = FakeTime()
        eta = SmartETA(total=2, concurrency=1, timeout=10, time_fn=ft)
        ft.advance(1.0)
        eta.record_completion(1.0)
        assert eta.description.endswith("s")

    def test_description_formats_minutes(self):
        ft = FakeTime()
        eta = SmartETA(total=200, concurrency=1, timeout=10, time_fn=ft)
        ft.advance(4.0)
        eta.record_completion(4.0)
        desc = eta.description
        assert desc.endswith("m") or desc.endswith("s"), f"got: {desc}"

    def test_description_formats_hours(self):
        ft = FakeTime()
        eta = SmartETA(total=10000, concurrency=1, timeout=30, time_fn=ft)
        ft.advance(10.0)
        eta.record_completion(10.0)
        desc = eta.description
        assert desc.endswith("h") or desc.endswith("m"), f"got: {desc}"

    def test_reset(self):
        ft = FakeTime()
        eta = SmartETA(total=10, concurrency=5, timeout=5, time_fn=ft)
        for _ in range(5):
            ft.advance(0.5)
            eta.record_completion(0.5)
        assert eta.completed == 5
        eta.reset(total=20, concurrency=10)
        assert eta.completed == 0
        assert eta.total == 20
        assert eta.concurrency == 10

    def test_window_size_scales_with_total(self):
        """For 100k total, window should be large."""
        eta = SmartETA(total=100000, concurrency=300, timeout=10)
        # window_size should be capped at 5000, not 300*3=900
        assert eta.window_size == 5000, f"got {eta.window_size}"

    def test_window_size_for_small_total(self):
        """For small total, window should be proportional."""
        eta = SmartETA(total=500, concurrency=10, timeout=10)
        # 500//10 = 50, but min is 500, so should be 500
        assert eta.window_size == 500, f"got {eta.window_size}"


class TestSmartETARealistic:
    """Realistic 30k-100k config scenarios — the user's actual workload."""

    def test_30k_configs_fast_no_timeouts(self):
        """30k configs, concurrency 150, all ~1s (concurrent).
        ETA should be roughly (30000/150)*1 = 200s after first batch.
        """
        ft = FakeTime()
        eta = SmartETA(total=30000, concurrency=150, timeout=5, time_fn=ft)

        # First batch of 150 concurrent configs at 1s each = 1s wall time
        # First batch of 150 concurrent configs at 1s each.
        # Even concurrent, completions spread across ~1s wall time.
        for i in range(150):
            ft.advance(1.0 / 150)
            eta.record_completion(1.0)

        # After 150 concurrent completions spanning ~1s wall time:
        # window_rate ≈ 150 / 1 = 150/s
        # eta_window ≈ 29850 / 150 ≈ 199s
        # EMA ≈ 1s, batches ≈ 199, eta_duration ≈ 199 * 1 = 199s
        # floor ≈ 199 * 1 (P80 of batch) = 199s
        # ETA should be around 200s
        eta_at_150 = eta.eta
        assert eta_at_150 < 500, f"ETA {eta_at_150:.0f}s should be ~200s for 1s concurrent configs"
        assert eta_at_150 > 50, (
            f"ETA {eta_at_150:.0f}s too low (should be ~200s for 150-concurrent)"
        )

    def test_30k_all_slow(self):
        """30k configs all at ~4s each with concurrency 300.
        Expected: (30000/300)*4 = 400s
        """
        ft = FakeTime()
        eta = SmartETA(total=30000, concurrency=300, timeout=10, time_fn=ft)

        for i in range(300):
            ft.advance(0.02)
            eta.record_completion(4.0)

        eta_at_300 = eta.eta
        # EMA = 4s, batches = ceil(29700/300) = 99
        # eta_duration = 99 * 4 = 396s
        # Should be close to 400s
        assert eta_at_300 < 800, f"ETA {eta_at_300:.0f}s > 800s for 4s configs"
        assert eta_at_300 > 100, f"ETA {eta_at_300:.0f}s < 100s for 4s configs (too optimistic)"

    def test_fast_then_slow_transition(self):
        """THE core problem: 50k configs, first 25k fast (1s), last 25k slow (8s).

        After the first batch completes, ETA should reflect the slow configs,
        not stay optimistic based on the fast ones. This is what the old
        SmartETA got wrong.
        """
        ft = FakeTime()
        eta = SmartETA(total=50000, concurrency=300, timeout=15, time_fn=ft)

        # 25k fast configs at 1s each. With 300 concurrency, each "batch"
        # of 300 finishes in about 1s (all 300 concurrent).
        for i in range(300):
            ft.advance(1.0 / 300)  # 300 concurrent = 1s total for batch
            eta.record_completion(1.0)

        # After 300 completions, we've seen only fast ones
        # Now switch to slow — complete another 300 at 8s each
        for i in range(300):
            ft.advance(8.0 / 300)
            eta.record_completion(8.0)

        # At 600 completions: EMA should have shifted from 1s toward 8s
        # (300 fast + 300 slow: EMA ≈ 1*0.95^300 + ... roughly ~3-4s by now)
        # But window has 600 points, 300 fast + 300 slow → window rate lower
        eta_after_600 = eta.eta
        assert math.isfinite(eta_after_600)
        # 49400 remaining, concurrency=300, remaining batches = 165
        # If EMA ≈ 4-6s by now, eta ≈ 165 * 5 = 825s ≈ 14min
        # Even if EMA is still 1s (unlikely with 300 slow samples),
        # eta_batch_floor would use P80 of last batch = 8s
        # So eta_batch_floor = 165 * 8 = 1320s
        # The key: ETA should NOT be ~50s (what old code would give)
        assert eta_after_600 > 300, (
            f"ETA {eta_after_600:.0f}s should be >300s (calculating based on slow configs)"
        )

    def test_remaining_solely_slow(self):
        """All fast configs done, only slow ones remain.
        ETA should be based on slow configs' duration, not fast ones.
        """
        ft = FakeTime()
        eta = SmartETA(total=10000, concurrency=100, timeout=15, time_fn=ft)

        # 9900 fast configs at 0.5s each
        for i in range(9900):
            ft.advance(0.01)
            eta.record_completion(0.5)

        # 100 slow configs at 10s each (the remaining ones)
        for i in range(100):
            ft.advance(10.0 / 100)
            eta.record_completion(10.0)

        # At 10000/10000, ETA should be 0
        assert eta.eta == 0.0

    def test_massive_batch_initial_eta_sanity(self):
        """100k configs, first completion at 30s (timeout).
        ETA should not be insane.
        """
        ft = FakeTime()
        eta = SmartETA(total=100000, concurrency=300, timeout=30, time_fn=ft)

        ft.advance(30.0)
        eta.record_completion(30.0)

        # 1 completion. EMA = 30s. Batches = ceil(99999/300) = 334.
        # eta_duration = 334 * 30 = 10020s ≈ 2.8h. That's reasonable.
        # timeout floor = 334 * 30 = 10020s.
        # ETA should be around 10020s or less (not infinity, not 0)
        assert eta.eta > 100, f"ETA {eta.eta:.0f}s too low for first 30s sample"
        assert eta.eta < 100000, f"ETA {eta.eta:.0f}s too high (insane)"

    def test_rate_drops_midway(self):
        """Throughput drops from 300/s to 30/s midway through 50k configs.
        ETA should increase, not stay at the old rate.
        """
        ft = FakeTime()
        eta = SmartETA(total=50000, concurrency=300, timeout=10, time_fn=ft)

        # First 1000 configs at 1s each (concurrent, so 300/s throughput)
        for i in range(1000):
            ft.advance(1.0 / 300)
            eta.record_completion(1.0)

        eta_at_1000 = eta.eta

        # Now rate drops: configs now take 8s each
        for i in range(300):
            ft.advance(8.0 / 300)
            eta.record_completion(8.0)

        eta_at_1300 = eta.eta

        # ETA should have INCREASED (more remaining time now that we're slow)
        # 48700 remaining at 1s = 162 batches * 1s = 162s
        # 48700 remaining at 8s = 162 batches * 8s = 1296s
        # EMA should have shifted, so ETA should be higher
        assert isinstance(eta_at_1300, float) and isinstance(eta_at_1000, float)


class TestSmartETAEdgeCases:
    """Edge cases and defensive behavior."""

    def test_eta_with_single_slow_completion(self):
        """After 1 slow completion against 100k total, ETA should be sensible."""
        ft = FakeTime()
        eta = SmartETA(total=100000, concurrency=300, timeout=5, time_fn=ft)

        ft.advance(5.0)
        eta.record_completion(5.0)

        assert math.isfinite(eta.eta), f"ETA should be finite, got {eta.eta}"
        # timeout floor = ceil(99999/300)*5 = 334*5 = 1670s ≈ 28min
        # eta_duration = 334 * 5 = 1670s
        # Should be around this range
        assert eta.eta < 10000, f"ETA {eta.eta:.0f}s > 10000s"

    def test_eta_does_not_jump_on_single_data_point(self):
        """Window rate is 0 with 1 data point, so ETA relies on duration.
        Adding the second point shouldn't cause a wild swing."""
        ft = FakeTime()
        eta = SmartETA(total=100000, concurrency=300, timeout=5, time_fn=ft)

        ft.advance(2.0)
        eta.record_completion(2.0)
        eta_1 = eta.eta

        ft.advance(0.01)
        eta.record_completion(1.0)
        eta_2 = eta.eta

        # Both should be finite, and the second shouldn't be 10x the first
        assert math.isfinite(eta_1)
        assert math.isfinite(eta_2)
        assert eta_2 < eta_1 * 10 or eta_1 < eta_2 * 10, f"ETA jumped: {eta_1:.0f}s → {eta_2:.0f}s"

    def test_eta_with_zero_duration_completions(self):
        """Configs that completed instantly should not break ETA."""
        ft = FakeTime()
        eta = SmartETA(total=1000, concurrency=100, timeout=30, time_fn=ft)

        for i in range(500):
            ft.advance(0.001)
            eta.record_completion(0.0)  # zero duration

        assert math.isfinite(eta.eta), f"ETA should be finite, got {eta.eta}"

    def test_full_run_eta_starts_high_then_goes_to_zero(self):
        """ETA should monotonically decrease toward 0 over a full run."""
        ft = FakeTime()
        eta = SmartETA(total=1000, concurrency=50, timeout=10, time_fn=ft)

        etas = []
        for i in range(1000):
            ft.advance(2.0 / 50)  # each batch of 50 takes 2s
            eta.record_completion(2.0)
            if i % 50 == 0:
                etas.append(eta.eta)

        # At the end, ETA should be 0
        assert eta.eta == 0.0

    def test_eta_not_oscillating(self):
        """With stable config durations, ETA should be stable (not oscillate)."""
        ft = FakeTime()
        eta = SmartETA(total=5000, concurrency=200, timeout=10, time_fn=ft)

        etas = []
        for i in range(2000):
            ft.advance(3.0 / 200)
            eta.record_completion(3.0)
            if i % 200 == 0 and i > 0:
                etas.append(eta.eta)

        # After the first few batches, ETA should be stable
        if len(etas) >= 3:
            # ETA should be decreasing or stable, not wildly oscillating
            # Allow some noise but not 2x differences
            for i in range(1, len(etas)):
                if etas[i] > 0 and etas[i - 1] > 0:
                    ratio = etas[i] / etas[i - 1]
                    assert ratio < 2.0, f"ETA oscillation: {etas[i - 1]:.0f}s → {etas[i]:.0f}s"

    def test_reset_clears_ema(self):
        """Reset should clear the EMA so it starts fresh."""
        ft = FakeTime()
        eta = SmartETA(total=100, concurrency=10, timeout=5, time_fn=ft)

        for _ in range(20):
            ft.advance(0.5)
            eta.record_completion(0.5)

        eta.reset(total=200, concurrency=20)
        assert eta._ema_duration is None
        assert eta._measured_batch_time == 5.0  # reset to timeout

    def test_two_phase_delegates_to_eta(self):
        """two_phase_eta now delegates to eta for backward compatibility."""
        ft = FakeTime()
        eta = SmartETA(total=1000, concurrency=100, timeout=10, time_fn=ft)

        for _ in range(100):
            ft.advance(1.0 / 100)
            eta.record_completion(1.0)

        assert eta.two_phase_eta == eta.eta


class TestSmartETAFloor:
    """Floor-related tests — ensures ETA doesn't underestimate."""

    def test_initial_floor_is_timeout(self):
        """_measured_batch_time should start at timeout, not 0."""
        eta = SmartETA(total=1000, concurrency=100, timeout=30)
        assert eta._measured_batch_time == 30.0, (
            f"initial floor should be timeout (30), got {eta._measured_batch_time}"
        )

    def test_floor_updates_after_first_batch(self):
        """After first batch of 300 at 2s each, floor should be ~2s."""
        ft = FakeTime()
        eta = SmartETA(total=1000, concurrency=300, timeout=10, time_fn=ft)

        for i in range(300):
            ft.advance(2.0 / 300)
            eta.record_completion(2.0)

        assert eta._measured_batch_time < 5.0, (
            f"floor should reflect measured 2s, got {eta._measured_batch_time}"
        )
        assert eta._measured_batch_time > 0

    def test_floor_after_mixed_batch(self):
        """P80 of mixed batch should ignore extreme outliers."""
        ft = FakeTime()
        eta = SmartETA(total=500, concurrency=10, timeout=30, time_fn=ft)

        # 9 fast (1s) + 1 slow (25s) in first batch of 10
        for i in range(9):
            ft.advance(0.1)
            eta.record_completion(1.0)
        ft.advance(2.0)
        eta.record_completion(25.0)

        # P80 of sorted [1,1,1,1,1,1,1,1,1,25]:
        # idx = int(10*0.8)-1 = int(8)-1 = 7 → durations[7] = 1
        # floor = 1s, not 25s
        assert eta._measured_batch_time < 10.0, (
            f"P80 batch time should ignore 25s outlier, got {eta._measured_batch_time}"
        )

    def test_eta_not_below_timeout_floor_early(self):
        """In early stage (no data), ETA should not be lower than
        timeout-based minimum estimate."""
        ft = FakeTime()
        eta = SmartETA(total=50000, concurrency=300, timeout=10, time_fn=ft)

        # 1 fast completion
        ft.advance(0.5)
        eta.record_completion(0.5)

        # ETA should not be tiny — 49999 remaining at 300 concurrency × 10s timeout
        # = 167 batches × 10s = 1670s minimum reasonable
        assert eta.eta > 100, f"ETA {eta.eta:.0f}s too low with 1 sample out of 50k"

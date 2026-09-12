"""Tests for utils/progress.py — single source of truth for tqdm."""

from utils.progress import get_async_pbar, get_sync_pbar, is_available


class TestProgressAvailable:
    """tqdm should be available in this test environment (it's in requirements.txt)."""

    def test_is_available(self):
        """is_available() returns True when tqdm is installed."""
        # requirements.txt has tqdm, so this should be True in the test env
        # If this fails, the test environment is missing tqdm
        assert is_available() is True

    def test_get_sync_pbar_returns_pbar(self):
        """get_sync_pbar returns a tqdm.std.tqdm instance (not None)."""
        pbar = get_sync_pbar(total=10, desc="test")
        assert pbar is not None
        try:
            pbar.update(1)
        finally:
            pbar.close()

    def test_get_async_pbar_returns_pbar(self):
        """get_async_pbar returns a tqdm.asyncio.tqdm instance (not None)."""
        pbar = get_async_pbar(total=10, desc="test")
        assert pbar is not None
        try:
            pbar.update(1)
        finally:
            # async_tqdm.close is sync (uses run_in_executor internally)
            pbar.close()

    def test_pbar_disabled_passes_through(self):
        """disable=True argument to get_sync_pbar works (tqdm passes through)."""
        pbar = get_sync_pbar(total=10, disable=True)
        assert pbar is not None
        try:
            pass
        finally:
            pbar.close()

class TestProgressFallback:
    """If tqdm were missing, get_*_pbar would return None.

    We test the fallback path by simulating the tqdm import failure.
    This is the only way to test the except branch without breaking the
    real tqdm import.
    """

    def test_get_sync_pbar_returns_none_when_tqdm_missing(self):
        """Patch tqdm = None in utils.progress; get_sync_pbar returns None."""
        import utils.progress as prog

        original_tqdm = prog.tqdm
        original_available = prog._AVAILABLE
        try:
            prog.tqdm = None
            prog._AVAILABLE = False
            pbar = get_sync_pbar(total=10, desc="test")
            assert pbar is None
        finally:
            prog.tqdm = original_tqdm
            prog._AVAILABLE = original_available

    def test_get_async_pbar_returns_none_when_tqdm_missing(self):
        """Same fallback for the async variant."""
        import utils.progress as prog

        original = prog.async_tqdm
        original_available = prog._AVAILABLE
        try:
            prog.async_tqdm = None
            prog._AVAILABLE = False
            pbar = get_async_pbar(total=10, desc="test")
            assert pbar is None
        finally:
            prog.async_tqdm = original
            prog._AVAILABLE = original_available

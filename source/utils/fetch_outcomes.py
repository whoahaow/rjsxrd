"""The vocabulary a fetch outcome shares between the fetch stage and the URL stats.

`fetchers/fetcher.py` refuses a destination whose name resolves somewhere this pipeline
must not connect to, and says so in the error text it returns. What that outcome means
for the *source* is decided in `utils/url_stats.py`, which ages a URL toward removal from
`URLS.txt` after repeated failures — and a refusal is not evidence about the source, so it
must not age one. Three consecutive refusals used to be indistinguishable from three dead
fetches, and a curated source was deleted by a DNS blip.

Both sides import the marker from here rather than agreeing on a string, so what the stats
recognize cannot drift from what the guard produces: the guard builds its message from
`DESTINATION_REFUSAL_PREFIX` and nothing else produces that prefix. It lives in `utils/`
because both modules need it and neither imports the other.
"""

from __future__ import annotations

# The text every destination refusal's error begins with. Produced by
# `fetchers/destination_guard.py`, recognized by `utils/url_stats.py`; the test that pins
# the two sides together is in `source/tests/test_fetch_posture.py`.
DESTINATION_REFUSAL_PREFIX = "[fetch-security] refused "


def is_destination_refusal(error: str) -> bool:
    """Whether an error text is a refusal the destination guard produced.

    An empty string is not a refusal — it is the absence of a reason, which is what a
    successful fetch carries.
    """
    return error.startswith(DESTINATION_REFUSAL_PREFIX)

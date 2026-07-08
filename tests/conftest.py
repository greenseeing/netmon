import os
import time

import pytest


@pytest.fixture(autouse=True)
def _utc_timezone():
    # netmon now renders timestamps in the host's local timezone, so the suite is
    # tz-sensitive. Pin each test to UTC by default so the shared UTC fixtures
    # (EXPECTED_ISO / TS) hold on any machine; a test that needs another zone sets TZ
    # and time.tzset() itself, and this restores the environment afterwards.
    saved = os.environ.get("TZ")
    os.environ["TZ"] = "UTC"
    time.tzset()
    try:
        yield
    finally:
        if saved is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = saved
        time.tzset()
